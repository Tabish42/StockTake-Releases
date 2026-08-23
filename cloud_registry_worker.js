/**
 * StockTake Cloud Device Registry & Remote Security Controller
 * Hosted on Cloudflare Workers (Atomic Key-Per-Device Architecture)
 * 
 * Features:
 * - Atomic key-per-device storage (`device:{id}`) to prevent race conditions during shift start.
 * - Global fleet policy storage (`fleet:global_policy`) for master switch and version gates.
 * - Read-only status checks (`GET /api/device/status`) to strictly preserve free KV quotas.
 * - Authenticated administrative routes with Bearer / X-Admin-Secret header support.
 * - Remote command distribution queue (`FORCE_SYNC`, `WIPE_DB`, `PURGE_CACHE`, `TRIGGER_UPDATE`, `SET_BRANCH`).
 * - Command acknowledgment (`POST /api/device/ack_command`) and audit logging.
 * - Granular permissions (`allow_scanning`, `allow_price_check`, `branch`).
 * - Minimum version enforcement.
 * - In-memory storage fallback for standalone testing / non-KV environments.
 */

const DEFAULT_ADMIN_SECRET = "StockTake#FleetShield@2026!SecuredPolicyKey";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Admin-Secret, X-Admin-Token, X-Device-Id, User-Agent, Cache-Control, If-None-Match",
  "Access-Control-Expose-Headers": "Content-Length, X-Server-Time, ETag",
  "Access-Control-Max-Age": "86400",
  "Content-Type": "application/json"
};

const ALLOWED_COMMANDS = [
  "FORCE_SYNC",
  "WIPE_DB",
  "PURGE_CACHE",
  "TRIGGER_UPDATE",
  "SET_BRANCH",
  "RELOAD_CONFIG",
  "ENFORCE_MIN_VERSION"
];

// Fallback in-memory store for local testing / non-KV environments
const inMemoryStore = new Map();

/**
 * Constant-time string equality check to mitigate timing attacks.
 */
function secureCompare(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= (a.charCodeAt(i) ^ b.charCodeAt(i));
  }
  return mismatch === 0;
}

/**
 * Validates whether the incoming request contains a valid admin secret.
 */
function checkAdminAuth(request, env) {
  const configuredSecret = (env && env.ADMIN_SECRET_KEY) ? env.ADMIN_SECRET_KEY : DEFAULT_ADMIN_SECRET;

  // 1. Check Authorization: Bearer <token> or Token <token>
  const authHeader = request.headers.get("Authorization") || request.headers.get("authorization") || "";
  if (authHeader) {
    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch && secureCompare(bearerMatch[1].trim(), configuredSecret)) {
      return true;
    }
    const tokenMatch = authHeader.match(/^Token\s+(.+)$/i);
    if (tokenMatch && secureCompare(tokenMatch[1].trim(), configuredSecret)) {
      return true;
    }
    if (secureCompare(authHeader.trim(), configuredSecret)) {
      return true;
    }
  }

  // 2. Check X-Admin-Secret
  const adminSecret = request.headers.get("X-Admin-Secret") || request.headers.get("x-admin-secret") || "";
  if (adminSecret && secureCompare(adminSecret.trim(), configuredSecret)) {
    return true;
  }

  // 3. Check X-Admin-Token (Legacy / Alternative header)
  const adminToken = request.headers.get("X-Admin-Token") || request.headers.get("x-admin-token") || "";
  if (adminToken && secureCompare(adminToken.trim(), configuredSecret)) {
    return true;
  }

  return false;
}

/**
 * Standardized JSON response helper.
 */
function jsonResponse(data, status = 200, customHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...CORS_HEADERS,
      "X-Server-Time": Date.now().toString(),
      ...customHeaders
    }
  });
}

/**
 * Standardized error response helper.
 */
function errorResponse(message, status = 400, details = null) {
  const payload = {
    error: message,
    status: status,
    timestamp: Date.now()
  };
  if (details) payload.details = details;
  return jsonResponse(payload, status);
}

/**
 * Semantic version comparison helper:
 * Returns true if clientVersion < minRequiredVersion.
 */
function isVersionOutdated(clientVersion, minRequiredVersion) {
  if (!clientVersion || !minRequiredVersion) return false;
  const clean = (v) => v.toString().replace(/^v/i, "").split("-")[0].split(".").map(n => parseInt(n, 10) || 0);
  const clientParts = clean(clientVersion);
  const minParts = clean(minRequiredVersion);
  for (let i = 0; i < Math.max(clientParts.length, minParts.length); i++) {
    const c = clientParts[i] || 0;
    const m = minParts[i] || 0;
    if (c < m) return true;
    if (c > m) return false;
  }
  return false;
}

/**
 * Prunes expired commands based on TTL / expires_at.
 */
function pruneExpiredCommands(commands) {
  if (!Array.isArray(commands)) return [];
  const now = Date.now();
  return commands.filter(cmd => !cmd.expires_at || cmd.expires_at > now);
}

/**
 * Low-level KV Get wrapper with in-memory fallback.
 */
async function kvGet(KV, key) {
  if (KV) {
    return await KV.get(key);
  }
  return inMemoryStore.get(key) || null;
}

/**
 * Low-level KV Put wrapper with in-memory fallback.
 */
async function kvPut(KV, key, value) {
  if (KV) {
    await KV.put(key, value);
  } else {
    inMemoryStore.set(key, value);
  }
}

/**
 * Low-level KV Delete wrapper with in-memory fallback.
 */
async function kvDelete(KV, key) {
  if (KV) {
    await KV.delete(key);
  } else {
    inMemoryStore.delete(key);
  }
}

/**
 * Deletes atomic device record (`device:{id}`).
 */
async function deleteDeviceRecord(KV, deviceId) {
  const normId = deviceId.trim().toUpperCase();
  const key = `device:${normId}`;
  await kvDelete(KV, key);
}

/**
 * Low-level KV List wrapper with in-memory fallback.
 */
async function kvList(KV, prefix) {
  if (KV) {
    const keys = [];
    let cursor = undefined;
    do {
      const res = await KV.list({ prefix: prefix, cursor: cursor });
      if (res && res.keys) {
        keys.push(...res.keys);
      }
      cursor = res && !res.list_complete ? res.cursor : undefined;
    } while (cursor);
    return keys;
  } else {
    const keys = [];
    for (const k of inMemoryStore.keys()) {
      if (k.startsWith(prefix)) {
        keys.push({ name: k });
      }
    }
    return keys;
  }
}

/**
 * Loads global fleet policy with defaults and legacy migration.
 */
async function getGlobalPolicy(KV) {
  const defaultPolicy = {
    master_switch_enabled: true,
    require_whitelist: false,
    blocked_message: "Access to StockTake has been revoked by the administrator.",
    default_allow_scanning: true,
    default_allow_price_check: true,
    default_branch: "DEFAULT",
    min_version_android: "2.1.0",
    min_version_windows: "2.1.0",
    updated_at: Date.now(),
    updated_by: "SYSTEM"
  };

  try {
    const raw = await kvGet(KV, "fleet:global_policy");
    if (raw) {
      return { ...defaultPolicy, ...JSON.parse(raw) };
    }

    // Check legacy "fleet_policy" migration fallback
    const legacyRaw = await kvGet(KV, "fleet_policy");
    if (legacyRaw) {
      const legacy = JSON.parse(legacyRaw);
      const migrated = {
        ...defaultPolicy,
        master_switch_enabled: legacy.master_switch_enabled !== undefined ? legacy.master_switch_enabled : true,
        blocked_message: legacy.blocked_message || defaultPolicy.blocked_message
      };
      await saveGlobalPolicy(KV, migrated);

      // Migrate legacy device records if present
      if (legacy.device_records && typeof legacy.device_records === "object") {
        for (const [id, rec] of Object.entries(legacy.device_records)) {
          const normId = id.trim().toUpperCase();
          const isBlocked = Array.isArray(legacy.blocked_devices) && legacy.blocked_devices.includes(normId);
          const devObj = {
            device_id: normId,
            id: normId,
            name: rec.name || "",
            model: rec.model || "Unknown Model",
            platform: rec.platform || "Android",
            version: rec.version || "1.0.0",
            branch: rec.branch || "DEFAULT",
            ip_address: rec.ip_address || "",
            is_blocked: isBlocked,
            blocked_message: isBlocked ? (legacy.blocked_message || "") : "",
            allow_scanning: true,
            allow_price_check: true,
            pending_commands: [],
            created_at: Date.now(),
            last_seen: rec.last_seen ? new Date(rec.last_seen).getTime() : Date.now()
          };
          await saveDeviceRecord(KV, normId, devObj);
        }
      }
      return migrated;
    }
  } catch (e) {
    console.error("Error reading global policy:", e);
  }

  return defaultPolicy;
}

/**
 * Saves global fleet policy.
 */
async function saveGlobalPolicy(KV, policy) {
  policy.updated_at = Date.now();
  await kvPut(KV, "fleet:global_policy", JSON.stringify(policy));
}

/**
 * Loads atomic device record (`device:{id}`).
 */
async function getDeviceRecord(KV, deviceId) {
  const normId = deviceId.trim().toUpperCase();
  const key = `device:${normId}`;
  try {
    const raw = await kvGet(KV, key);
    if (raw) {
      return JSON.parse(raw);
    }
  } catch (e) {
    console.error(`Error reading device record ${key}:`, e);
  }
  return null;
}

/**
 * Saves atomic device record (`device:{id}`).
 */
async function saveDeviceRecord(KV, deviceId, record) {
  const normId = deviceId.trim().toUpperCase();
  const key = `device:${normId}`;
  await kvPut(KV, key, JSON.stringify(record));
}

/**
 * Enumerates all devices from KV with batch parallel reading.
 */
async function listAllDevices(KV) {
  const devices = [];
  try {
    const deviceKeys = await kvList(KV, "device:");
    const batchSize = 25;
    for (let i = 0; i < deviceKeys.length; i += batchSize) {
      const chunk = deviceKeys.slice(i, i + batchSize);
      const records = await Promise.all(chunk.map(k => kvGet(KV, k.name)));
      for (const raw of records) {
        if (raw) {
          try {
            devices.push(JSON.parse(raw));
          } catch (_) {}
        }
      }
    }
  } catch (e) {
    console.error("Error listing devices:", e);
  }
  return devices;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: CORS_HEADERS
      });
    }

    const KV = env && env.DEVICE_REGISTRY_KV;

    try {
      // -------------------------------------------------------------
      // 2. Device Registration (POST /api/device/register)
      // Atomic write to key `device:{id}`
      // -------------------------------------------------------------
      if (url.pathname === "/api/device/register" && request.method === "POST") {
        let body;
        try {
          body = await request.json();
        } catch (_) {
          return errorResponse("Malformed JSON in request body", 400);
        }

        const rawId = body.device_id || body.id || "";
        const id = rawId.trim().toUpperCase();

        if (!id) {
          return errorResponse("Missing device id", 400);
        }

        const [globalPolicy, rawDevice] = await Promise.all([
          getGlobalPolicy(KV),
          getDeviceRecord(KV, id)
        ]);

        const clientIp = request.headers.get("CF-Connecting-IP") ||
                         request.headers.get("x-forwarded-for") ||
                         body.ip_address || "";
        const now = Date.now();

        let device = rawDevice;
        if (device) {
          device.name = body.name !== undefined ? body.name : (device.name || "");
          device.model = body.model !== undefined ? body.model : (device.model || "Unknown Model");
          device.platform = body.platform !== undefined ? body.platform : (device.platform || "Android");
          device.version = body.version !== undefined ? body.version : (device.version || "1.0.0");
          device.branch = body.branch !== undefined ? body.branch : (device.branch || globalPolicy.default_branch || "DEFAULT");
          device.ip_address = clientIp || device.ip_address || "";
          device.last_seen = now;
          device.last_seen_human = new Date(now).toISOString().replace("T", " ").substring(0, 19);
          if (device.allow_scanning === undefined) {
            device.allow_scanning = globalPolicy.default_allow_scanning !== undefined ? globalPolicy.default_allow_scanning : true;
          }
          if (device.allow_price_check === undefined) {
            device.allow_price_check = globalPolicy.default_allow_price_check !== undefined ? globalPolicy.default_allow_price_check : true;
          }
          device.pending_commands = pruneExpiredCommands(device.pending_commands || []);
        } else {
          device = {
            device_id: id,
            id: id,
            name: body.name || "",
            model: body.model || "Unknown Model",
            platform: body.platform || "Android",
            version: body.version || "1.0.0",
            branch: body.branch || globalPolicy.default_branch || "DEFAULT",
            ip_address: clientIp,
            is_blocked: false,
            blocked_message: "",
            allow_scanning: globalPolicy.default_allow_scanning !== undefined ? globalPolicy.default_allow_scanning : true,
            allow_price_check: globalPolicy.default_allow_price_check !== undefined ? globalPolicy.default_allow_price_check : true,
            pending_commands: [],
            last_seen: now,
            last_seen_human: new Date(now).toISOString().replace("T", " ").substring(0, 19),
            created_at: now
          };
        }

        // Persist atomic device record
        await saveDeviceRecord(KV, id, device);

        // Evaluate authorization
        const isWin = (device.platform || "").toLowerCase().includes("win");
        const minReqVersion = isWin ? (globalPolicy.min_version_windows || "2.1.0") : (globalPolicy.min_version_android || "2.1.0");
        const isOutdated = isVersionOutdated(device.version, minReqVersion);

        let isAuthorized = true;
        let blockedMsg = "";

        if (!globalPolicy.master_switch_enabled) {
          isAuthorized = false;
          blockedMsg = globalPolicy.blocked_message || "Fleet-wide access has been disabled by administrator.";
        } else if (device.is_blocked) {
          isAuthorized = false;
          blockedMsg = device.blocked_message || globalPolicy.blocked_message || "Device access has been revoked.";
        } else if (globalPolicy.require_whitelist && !device.is_allowed) {
          isAuthorized = false;
          blockedMsg = "Device not on authorized whitelist.";
        } else if (isOutdated) {
          isAuthorized = false;
          blockedMsg = `Application update required. Minimum version is ${minReqVersion}.`;
        }

        return jsonResponse({
          is_authorized: isAuthorized,
          blocked_message: blockedMsg,
          allow_scanning: isAuthorized ? (device.allow_scanning !== false) : false,
          allow_price_check: isAuthorized ? (device.allow_price_check !== false) : false,
          branch: device.branch || "DEFAULT",
          pending_commands: device.pending_commands || [],
          min_required_version: minReqVersion,
          server_time: now,
          // Compatibility aliases
          id: id,
          device_id: id,
          status: "ok",
          is_blocked: device.is_blocked || false,
          master_switch_enabled: globalPolicy.master_switch_enabled
        });
      }

      // -------------------------------------------------------------
      // 3. Lightweight Device Status Polling (GET /api/device/status)
      // Zero KV writes strictly preserved for free tier quota.
      // -------------------------------------------------------------
      if (url.pathname === "/api/device/status" && request.method === "GET") {
        const rawId = url.searchParams.get("id") || url.searchParams.get("device_id") || "";
        const id = rawId.trim().toUpperCase();

        if (!id) {
          return errorResponse("Missing required query parameter: id or device_id", 400);
        }

        const [globalPolicy, device] = await Promise.all([
          getGlobalPolicy(KV),
          getDeviceRecord(KV, id)
        ]);

        const now = Date.now();
        const isWin = ((device && device.platform) || url.searchParams.get("platform") || "").toLowerCase().includes("win");
        const minReqVersion = isWin ? (globalPolicy.min_version_windows || "2.1.0") : (globalPolicy.min_version_android || "2.1.0");

        if (!device) {
          const isAuthorized = globalPolicy.master_switch_enabled && !globalPolicy.require_whitelist;
          const blockedMsg = globalPolicy.master_switch_enabled ? "" : globalPolicy.blocked_message;
          return jsonResponse({
            is_authorized: isAuthorized,
            blocked_message: blockedMsg,
            allow_scanning: isAuthorized ? (globalPolicy.default_allow_scanning !== false) : false,
            allow_price_check: isAuthorized ? (globalPolicy.default_allow_price_check !== false) : false,
            branch: globalPolicy.default_branch || "DEFAULT",
            pending_commands: [],
            min_required_version: minReqVersion,
            server_time: now,
            id: id,
            device_id: id,
            is_blocked: false,
            master_switch_enabled: globalPolicy.master_switch_enabled
          });
        }

        const clientVersion = url.searchParams.get("version") || device.version || "1.0.0";
        const isOutdated = isVersionOutdated(clientVersion, minReqVersion);

        let isAuthorized = true;
        let blockedMsg = "";

        if (!globalPolicy.master_switch_enabled) {
          isAuthorized = false;
          blockedMsg = globalPolicy.blocked_message || "Fleet-wide access has been disabled by administrator.";
        } else if (device.is_blocked) {
          isAuthorized = false;
          blockedMsg = device.blocked_message || globalPolicy.blocked_message || "Device access has been revoked.";
        } else if (globalPolicy.require_whitelist && !device.is_allowed) {
          isAuthorized = false;
          blockedMsg = "Device not on authorized whitelist.";
        } else if (isOutdated) {
          isAuthorized = false;
          blockedMsg = `Application update required. Minimum version is ${minReqVersion}.`;
        }

        const activeCommands = pruneExpiredCommands(device.pending_commands || []);

        return jsonResponse({
          is_authorized: isAuthorized,
          blocked_message: blockedMsg,
          allow_scanning: isAuthorized ? (device.allow_scanning !== false) : false,
          allow_price_check: isAuthorized ? (device.allow_price_check !== false) : false,
          branch: device.branch || "DEFAULT",
          pending_commands: activeCommands,
          min_required_version: minReqVersion,
          server_time: now,
          id: id,
          device_id: id,
          is_blocked: device.is_blocked || false,
          master_switch_enabled: globalPolicy.master_switch_enabled
        });
      }

      // -------------------------------------------------------------
      // 4. Admin Fleet List (GET /api/device/list)
      // Authenticated enumeration of registered fleet devices
      // -------------------------------------------------------------
      if (url.pathname === "/api/device/list" && request.method === "GET") {
        if (!checkAdminAuth(request, env)) {
          return errorResponse("Unauthorized: Missing or invalid admin authorization token", 401);
        }

        const [globalPolicy, devices] = await Promise.all([
          getGlobalPolicy(KV),
          listAllDevices(KV)
        ]);

        const now = Date.now();
        const mappedDevices = devices.map(dev => {
          const devId = dev.device_id || dev.id || "";
          const lastSeen = typeof dev.last_seen === "number"
            ? dev.last_seen
            : (dev.last_seen ? new Date(dev.last_seen).getTime() : 0);
          const isOnline = (now - lastSeen) < 120000; // < 2 minutes = online
          const isWin = (dev.platform || "").toLowerCase().includes("win");
          const minVer = isWin ? (globalPolicy.min_version_windows || "2.1.0") : (globalPolicy.min_version_android || "2.1.0");
          const isOutdated = isVersionOutdated(dev.version, minVer);
          const isAuthorized = globalPolicy.master_switch_enabled && !dev.is_blocked && !isOutdated;

          return {
            device_id: devId,
            id: devId,
            name: dev.name || "",
            model: dev.model || "",
            platform: dev.platform || "",
            version: dev.version || "",
            branch: dev.branch || "DEFAULT",
            ip_address: dev.ip_address || "",
            last_seen: lastSeen,
            last_seen_ts: lastSeen,
            last_seen_human: dev.last_seen_human || (lastSeen > 0 ? new Date(lastSeen).toISOString().replace("T", " ").substring(0, 19) : "Never"),
            is_blocked: dev.is_blocked || false,
            is_authorized: isAuthorized,
            is_allowed: isAuthorized,
            allow_scanning: dev.allow_scanning !== false,
            allow_price_check: dev.allow_price_check !== false,
            pending_commands_count: (dev.pending_commands || []).length,
            pending_commands: dev.pending_commands || [],
            last_ack_command: dev.last_ack_command || null,
            is_online: isOnline
          };
        });

        return jsonResponse({
          master_switch_enabled: globalPolicy.master_switch_enabled,
          blocked_message: globalPolicy.blocked_message,
          global_policy: globalPolicy,
          devices: mappedDevices,
          total_count: mappedDevices.length
        });
      }

      // -------------------------------------------------------------
      // 5. Admin Device & Master Switch Toggle (POST /api/device/toggle)
      // Authenticated mutation of device blocks, permissions, metadata
      // -------------------------------------------------------------
      if (url.pathname === "/api/device/toggle" && request.method === "POST") {
        if (!checkAdminAuth(request, env)) {
          return errorResponse("Unauthorized: Missing or invalid admin authorization token", 401);
        }

        let body;
        try {
          body = await request.json();
        } catch (_) {
          return errorResponse("Malformed JSON in request body", 400);
        }

        const rawId = body.device_id || body.id || "";
        const id = rawId.trim().toUpperCase();

        if (body.master_switch_enabled !== undefined || (!id && body.blocked_message)) {
          const globalPolicy = await getGlobalPolicy(KV);
          if (body.master_switch_enabled !== undefined) {
            globalPolicy.master_switch_enabled = Boolean(body.master_switch_enabled);
          }
          if (body.blocked_message) {
            globalPolicy.blocked_message = body.blocked_message;
          }
          await saveGlobalPolicy(KV, globalPolicy);
        }

        let updatedDevice = null;
        if (id) {
          const [globalPolicy, rawDevice] = await Promise.all([
            getGlobalPolicy(KV),
            getDeviceRecord(KV, id)
          ]);

          const now = Date.now();
          let device = rawDevice;

          if (!device) {
            device = {
              device_id: id,
              id: id,
              name: body.name ? body.name.trim() : "",
              model: "Unknown Model",
              platform: "Unknown OS",
              version: "1.0.0",
              branch: body.branch || globalPolicy.default_branch || "DEFAULT",
              ip_address: "",
              is_blocked: body.is_blocked === true,
              blocked_message: body.blocked_message || "",
              allow_scanning: body.allow_scanning !== undefined ? Boolean(body.allow_scanning) : (globalPolicy.default_allow_scanning !== false),
              allow_price_check: body.allow_price_check !== undefined ? Boolean(body.allow_price_check) : (globalPolicy.default_allow_price_check !== false),
              pending_commands: [],
              last_seen: now,
              created_at: now
            };
          } else {
            if (body.is_blocked !== undefined) device.is_blocked = Boolean(body.is_blocked);
            if (body.blocked_message !== undefined) device.blocked_message = body.blocked_message;
            if (body.allow_scanning !== undefined) device.allow_scanning = Boolean(body.allow_scanning);
            if (body.allow_price_check !== undefined) device.allow_price_check = Boolean(body.allow_price_check);
            if (body.branch !== undefined) device.branch = body.branch;
            if (body.name !== undefined) device.name = body.name.trim();
            device.updated_at = now;
          }

          await saveDeviceRecord(KV, id, device);
          updatedDevice = device;
        }

        return jsonResponse({
          success: true,
          device_id: id || null,
          id: id || null,
          updated: true,
          status: "ok",
          is_blocked: updatedDevice ? updatedDevice.is_blocked : undefined,
          allow_scanning: updatedDevice ? updatedDevice.allow_scanning : undefined,
          allow_price_check: updatedDevice ? updatedDevice.allow_price_check : undefined,
          branch: updatedDevice ? updatedDevice.branch : undefined,
          name: updatedDevice ? updatedDevice.name : undefined
        });
      }

      // -------------------------------------------------------------
      // 5b. Admin Device Deletion (POST /api/device/delete or DELETE /api/device)
      // Authenticated deletion of registered device from KV
      // -------------------------------------------------------------
      if (((url.pathname === "/api/device/delete" && request.method === "POST") ||
           (url.pathname === "/api/device" && request.method === "DELETE") ||
           (url.pathname === "/api/device/delete" && request.method === "DELETE"))) {
        if (!checkAdminAuth(request, env)) {
          return errorResponse("Unauthorized: Missing or invalid admin authorization token", 401);
        }

        let id = url.searchParams.get("id") || url.searchParams.get("device_id") || "";
        if (!id && request.method === "POST") {
          try {
            const body = await request.json();
            id = body.device_id || body.id || "";
          } catch (_) {}
        }
        id = id.trim().toUpperCase();

        if (!id) {
          return errorResponse("Missing required field: id or device_id", 400);
        }

        await deleteDeviceRecord(KV, id);

        return jsonResponse({
          success: true,
          deleted: true,
          device_id: id,
          status: "ok"
        });
      }

      // -------------------------------------------------------------
      // 6. Admin Remote Command Dispatch (POST /api/device/command)
      // Authenticated issuance of maintenance & remote actions
      // -------------------------------------------------------------
      if (url.pathname === "/api/device/command" && request.method === "POST") {
        if (!checkAdminAuth(request, env)) {
          return errorResponse("Unauthorized: Missing or invalid admin authorization token", 401);
        }

        let body;
        try {
          body = await request.json();
        } catch (_) {
          return errorResponse("Malformed JSON in request body", 400);
        }

        const rawId = body.device_id || body.id || "";
        const id = rawId.trim().toUpperCase();
        const command = (body.command || "").trim().toUpperCase();

        if (!id || !command) {
          return errorResponse("Missing required field: device_id or command", 400);
        }

        if (!ALLOWED_COMMANDS.includes(command)) {
          return errorResponse(`Unsupported command: ${command}. Supported: ${ALLOWED_COMMANDS.join(", ")}`, 400);
        }

        const device = await getDeviceRecord(KV, id);
        if (!device) {
          return errorResponse(`Target device ${id} not found in registry`, 404);
        }

        if (!Array.isArray(device.pending_commands)) {
          device.pending_commands = [];
        }

        // Clean expired commands before enqueuing
        device.pending_commands = pruneExpiredCommands(device.pending_commands);

        const commandId = `CMD-${Date.now()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;
        const ttlSeconds = typeof body.ttl_seconds === "number" && body.ttl_seconds > 0 ? body.ttl_seconds : 86400;

        const cmdObj = {
          command_id: commandId,
          command: command,
          payload: body.payload || {},
          created_at: Date.now(),
          expires_at: Date.now() + (ttlSeconds * 1000),
          status: "QUEUED"
        };

        // Enforce max pending queue depth of 10
        if (device.pending_commands.length >= 10) {
          device.pending_commands.shift(); // Evict oldest
        }

        device.pending_commands.push(cmdObj);
        await saveDeviceRecord(KV, id, device);

        return jsonResponse({
          success: true,
          command_id: commandId,
          device_id: id,
          command: command,
          status: "QUEUED",
          enqueued_at: cmdObj.created_at
        });
      }

      // -------------------------------------------------------------
      // 7. Device Command Acknowledgment (POST /api/device/ack_command)
      // Public route for devices to acknowledge completed action
      // -------------------------------------------------------------
      if (url.pathname === "/api/device/ack_command" && request.method === "POST") {
        let body;
        try {
          body = await request.json();
        } catch (_) {
          return errorResponse("Malformed JSON in request body", 400);
        }

        const rawId = body.device_id || body.id || "";
        const id = rawId.trim().toUpperCase();
        const commandId = (body.command_id || "").trim();

        if (!id || !commandId) {
          return errorResponse("Missing device_id or command_id", 400);
        }

        const device = await getDeviceRecord(KV, id);
        if (!device) {
          return errorResponse(`Device ${id} not found`, 404);
        }

        if (Array.isArray(device.pending_commands)) {
          device.pending_commands = device.pending_commands.filter(c => c.command_id !== commandId);
        } else {
          device.pending_commands = [];
        }

        device.last_ack_command = {
          command_id: commandId,
          status: body.status || "COMPLETED",
          result_message: body.result_message || "",
          error_details: body.error_details || null,
          executed_at: body.executed_at || Date.now()
        };

        await saveDeviceRecord(KV, id, device);

        return jsonResponse({
          success: true,
          acknowledged: true,
          command_id: commandId,
          status: "ACKNOWLEDGED",
          remaining_pending_count: device.pending_commands.length
        });
      }

      // -------------------------------------------------------------
      // 8. Admin Global Policy Update (POST /api/policy/global)
      // Authenticated route to update fleet-wide governance
      // -------------------------------------------------------------
      if ((url.pathname === "/api/policy/global" || url.pathname === "/api/admin/policy") && request.method === "POST") {
        if (!checkAdminAuth(request, env)) {
          return errorResponse("Unauthorized: Missing or invalid admin authorization token", 401);
        }

        let body;
        try {
          body = await request.json();
        } catch (_) {
          return errorResponse("Malformed JSON in request body", 400);
        }

        const globalPolicy = await getGlobalPolicy(KV);

        if (body.master_switch_enabled !== undefined) {
          globalPolicy.master_switch_enabled = Boolean(body.master_switch_enabled);
        }
        if (body.require_whitelist !== undefined) {
          globalPolicy.require_whitelist = Boolean(body.require_whitelist);
        }
        if (body.blocked_message !== undefined) {
          globalPolicy.blocked_message = String(body.blocked_message);
        }
        if (body.default_allow_scanning !== undefined) {
          globalPolicy.default_allow_scanning = Boolean(body.default_allow_scanning);
        }
        if (body.default_allow_price_check !== undefined) {
          globalPolicy.default_allow_price_check = Boolean(body.default_allow_price_check);
        }
        if (body.default_branch !== undefined) {
          globalPolicy.default_branch = String(body.default_branch);
        }
        if (body.min_version_android !== undefined) {
          globalPolicy.min_version_android = String(body.min_version_android);
        }
        if (body.min_version_windows !== undefined) {
          globalPolicy.min_version_windows = String(body.min_version_windows);
        }
        if (body.updated_by !== undefined) {
          globalPolicy.updated_by = String(body.updated_by);
        }

        await saveGlobalPolicy(KV, globalPolicy);

        return jsonResponse({
          success: true,
          global_policy: globalPolicy
        });
      }

      // -------------------------------------------------------------
      // 404 Endpoint Not Found
      // -------------------------------------------------------------
      return errorResponse(`Endpoint not found: ${request.method} ${url.pathname}`, 404);

    } catch (err) {
      console.error("Unhandled Worker error:", err);
      return errorResponse(err && err.message ? err.message : "Internal server error", 500);
    }
  }
};
