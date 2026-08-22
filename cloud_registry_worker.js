/**
 * StockTake Cloud Device Registry & Remote Security Controller
 * Hosted on Cloudflare Workers (100% Free - 100,000 req/day)
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Device-Id, User-Agent",
      "Content-Type": "application/json"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // Storage: Use KV namespace if bound, otherwise in-memory Map fallback
    const KV = env.DEVICE_REGISTRY_KV;

    // Helper: Load policy
    async function getPolicy() {
      if (KV) {
        const raw = await KV.get("fleet_policy");
        if (raw) return JSON.parse(raw);
      }
      return {
        master_switch_enabled: true,
        blocked_message: "Access to StockTake has been revoked by the administrator.",
        blocked_devices: [],
        allowed_devices: [],
        device_records: {}
      };
    }

    // Helper: Save policy
    async function savePolicy(policy) {
      if (KV) {
        await KV.put("fleet_policy", JSON.stringify(policy));
      }
    }

    try {
      // 1. Device Registration (Called by mobile phones / PCs on open / sync / every 30s)
      if (url.pathname === "/api/device/register" && request.method === "POST") {
        const body = await request.json();
        const id = (body.id || "").trim().toUpperCase();
        if (!id) return new Response(JSON.stringify({ error: "Missing device id" }), { status: 400, headers: corsHeaders });

        const policy = await getPolicy();
        const now = new Date().toISOString().replace('T', ' ').substring(0, 16);

        const existing = policy.device_records[id] || {};
        policy.device_records[id] = {
          id: id,
          name: body.name || existing.name || "",
          model: body.model || existing.model || "Unknown Model",
          platform: body.platform || existing.platform || "Unknown OS",
          branch: body.branch || existing.branch || "DEFAULT",
          version: body.version || existing.version || "2.0.6",
          last_seen: now
        };

        await savePolicy(policy);

        const isBlocked = policy.blocked_devices.includes(id);
        const isAllowed = policy.master_switch_enabled && !isBlocked;

        return new Response(JSON.stringify({
          status: "ok",
          id: id,
          is_authorized: isAllowed,
          is_blocked: isBlocked,
          master_switch_enabled: policy.master_switch_enabled,
          blocked_message: policy.blocked_message
        }), { headers: corsHeaders });
      }

      // 2. Device Status Check (Checked in background every 30s)
      if (url.pathname === "/api/device/status" && request.method === "GET") {
        const id = (url.searchParams.get("id") || "").trim().toUpperCase();
        const policy = await getPolicy();
        const isBlocked = policy.blocked_devices.includes(id);
        const isAllowed = policy.master_switch_enabled && !isBlocked;

        return new Response(JSON.stringify({
          id: id,
          is_authorized: isAllowed,
          is_blocked: isBlocked,
          master_switch_enabled: policy.master_switch_enabled,
          blocked_message: policy.blocked_message
        }), { headers: corsHeaders });
      }

      // 3. Fleet List (Admin PC fetches all registered devices)
      if (url.pathname === "/api/device/list" && request.method === "GET") {
        const policy = await getPolicy();
        const devices = Object.values(policy.device_records).map(dev => ({
          id: dev.id,
          name: dev.name,
          model: dev.model,
          platform: dev.platform,
          branch: dev.branch,
          version: dev.version,
          last_seen: dev.last_seen,
          is_blocked: policy.blocked_devices.includes(dev.id),
          is_allowed: policy.master_switch_enabled && !policy.blocked_devices.includes(dev.id)
        }));

        return new Response(JSON.stringify({
          master_switch_enabled: policy.master_switch_enabled,
          blocked_message: policy.blocked_message,
          devices: devices
        }), { headers: corsHeaders });
      }

      // 4. Admin Toggle Block/Allow or Rename Device
      if (url.pathname === "/api/device/toggle" && request.method === "POST") {
        const body = await request.json();
        const id = (body.id || "").trim().toUpperCase();
        const isBlocked = body.is_blocked;
        const name = body.name;

        const policy = await getPolicy();
        if (id) {
          if (isBlocked === true) {
            if (!policy.blocked_devices.includes(id)) policy.blocked_devices.push(id);
          } else if (isBlocked === false) {
            policy.blocked_devices = policy.blocked_devices.filter(d => d !== id);
          }

          if (name !== undefined && policy.device_records[id]) {
            policy.device_records[id].name = name.trim();
          }
        }

        if (body.master_switch_enabled !== undefined) {
          policy.master_switch_enabled = body.master_switch_enabled;
        }

        if (body.blocked_message) {
          policy.blocked_message = body.blocked_message;
        }

        await savePolicy(policy);

        return new Response(JSON.stringify({ status: "ok", updated: true }), { headers: corsHeaders });
      }

      return new Response(JSON.stringify({ error: "Endpoint not found" }), { status: 404, headers: corsHeaders });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers: corsHeaders });
    }
  }
};
