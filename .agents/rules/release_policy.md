# Release & Deployment Policy

## Synchronized Cross-Platform Releases
1. **Dual-Platform Invariant**: Any version bump or release to GitHub MUST include and publish binaries for BOTH platforms:
   - **Android**: StockTake-<version>.apk (signed production build with R8/ProGuard)
   - **Windows**: StockTake-<version>.msi (signed MSI installer)
2. **Centralized Release Distribution**:
   - Both artifacts must be attached to the release tag in Tabish42/StockTake-Releases.
   - Ensure the direct binary file naming conventions match exactly what in-app updaters query (AppUpdateManager.kt on Android and AppUpdateService.kt on Windows).
3. **One-Click In-App Updating**:
   - The release must be verified to ensure in-app updaters on both Android handheld scanners and Windows POS workstations detect the update and install it in one click without manual intervention.
