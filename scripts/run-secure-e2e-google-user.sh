#!/usr/bin/env bash
# Delegate the real local UI journey to its owning Professional portal runner.
# That runner owns its leased ports, ephemeral services, test state and cleanup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
GW_PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

for command_name in node npm; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "ERROR: missing required command ${command_name}." >&2
    exit 2
  }
done
if [[ "$(node --version)" != 'v26.13.0' ]]; then
  echo 'ERROR: this workspace requires Node.js 26.13.0 for the real local UI gate.' >&2
  exit 2
fi
if [[ -z "${PORTAL_PROJECT_ROOT:-}" || ! -d "$PORTAL_PROJECT_ROOT" ]]; then
  echo 'ERROR: PORTAL_PROJECT_ROOT must explicitly select the Professional portal checkout.' >&2
  exit 2
fi
PORTAL_PROJECT_ROOT="$(cd "$PORTAL_PROJECT_ROOT" && pwd -P)"
if [[ -n "${VET_GW_PROJECT_ROOT:-}" ]]; then
  if [[ ! -d "$VET_GW_PROJECT_ROOT" || "$(cd "$VET_GW_PROJECT_ROOT" && pwd -P)" != "$GW_PROJECT_ROOT" ]]; then
    echo 'ERROR: VET_GW_PROJECT_ROOT must name this exact SOS gateway checkout.' >&2
    exit 2
  fi
fi
if [[ "$#" -ne 0 ]]; then
  echo 'ERROR: this launcher runs the complete canonical journey without filter arguments.' >&2
  exit 2
fi
node --input-type=commonjs -e '
  const fs = require("node:fs");
  const path = require("node:path");
  const [gatewayRoot, portalRoot] = process.argv.slice(1);
  const gateway = JSON.parse(fs.readFileSync(path.join(gatewayRoot, "package.json"), "utf8"));
  const portal = JSON.parse(fs.readFileSync(path.join(portalRoot, "package.json"), "utf8"));
  if (gateway.name !== "sos-gw-node-ts") throw new Error("The launcher requires this SOS gateway checkout.");
  if (portal.name !== "vet-professional-next" || portal.scripts?.["test:e2e:local"] !== "node scripts/run-local-e2e.mjs"
    || !fs.existsSync(path.join(portalRoot, "scripts/run-local-e2e.mjs"))) {
    throw new Error("PORTAL_PROJECT_ROOT must provide the canonical Professional local UI runner.");
  }
' "$GW_PROJECT_ROOT" "$PORTAL_PROJECT_ROOT"

export VET_GW_PROJECT_ROOT="$GW_PROJECT_ROOT"
cd "$PORTAL_PROJECT_ROOT"
exec npm run test:e2e:local -- --workers=1
