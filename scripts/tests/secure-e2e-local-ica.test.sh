#!/usr/bin/env bash
# Flow contract: the SOS gateway delegates its real local UI/ICA boundary to
# the explicitly selected Professional runner, which owns ephemeral processes,
# state, leases and cleanup; this source check is not a browser or ICA proof.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="${ROOT_DIR}/scripts/run-secure-e2e-google-user.sh"
bash -n "$SCRIPT"
grep -Fq 'PORTAL_PROJECT_ROOT' "$SCRIPT"
grep -Fq 'VET_GW_PROJECT_ROOT="$GW_PROJECT_ROOT"' "$SCRIPT"
grep -Fq 'v26.13.0' "$SCRIPT"
grep -Fq 'exec npm run test:e2e:local -- --workers=1' "$SCRIPT"
if grep -Eq 'GDC_SDK_NODE_ROOT|gdc-sdk-node-ts|local-close\.sh|pkill|start_local_ica|AUTH_BEARER=' "$SCRIPT"; then
  echo 'ERROR: the launcher must not duplicate services, synthesize authority or clean unrelated processes.' >&2
  exit 1
fi
echo 'OK: the local Professional runner owns its UI and ICA boundary.'
