#!/usr/bin/env bash
# Flow contract: one immutable image reaches real local Fabric and completes
# ConsentAccess, SMART IPS allowed/denied and role-licence readback through the
# reviewed external SDK test consumer. No cloud configuration is changed.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
if [[ "${1:-}" == '--help' ]]; then
  cat <<'HELP'
Run the selected linux/amd64 image with native verification and an owned local
TLS ICA/OIDC fixture plus Redis. Required explicit inputs: IMAGE_NAME,
STRICT_FABRIC_DRIVER_MODULE, STRICT_FABRIC_DRIVER_CONFIG, LOCAL_REDIS_IMAGE,
LOCAL_FABRIC_EVIDENCE_DIR. The external SDK driver is a test consumer only.
ConsentAccess, SMART IPS allow/deny and role licence are mandatory. Research
is an explicitly selected additional journey, never an implied success.
HELP
  exit 0
fi
: "${IMAGE_NAME:?Select the reviewed local image}"
: "${STRICT_FABRIC_DRIVER_MODULE:?Select the reviewed external interoperability driver}"
: "${STRICT_FABRIC_DRIVER_CONFIG:?Select its private synthetic fixture configuration}"
: "${LOCAL_REDIS_IMAGE:?Select the approved local replay-service image}"
: "${LOCAL_FABRIC_EVIDENCE_DIR:?Select the private local proof evidence directory}"
export IMAGE_NAME STRICT_FABRIC_DRIVER_MODULE STRICT_FABRIC_DRIVER_CONFIG LOCAL_REDIS_IMAGE LOCAL_FABRIC_EVIDENCE_DIR
export DOCKER_NETWORK="${DOCKER_NETWORK:-gdc-fabric-v3-devnet}"
export ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env.local-fabric}"
for executable in docker node npm openssl; do command -v "$executable" >/dev/null || { echo "Missing $executable" >&2; exit 2; }; done
docker image inspect "$IMAGE_NAME" >/dev/null
if ! docker ps --format '{{.Names}}' | grep -qx 'gdc-peer0-host1'; then
  echo 'The explicitly prepared local Fabric peer is absent. Prepare an isolated owned stack separately (npm run local:fabric:stack); this image gate never bootstraps or resets Fabric.' >&2
  exit 2
fi
NETWORK_MODE_VALUE=test-network \
BASE_ENV_FILE="${BASE_ENV_FILE:-${ROOT_DIR}/env.local-network.example}" \
FABRIC_PEER_ENDPOINT_VALUE=peer0-host1:7051 \
OUT_ENV_FILE="$ENV_FILE" \
  npm run prepare:local-fabric-env
# The application profile uses genuine verification; replay and public fixture
# trust are set by the owning orchestration process before starting the image.
CLEARING_HOUSE_MODE=local SECURITY_MODE=strict \
  node ./scripts/local-fabric-image-proof.mjs
