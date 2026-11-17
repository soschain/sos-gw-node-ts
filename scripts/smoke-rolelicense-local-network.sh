#!/usr/bin/env bash
set -euo pipefail

CHANNEL_NAME="${CHANNEL_NAME:-identity-local}"
CHAINCODE_NAME="${CHAINCODE_NAME:-rolelicense-sc}"
FABRIC_TOOLS_CONTAINER="${FABRIC_TOOLS_CONTAINER:-gdc-fabric-tools}"
ORG1_DOMAIN="${ORG1_DOMAIN:-host1.example.com}"
ORDERER_DOMAIN="${ORDERER_DOMAIN:-example.com}"
ORG1_MSP_ID="${ORG1_MSP_ID:-Host1MSP}"

ORG1_ADMIN_MSP="/workspace/organizations/peerOrganizations/${ORG1_DOMAIN}/users/Admin@${ORG1_DOMAIN}/msp"
ORG1_PEER_TLS="/workspace/organizations/peerOrganizations/${ORG1_DOMAIN}/peers/peer0.${ORG1_DOMAIN}/tls/ca.crt"
ORDERER_TLS_CA="/workspace/organizations/ordererOrganizations/${ORDERER_DOMAIN}/orderers/orderer.${ORDERER_DOMAIN}/tls/ca.crt"

ORGANIZATION_ID="${LICENSE_ORGANIZATION_ID:-urn:org:uuid:00000000-0000-4000-8000-000000000101}"
LICENSE_JURISDICTION="${LICENSE_JURISDICTION:-CA-BC}"
LICENSE_SECTOR="${LICENSE_SECTOR:-animal-care}"
LICENSE_ORGANIZATION_OFFICIAL_ID="${LICENSE_ORGANIZATION_OFFICIAL_ID:-00000000-0000-4000-8000-000000000101}"
# Use the same canonical identity builder as the gateway, never an ad-hoc key.
identity_json="$(LICENSE_JURISDICTION="$LICENSE_JURISDICTION" LICENSE_ORGANIZATION_OFFICIAL_ID="$LICENSE_ORGANIZATION_OFFICIAL_ID" node --input-type=module - <<'NODE'
import { buildOrganizationRoleLicenseId } from 'sos-data-utils-ts/organization-role-license';
import { EXAMPLE_ORGANIZATION_ROLE_LICENSE_IDENTITY as example } from 'sos-data-utils-ts/organization-role-license-examples';
const identity = { ...example, jurisdiction: process.env.LICENSE_JURISDICTION, organizationOfficialId: process.env.LICENSE_ORGANIZATION_OFFICIAL_ID };
console.log(JSON.stringify({ ...identity, id: buildOrganizationRoleLicenseId(identity) }));
NODE
)"
LICENSE_ID="$(jq -r '.id' <<<"$identity_json")"
CONTACT_ID="$(jq -r '.stableContactIdentifier' <<<"$identity_json")"
LICENSED_ROLE="$(jq -r '.licensedRole' <<<"$identity_json")"
LICENSE_MAX_DEVICES="${LICENSE_MAX_DEVICES:-}"
if [[ -n "$LICENSE_MAX_DEVICES" && ! "$LICENSE_MAX_DEVICES" =~ ^[1-9][0-9]*$ ]]; then
  echo "LICENSE_MAX_DEVICES must be omitted or a positive integer." >&2; exit 2
fi

for command_name in docker jq; do
  command -v "${command_name}" >/dev/null 2>&1 || { echo "ERROR: missing ${command_name}" >&2; exit 2; }
done

peer_env=(
  env
  CORE_PEER_LOCALMSPID="${ORG1_MSP_ID}"
  CORE_PEER_MSPCONFIGPATH="${ORG1_ADMIN_MSP}"
  CORE_PEER_ADDRESS=peer0-host1:7051
  CORE_PEER_TLS_ENABLED=true
  CORE_PEER_TLS_ROOTCERT_FILE="${ORG1_PEER_TLS}"
)

invoke() {
  local function_name="$1"
  shift
  local invocation
  invocation="$(jq -cn --arg fn "${function_name}" --args '{Args: ([$fn] + $ARGS.positional)}' -- "$@")"
  docker exec "${FABRIC_TOOLS_CONTAINER}" "${peer_env[@]}" \
    peer chaincode invoke \
    -o orderer:7050 --ordererTLSHostnameOverride orderer --tls --cafile "${ORDERER_TLS_CA}" \
    -C "${CHANNEL_NAME}" -n "${CHAINCODE_NAME}" -c "${invocation}" --waitForEvent >/dev/null
}

query() {
  local function_name="$1"
  shift
  local invocation
  invocation="$(jq -cn --arg fn "${function_name}" --args '{Args: ([$fn] + $ARGS.positional)}' -- "$@")"
  docker exec "${FABRIC_TOOLS_CONTAINER}" "${peer_env[@]}" \
    peer chaincode query -C "${CHANNEL_NAME}" -n "${CHAINCODE_NAME}" -c "${invocation}"
}

create_payload="$(jq -cn \
  --arg id "${LICENSE_ID}" \
  --arg organizationId "${ORGANIZATION_ID}" \
  --arg organizationOfficialId "${LICENSE_ORGANIZATION_OFFICIAL_ID}" \
  --arg stableContactIdentifier "${CONTACT_ID}" \
  --arg jurisdiction "${LICENSE_JURISDICTION}" \
  --arg sector "${LICENSE_SECTOR}" \
  --arg role "${LICENSED_ROLE}" --arg limit "${LICENSE_MAX_DEVICES}" \
  '{id:$id,organizationId:$organizationId,organizationOfficialId:$organizationOfficialId,jurisdiction:$jurisdiction,stableContactIdentifier:$stableContactIdentifier,licensedRole:$role,data:[({sector:$sector,active:true} + (if $limit == "" then {} else {maxDevices:($limit|tonumber)} end))]}')"

echo "[smoke-rolelicense] ensuring the regional organisation-role licence on ${CHANNEL_NAME}"
invoke EnsureRoleLicense "${LICENSE_ID}" "${create_payload}"
invoke UpsertSectorPolicy "${LICENSE_ID}" \
  "$(jq -cn --arg sector "${LICENSE_SECTOR}" --arg limit "$LICENSE_MAX_DEVICES" '{sector:$sector,active:true} + (if $limit == "" then {} else {maxDevices:($limit|tonumber)} end)')" \
  20

asset="$(query ReadRoleLicense "${LICENSE_ID}")"
jq -e --arg organizationOfficialId "${LICENSE_ORGANIZATION_OFFICIAL_ID}" --arg sector "${LICENSE_SECTOR}" --arg role "$LICENSED_ROLE" --arg limit "$LICENSE_MAX_DEVICES" '
  .organizationOfficialId == $organizationOfficialId
  and .licensedRole == $role
  and (.data | any(.sector == $sector and .active == true and (if $limit == "" then (has("maxDevices") | not) else .maxDevices == ($limit|tonumber) end)))
  and (has("devices") | not)
' <<<"${asset}" >/dev/null

echo "[smoke-rolelicense] regional role-licence policy readback succeeded; gateway DCR capacity is a separate gate"
