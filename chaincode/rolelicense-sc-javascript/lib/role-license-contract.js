/* SPDX-License-Identifier: Apache-2.0 */
"use strict";

const { Contract } = require("fabric-contract-api");

const ASSET_LABEL = "RoleLicense";
const ORGANIZATION_INDEX = "rolelicense~organization";
const FORBIDDEN_PERSONAL_FIELDS = ["email", "phone", "telephone", "employeeId", "subjectId"];

function txSeconds(stub) {
  const raw = stub.getTxTimestamp().seconds;
  return typeof raw === "object" && typeof raw.toNumber === "function" ? raw.toNumber() : Number(raw);
}

function required(value, label) {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function parseObject(input, label) {
  if (!input) throw new Error(`${label} is required`);
  const value = JSON.parse(input);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value;
}

function parseTimestamp(input) {
  const value = Number(input);
  if (!Number.isFinite(value)) throw new Error("Invalid timestamp");
  return value;
}

function normalizeSector(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeMaxDevices(value) {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < 1) throw new Error("maxDevices must be omitted or a positive integer");
  return value;
}

function normalizePolicies(data) {
  if (!Array.isArray(data) || data.length === 0) throw new Error("data must contain at least one sector policy");
  const seen = new Set();
  return data.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("sector policy must be an object");
    const sector = normalizeSector(item.sector);
    if (!sector) throw new Error("sector policy requires a canonical sector");
    if (seen.has(sector)) throw new Error(`Duplicate sector policy ${sector}`);
    seen.add(sector);
    const maxDevices = normalizeMaxDevices(item.maxDevices);
    return { sector, active: item.active === true, ...(maxDevices === undefined ? {} : { maxDevices }) };
  });
}

function assertNoPersonalFields(payload) {
  for (const field of FORBIDDEN_PERSONAL_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(payload, field)) throw new Error(`${field} must not be stored in a role licence`);
  }
}

async function readAsset(ctx, id) {
  const buffer = await ctx.stub.getState(id);
  if (!buffer || buffer.length === 0) throw new Error(`${ASSET_LABEL} ${id} does not exist`);
  return JSON.parse(buffer.toString("utf8"));
}

async function exists(ctx, id) {
  const buffer = await ctx.stub.getState(id);
  return !!buffer && buffer.length > 0;
}

async function write(ctx, asset) {
  await ctx.stub.putState(asset.id, Buffer.from(JSON.stringify(asset)));
}

function projectCreatePayload(id, payload, now) {
  assertNoPersonalFields(payload);
  if (payload.id && payload.id !== id) throw new Error(`Payload id ${payload.id} does not match ${id}`);
  const organizationOfficialId = required(payload.organizationOfficialId, "organizationOfficialId");
  if (organizationOfficialId.includes(":") || /^urn:/i.test(organizationOfficialId)) {
    throw new Error("organizationOfficialId must be the official identifier value, not an organization URN");
  }
  const jurisdiction = required(payload.jurisdiction, "jurisdiction").toLowerCase();
  const stableContactIdentifier = required(payload.stableContactIdentifier, "stableContactIdentifier");
  if (!/^urn:multibase:z[1-9A-HJ-NP-Za-km-z]+$/.test(stableContactIdentifier)) {
    throw new Error("stableContactIdentifier must be a canonical urn:multibase value");
  }
  const licensedRole = required(payload.licensedRole, "licensedRole");
  const status = payload.status || "active";
  if (status !== "active") throw new Error("A new role licence must be active");
  return {
    id,
    organizationOfficialId,
    jurisdiction,
    stableContactIdentifier,
    licensedRole,
    status,
    data: normalizePolicies(payload.data),
    createdAt: now,
    updatedAt: now,
  };
}

function sameIdentity(left, right) {
  return left.organizationOfficialId === right.organizationOfficialId
    && left.jurisdiction === right.jurisdiction
    && left.stableContactIdentifier === right.stableContactIdentifier
    && left.licensedRole === right.licensedRole;
}

function normalizeHistoryTimestamp(timestamp) {
  const raw = timestamp && timestamp.seconds;
  if (raw && typeof raw.toNumber === "function") return raw.toNumber();
  if (raw && typeof raw.low === "number") return raw.low;
  return Number(raw || 0);
}

class RoleLicenseContract extends Contract {
  async CreateRoleLicense(ctx, id, payloadJson) {
    if (await exists(ctx, id)) throw new Error(`${ASSET_LABEL} ${id} already exists`);
    const asset = projectCreatePayload(id, parseObject(payloadJson, "payload"), txSeconds(ctx.stub));
    await write(ctx, asset);
    const indexKey = ctx.stub.createCompositeKey(ORGANIZATION_INDEX, [asset.organizationOfficialId, id]);
    await ctx.stub.putState(indexKey, Buffer.from(""));
    return asset;
  }

  async createRoleLicense(ctx, id, payloadJson) { return this.CreateRoleLicense(ctx, id, payloadJson); }

  async EnsureRoleLicense(ctx, id, payloadJson) {
    const payload = parseObject(payloadJson, "payload");
    if (!(await exists(ctx, id))) return { created: true, asset: await this.CreateRoleLicense(ctx, id, payloadJson) };
    const current = await readAsset(ctx, id);
    const candidate = projectCreatePayload(id, payload, txSeconds(ctx.stub));
    if (!sameIdentity(current, candidate)) throw new Error(`ROLE_LICENSE_CONFLICT:${id}`);
    return { created: false, asset: current };
  }

  async ensureRoleLicense(ctx, id, payloadJson) { return this.EnsureRoleLicense(ctx, id, payloadJson); }
  async ReadRoleLicense(ctx, id) { return readAsset(ctx, id); }
  async readRoleLicense(ctx, id) { return this.ReadRoleLicense(ctx, id); }

  async ListRoleLicensesByOrganization(ctx, organizationOfficialId) {
    const id = required(organizationOfficialId, "organizationOfficialId");
    const iterator = await ctx.stub.getStateByPartialCompositeKey(ORGANIZATION_INDEX, [id]);
    const assets = [];
    while (true) {
      const result = await iterator.next();
      if (result.value) {
        const split = ctx.stub.splitCompositeKey(result.value.key);
        assets.push(await readAsset(ctx, split.attributes[1]));
      }
      if (result.done) { await iterator.close(); break; }
    }
    return assets;
  }

  async listRoleLicensesByOrganization(ctx, organizationOfficialId) {
    return this.ListRoleLicensesByOrganization(ctx, organizationOfficialId);
  }

  async UpsertSectorPolicy(ctx, id, policyJson, ts) {
    const asset = await readAsset(ctx, id);
    if (asset.status !== "active") throw new Error("Cannot update a revoked role licence");
    const next = normalizePolicies([parseObject(policyJson, "policy")])[0];
    const normalized = next.sector;
    const index = asset.data.findIndex((item) => item.sector === normalized);
    if (index >= 0) asset.data[index] = next; else asset.data.push(next);
    asset.data = normalizePolicies(asset.data);
    asset.updatedAt = parseTimestamp(ts);
    await write(ctx, asset);
    return asset;
  }

  async upsertSectorPolicy(ctx, id, policyJson, ts) {
    return this.UpsertSectorPolicy(ctx, id, policyJson, ts);
  }

  async RevokeRoleLicense(ctx, id, ts) {
    const asset = await readAsset(ctx, id);
    const timestamp = parseTimestamp(ts);
    asset.status = "revoked";
    asset.revokedAt = timestamp;
    asset.updatedAt = timestamp;
    await write(ctx, asset);
    return asset;
  }

  async revokeRoleLicense(ctx, id, ts) { return this.RevokeRoleLicense(ctx, id, ts); }

  async GetRoleLicenseHistory(ctx, id) {
    const iterator = await ctx.stub.getHistoryForKey(id);
    const history = [];
    while (true) {
      const result = await iterator.next();
      if (result.value) history.push({
        txId: result.value.txId,
        timestamp: normalizeHistoryTimestamp(result.value.timestamp),
        isDelete: result.value.isDelete,
        value: result.value.value && result.value.value.length
          ? JSON.parse(result.value.value.toString("utf8")) : null,
      });
      if (result.done) { await iterator.close(); break; }
    }
    return history;
  }

  async getRoleLicenseHistory(ctx, id) { return this.GetRoleLicenseHistory(ctx, id); }
}

module.exports = RoleLicenseContract;
