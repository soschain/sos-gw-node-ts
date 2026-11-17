// Flow contract: canonical regional licence ensure/upsert/revoke/history remains independent of gateway DCR device capacity.
/* SPDX-License-Identifier: Apache-2.0 */
"use strict";

const chai = require("chai");
const chaiAsPromised = require("chai-as-promised");
chai.use(chaiAsPromised);
const { expect } = chai;
const moduleUnderTest = require("../index");
const { createContractContext } = require("./contract-test-context.cjs");

let ID;
let ORG_OFFICIAL_ID;
let CONTACT;
let JURISDICTION;
let LICENSED_ROLE;
let ROLE_LICENSE_POLICIES;

before(async () => {
  const roleLicenseExamples = await import("sos-data-utils-ts/organization-role-license-examples");
  ({
    id: ID,
    organizationOfficialId: ORG_OFFICIAL_ID,
    stableContactIdentifier: CONTACT,
    jurisdiction: JURISDICTION,
    licensedRole: LICENSED_ROLE,
  } = roleLicenseExamples.EXAMPLE_ORGANIZATION_ROLE_LICENSE);
  ROLE_LICENSE_POLICIES = roleLicenseExamples.EXAMPLE_ORGANIZATION_ROLE_LICENSE_POLICIES;
});

function payload(overrides = {}) {
  return {
    id: ID,
    organizationOfficialId: ORG_OFFICIAL_ID,
    jurisdiction: JURISDICTION,
    stableContactIdentifier: CONTACT,
    licensedRole: LICENSED_ROLE,
    data: ROLE_LICENSE_POLICIES,
    ...overrides,
  };
}

describe("RoleLicenseContract", () => {
  let contract;
  beforeEach(() => { contract = new moduleUnderTest.RoleLicenseContract(); });

  it("exports and creates a privacy-preserving organization licence", async () => {
    expect(moduleUnderTest.contracts).to.deep.equal([moduleUnderTest.RoleLicenseContract]);
    const ctx = createContractContext({ txSeconds: 10 });
    const asset = await contract.CreateRoleLicense(ctx, ID, JSON.stringify(payload()));
    expect(asset).to.include({
      id: ID,
      organizationOfficialId: ORG_OFFICIAL_ID,
      jurisdiction: JURISDICTION.toLowerCase(),
      licensedRole: LICENSED_ROLE,
      status: "active",
    });
    expect(asset).not.to.have.property("devices");
    expect(ctx.readJson(ID)).to.deep.equal(asset);
    expect(ctx.writes).to.have.length(2);
  });

  it("ensures the deterministic identity without creating a duplicate", async () => {
    const createCtx = createContractContext({ txSeconds: 10 });
    const created = await contract.ensureRoleLicense(createCtx, ID, JSON.stringify(payload()));
    expect(created.created).to.equal(true);
    const retryCtx = createContractContext({ existingState: { [ID]: created.asset }, txSeconds: 20 });
    expect(await contract.EnsureRoleLicense(retryCtx, ID, JSON.stringify(payload()))).to.deep.equal({ created: false, asset: created.asset });
    await expect(contract.EnsureRoleLicense(retryCtx, ID, JSON.stringify(payload({ licensedRole: "2211" }))))
      .to.be.rejectedWith(`ROLE_LICENSE_CONFLICT:${ID}`);
  });

  it("extends and deactivates one exact sector without authoring device state", async () => {
    const existing = { ...payload(), jurisdiction: "es", status: "active", createdAt: 1, updatedAt: 1 };
    const ctx = createContractContext({ existingState: { [ID]: existing } });
    await contract.upsertSectorPolicy(ctx, ID, JSON.stringify({ sector: "animal-care", active: true, maxDevices: 5 }), "20");
    const updated = await contract.UpsertSectorPolicy(ctx, ID, JSON.stringify({ sector: "animal-care", active: false, maxDevices: 5 }), "30");
    expect(updated.data).to.deep.include({ sector: "animal-care", active: false, maxDevices: 5 });
    expect(updated).not.to.have.property("devices");
  });

  it("omits maxDevices when the GW or portal owns the device limit", async () => {
    const existing = { ...payload(), jurisdiction: "es", status: "active", createdAt: 1, updatedAt: 1 };
    const ctx = createContractContext({ existingState: { [ID]: existing } });
    const updated = await contract.UpsertSectorPolicy(ctx, ID, JSON.stringify({ sector: "onehealth-research", active: true }), "20");
    expect(updated.data.find((item) => item.sector === "onehealth-research")).to.deep.equal({ sector: "onehealth-research", active: true });
  });

  it("globally revokes only the licence asset", async () => {
    const existing = { ...payload(), jurisdiction: "es", status: "active", createdAt: 1, updatedAt: 1 };
    const ctx = createContractContext({ existingState: { [ID]: existing } });
    const revoked = await contract.RevokeRoleLicense(ctx, ID, "50");
    expect(revoked.status).to.equal("revoked");
    expect(revoked.revokedAt).to.equal(50);
    expect(revoked).not.to.have.property("devices");
    await expect(contract.UpsertSectorPolicy(ctx, ID, JSON.stringify({ sector: "onehealth-research", active: true }), "51"))
      .to.be.rejectedWith("revoked role licence");
  });

  it("lists by organization and returns Fabric history", async () => {
    const asset = { ...payload(), jurisdiction: "es", status: "active", createdAt: 1, updatedAt: 1 };
    const index = `rolelicense~organization\u0000${ORG_OFFICIAL_ID}\u0000${ID}`;
    const history = [{ txId: "TX-1", timestamp: { seconds: { toNumber: () => 9 } }, isDelete: false, value: Buffer.from(JSON.stringify(asset)) }];
    const ctx = createContractContext({ existingState: { [ID]: asset, [index]: "" }, historyByKey: { [ID]: history } });
    expect(await contract.listRoleLicensesByOrganization(ctx, ORG_OFFICIAL_ID)).to.deep.equal([asset]);
    expect((await contract.getRoleLicenseHistory(ctx, ID))[0]).to.include({ txId: "TX-1", timestamp: 9 });
    expect(await contract.readRoleLicense(ctx, ID)).to.deep.equal(asset);
  });

  it("rejects clear personal data, invalid identities, policies and operations", async () => {
    await expect(contract.createRoleLicense(createContractContext(), ID, JSON.stringify(payload({ email: "private@example.org" }))))
      .to.be.rejectedWith("email must not be stored");
    await expect(contract.CreateRoleLicense(createContractContext(), ID, JSON.stringify(payload({ stableContactIdentifier: "private@example.org" }))))
      .to.be.rejectedWith("canonical urn:multibase");
    await expect(contract.CreateRoleLicense(createContractContext(), ID, JSON.stringify(payload({ organizationOfficialId: `urn:org:tax:${ORG_OFFICIAL_ID}` }))))
      .to.be.rejectedWith("official identifier value");
    await expect(contract.CreateRoleLicense(createContractContext(), ID, JSON.stringify(payload({ data: [] }))))
      .to.be.rejectedWith("at least one");
    await expect(contract.CreateRoleLicense(createContractContext({ existingState: { [ID]: payload() } }), ID, JSON.stringify(payload())))
      .to.be.rejectedWith("already exists");
    await expect(contract.ReadRoleLicense(createContractContext(), ID)).to.be.rejectedWith("does not exist");
    const existing = { ...payload(), jurisdiction: "es", status: "active", createdAt: 1, updatedAt: 1 };
    const ctx = createContractContext({ existingState: { [ID]: existing } });
    await expect(contract.UpsertSectorPolicy(ctx, ID, JSON.stringify({ sector: "health-care", active: true, maxDevices: 0 }), "2"))
      .to.be.rejectedWith("positive integer");
    await expect(contract.UpsertSectorPolicy(ctx, ID, JSON.stringify({ sector: "", active: true }), "2"))
      .to.be.rejectedWith("canonical sector");
    await expect(contract.UpsertSectorPolicy(ctx, ID, JSON.stringify({ sector: "health-care", active: true, maxDevices: null }), "2"))
      .to.be.rejectedWith("omitted or a positive integer");
  });
});
