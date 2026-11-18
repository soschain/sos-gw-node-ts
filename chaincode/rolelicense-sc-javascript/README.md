# Organization role licence chaincode

`rolelicense-sc` stores organization-owned licence assignments on the regional
organization identity channel (`identity-eu`, `identity-na`, and so on). It is
not deployed on `identity-global`, which is reserved for natural-person identity.

The deterministic asset identity binds the official organization identifier,
one stable hashed email/telephone identifier and the licensed role. A different
role is a different licence. Tenant-local employee UUIDs and clear contact or
payment data are prohibited.

`data[]` holds explicit sector policies (`sector`, `active`, and optional
`maxDevices`). The contract creates/ensures the licence, updates one sector,
revokes the licence, and returns its Fabric history. It stores no DCR device
list and exposes no `RegisterDevice` operation.

The gateway checks the current licence and its sector policy when registering
or replacing a device and enforces the configured installation capacity there.
An omitted `maxDevices` leaves that capacity to gateway policy; a policy value
is not evidence that a blockchain transaction registers or counts devices.

This compatibility source follows the canonical contract in
`fabric-multicloud/devnet/fabric-v3/external-chaincodes/rolelicense-sc`.
Reconciling these local files does not change a deployed contract, its package
identifier, channel definitions, ledger data or CCAAS image.

Test Network and production use the same Offer/Order/payment-evidence and
licence-registration path; only the configured payment provider/environment
differs.

