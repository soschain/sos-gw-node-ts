// Flow contract: the actual public seat owner preserves independent tenant/member/contact/install fields; compile failures guard epoch-second types and the distinct OIDC device metadata contract.
import {DeviceAppTypes,DeviceBindingStatuses,DeviceUserClasses,type DeviceInfo,type DeviceBinding,type DeviceLicense,type DeviceRestrictions} from 'sos-data-utils-ts/device-license-contract';
import {REPOSITORY_SAFE_EXAMPLES as safe} from 'sos-data-utils-ts/repository-privacy';
const installation:DeviceInfo={clientInstanceId:safe.resourceUuid,os:'test-platform',osVersion:'1',manufacturer:'example-manufacturer',model:'example-model'};
const restrictions:DeviceRestrictions={manufacturer:'^example-',model:'^example-'};
const binding:DeviceBinding={clientId:safe.resourceUuid,clientInstanceId:installation.clientInstanceId,status:DeviceBindingStatuses.Revoked,deviceInfo:installation,activatedAt:1,revokedAt:2};
const seat:DeviceLicense={id:safe.resourceUuid,tenantId:safe.tenantId,ownerOrganizationId:safe.organizationScopedResources.organizationUrn,authorizedSubjectDid:safe.didWeb,orderId:safe.resourceUuid,activationCode:'synthetic-code',userClass:DeviceUserClasses.Employee,userCategory:'medicalStaff',type:DeviceAppTypes.Web,status:'issued',plan:'test-plan',renewalCycle:null,reactivationEnabled:true,issuedAt:1,activatedAt:2,exp:3,subjectId:safe.resourceUuid,issuedToEmail:safe.firstContactEmail,issuedToPhone:safe.firstContactPhoneE164,issuedToRole:'2261',invitationId:safe.resourceUuid,relatedPersonId:safe.firstContactIdentifier,deviceId:safe.resourceUuid,maxDevices:2,deviceBindings:[binding],activatedBy:safe.didWeb,deviceRestrictions:restrictions,deviceInfo:installation};
const legacy:DeviceLicense={id:seat.id,tenantId:seat.tenantId,orderId:seat.orderId,userClass:'individual',type:'mobile',status:'available',plan:seat.plan,renewalCycle:'1m',reactivationEnabled:false,exp:0};
// @ts-expect-error Persisted times are numeric Unix epoch seconds, not serialized dates.
const invalidTime:DeviceLicense={...seat,exp:'2026-01-01T00:00:00Z'};
// @ts-expect-error Revoked installation state is not a seat lifecycle value.
const invalidSeat:DeviceLicense={...seat,status:'revoked'};
// @ts-expect-error Seat inactivity is not an installation binding state.
const invalidBinding:DeviceBinding={...binding,status:'inactive'};
// @ts-expect-error OIDC ext_device_info is a separate metadata contract.
const oidcDevice:DeviceInfo={device_id:safe.resourceUuid,device_name:'test-device'};
void [legacy,invalidTime,invalidSeat,invalidBinding,oidcDevice];
