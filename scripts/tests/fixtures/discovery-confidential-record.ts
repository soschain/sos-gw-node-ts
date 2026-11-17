// Flow contract: both discovery sections carry the owned protected envelope, including status, revision and indexed metadata.
import type { ConfidentialStorageDoc } from 'sos-data-utils-ts/confidential-storage';
const request: ConfidentialStorageDoc = {id:'communication-request-one',status:'active',sequence:1,contentType:'application/jose+json',jwe:{protected:'synthetic-header',iv:'synthetic-iv',ciphertext:'synthetic-ciphertext',tag:'synthetic-tag'}};
const document: ConfidentialStorageDoc = {id:'document-reference-one',status:'active',sequence:0,content:{claims:{'DocumentReference.status':'current'}}};
const records: readonly ConfidentialStorageDoc[] = [request,document];
const identifiers: readonly string[] = records.map(record=>record.id);
void identifiers;
// @ts-expect-error A physical record identity must remain a string.
const wrongIdentity: ConfidentialStorageDoc = {...request,id:1};
// @ts-expect-error A revision is a number, never a string counter.
const wrongRevision: ConfidentialStorageDoc = {...document,sequence:'1'};
void wrongIdentity;void wrongRevision;
