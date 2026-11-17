import { decodeReminderPermissionBundle } from 'sos-data-utils-ts/reminder-metadata';
import { evaluateReminderRuntimeAccess, ReminderActions, ReminderActorKinds, ReminderChannels, ReminderEntityKinds } from 'sos-sdk-core-ts/reminder-permissions';
/** Stored task policy is evaluated separately for every dispatched or grouped task. */
export function evaluateReminderTaskVoiceAccess(task: { subjectId: string; metadata?: Record<string, unknown> }) {
  return evaluateReminderRuntimeAccess({
    subject: task.subjectId,
    permissionBundle: decodeReminderPermissionBundle(task.metadata),
    actorKind: ReminderActorKinds.Assistant,
    actorId: 'voice-assistant',
    action: ReminderActions.Execute,
    entity: ReminderEntityKinds.DispatchWindow,
    channel: ReminderChannels.Phone,
  });
}
