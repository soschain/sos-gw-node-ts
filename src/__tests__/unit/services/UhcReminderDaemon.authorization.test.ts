/** Flow contract: scheduled voice jobs require their own stored subject-bound explicit assistant policy; grouping never grants another task authority or leaks its identifier. */
import { describe, it, expect, jest } from '@jest/globals';
import { UhcReminderDaemon } from '../../../services/UhcReminderDaemon.js';
import { encodeReminderPermissionBundle } from 'sos-data-utils-ts/reminder-metadata';
import { REPOSITORY_SAFE_EXAMPLES as SAFE } from 'sos-data-utils-ts/repository-privacy';

const policy = (subject: string = SAFE.didWeb) => encodeReminderPermissionBundle({ subject, purpose: 'reminder-delivery', rules: [{ actorKind: 'assistant', actorId: 'voice-assistant', decision: 'allow', actions: ['execute'], entities: ['dispatch-window'], channels: ['phone'], purpose: 'reminder-delivery' }] });
const task = (id: string, metadata: Record<string, string> = {}): any => ({ id, subjectId: SAFE.didWeb, status: 'scheduled', createdAt: '2026-01-01T00:00:00Z', updatedAt: '2026-01-01T00:00:00Z', scheduledFor: '2026-01-01T00:00:00Z', title: 'Reminder', metadata: { 'voice-to': SAFE.phoneE164, ...metadata } });
function harness(tasks: any[]) {
 const calls = jest.fn(async () => ({ sid: 'example-call', status: 'queued', to: SAFE.phoneE164 }));
 const taskService = { listTasks: jest.fn(async () => tasks), getRepository: () => ({ save: jest.fn(async () => undefined) }) };
 const orchestrator = { isRootTask: () => true, selectNextCallTask: async (rootTask: any) => ({ rootTask, callTask: rootTask, pendingReminderCount: 1 }) };
 const daemon = new UhcReminderDaemon({ taskService: taskService as any, taskOrchestrator: orchestrator as any, phoneAdapter: { startVoiceReminderCall: calls } as any, apiBaseUrl: SAFE.httpsBaseUrl, pollSeconds: 30, enabled: true, voiceEnabled: true, maxAttempts: 1, groupWindowMinutes: 5, defaultLocale: 'en' });
 return { daemon, calls };
}
describe('stored reminder task authorization', () => {
 it('denies absent or differently bound policy before a call is started', async () => {
  for (const metadata of [{}, policy(SAFE.firstContactIdentifier)]) { const h = harness([task('denied-task', metadata)]); await h.daemon.tick(); expect(h.calls).not.toHaveBeenCalled(); }
 });
 it('calls an explicitly authorized task and excludes unauthorized grouped roots', async () => {
  const authorized = task('authorized-task', policy()), forbidden = task('forbidden-task');
  const h = harness([authorized, forbidden]); await h.daemon.tick();
  expect(h.calls).toHaveBeenCalledTimes(1);
  expect(authorized.metadata['voice-call-group-root-ids']).toBe('authorized-task');
 });
});
