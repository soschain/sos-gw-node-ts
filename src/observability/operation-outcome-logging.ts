// Copyright 2025 Antifraud Services Inc. under the Apache License, Version 2.0.

import { isIssueSeverityCode, isIssueTypeCode } from 'fhir-data-utils-ts/operation-outcome';
import type { NextFunction, Request, RequestHandler, Response } from 'express';

const ERROR_SEVERITIES = new Set(['error', 'fatal']);
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_ISSUES_PER_EVENT = 25;

type JsonRecord = Record<string, unknown>;

export interface OperationOutcomeIssueLog {
  severity?: string;
  code?: string;
  responseStatus?: number;
  entryIndex?: number;
}

export interface OperationOutcomeLogContext {
  source: 'http_response' | 'worker_response' | 'worker_exception';
  httpStatus?: number;
  method?: string;
  path?: string;
  thid?: string;
}

export interface StructuredOperationOutcomeLog extends OperationOutcomeLogContext {
  severity: 'ERROR';
  event: 'operation_outcome_error';
  message: string;
  issueCount: number;
  issues: OperationOutcomeIssueLog[];
  issuesTruncated?: boolean;
}

export interface StructuredHttpErrorLog extends Omit<OperationOutcomeLogContext, 'source'> {
  severity: 'ERROR';
  event: 'http_error_response';
  message: string;
  source: 'http_response';
  operationOutcomeDetected: false;
}

export type StructuredErrorLog = StructuredOperationOutcomeLog | StructuredHttpErrorLog;
export type StructuredErrorLogSink = (entry: StructuredErrorLog) => void;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseStatus(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value !== 'string') return undefined;
  const match = value.match(/^\s*(\d{3})/);
  return match ? Number(match[1]) : undefined;
}

function normalizeIssue(
  issue: unknown,
  responseStatus: number | undefined,
  entryIndex: number | undefined,
): OperationOutcomeIssueLog | undefined {
  if (!isRecord(issue)) return undefined;
  const severity = isIssueSeverityCode(issue.severity) ? issue.severity : undefined;
  const isFailedStatus = responseStatus !== undefined && responseStatus >= 400;
  if (!isFailedStatus && !ERROR_SEVERITIES.has(severity || '')) return undefined;

  return {
    ...(severity ? { severity } : {}),
    ...(isIssueTypeCode(issue.code) ? { code: issue.code } : {}),
    ...(responseStatus !== undefined ? { responseStatus } : {}),
    ...(entryIndex !== undefined ? { entryIndex } : {}),
  };
}

function collectIssueArray(
  issues: unknown,
  responseStatus: number | undefined,
  entryIndex: number | undefined,
): OperationOutcomeIssueLog[] {
  if (!Array.isArray(issues)) return [];
  return issues
    .map((issue) => normalizeIssue(issue, responseStatus, entryIndex))
    .filter((issue): issue is OperationOutcomeIssueLog => Boolean(issue));
}

function parsePayload(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (!trimmed.startsWith('{') && !trimmed.startsWith('[')) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

/**
 * Extracts only failure metadata from supported GW/FHIR response shapes.
 * It deliberately does not recurse through clinical `resource` content.
 */
export function collectOperationOutcomeErrors(
  payload: unknown,
  outerStatus?: number,
): OperationOutcomeIssueLog[] {
  const root = parsePayload(payload);
  const collected: OperationOutcomeIssueLog[] = [];
  const visited = new Set<object>();

  const visit = (value: unknown, inheritedStatus?: number, entryIndex?: number): void => {
    const parsed = parsePayload(value);
    if (!isRecord(parsed) || visited.has(parsed)) return;
    visited.add(parsed);

    const response = isRecord(parsed.response) ? parsed.response : undefined;
    const explicitResponseStatus = parseStatus(response?.status);
    const responseStatus = explicitResponseStatus ?? inheritedStatus;

    if (parsed.resourceType === 'OperationOutcome') {
      collected.push(...collectIssueArray(parsed.issue, responseStatus, entryIndex));
    }

    const issuesContainer = isRecord(parsed.issues) ? parsed.issues : undefined;
    if (issuesContainer) {
      collected.push(...collectIssueArray(issuesContainer.issue, responseStatus, entryIndex));
    }

    const outcome = response && isRecord(response.outcome) ? response.outcome : undefined;
    const outcomeIssues = outcome ? collectIssueArray(outcome.issue, responseStatus, entryIndex) : [];
    collected.push(...outcomeIssues);

    if (explicitResponseStatus !== undefined && explicitResponseStatus >= 400 && outcomeIssues.length === 0) {
      collected.push({
        severity: 'error',
        code: 'missing-operation-outcome',
        responseStatus: explicitResponseStatus,
        ...(entryIndex !== undefined ? { entryIndex } : {}),
      });
    }

    if (parsed.body !== undefined) visit(parsed.body, responseStatus, entryIndex);

    for (const collectionName of ['data', 'entry'] as const) {
      const entries = parsed[collectionName];
      if (!Array.isArray(entries)) continue;
      entries.forEach((entry, index) => visit(entry, responseStatus, index));
    }

    // Some APIs return a raw OperationOutcome under `outcome`, outside an entry response.
    if (isRecord(parsed.outcome) && parsed.outcome !== outcome) {
      visit(parsed.outcome, responseStatus, entryIndex);
    }
  };

  visit(root, outerStatus);
  return collected;
}

function defaultSink(entry: StructuredErrorLog): void {
  console.error(JSON.stringify(entry));
}

export function logOperationOutcomeErrors(
  payload: unknown,
  context: OperationOutcomeLogContext,
  sink: StructuredErrorLogSink = defaultSink,
): number {
  const issues = collectOperationOutcomeErrors(payload, context.httpStatus);
  if (issues.length === 0) return 0;

  sink({
    severity: 'ERROR',
    event: 'operation_outcome_error',
    message: 'GW response contains one or more failed OperationOutcome issues',
    source: context.source,
    httpStatus: context.httpStatus,
    method: context.method,
    path: context.path,
    ...(context.thid && UUID_V4.test(context.thid) ? { thid: context.thid } : {}),
    issueCount: issues.length,
    issues: issues.slice(0, MAX_ISSUES_PER_EVENT),
    ...(issues.length > MAX_ISSUES_PER_EVENT ? { issuesTruncated: true } : {}),
  });
  return issues.length;
}

function requestRoute(req: Request): string | undefined {
  return isRecord(req.route) && typeof req.route.path === 'string'
    ? req.route.path
    : undefined;
}

/**
 * Observes completed Express responses without logging request/response bodies.
 * - HTTP >= 400 is always logged.
 * - HTTP 200 bundles are logged when an entry has status >= 400 or an
 *   OperationOutcome issue has severity `error`/`fatal`.
 */
export function createOperationOutcomeLoggingMiddleware(
  sink: StructuredErrorLogSink = defaultSink,
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    let responseBody: unknown;
    const originalJson = res.json.bind(res);
    const originalSend = res.send.bind(res);

    res.json = ((body: unknown) => {
      if (responseBody === undefined) responseBody = body;
      return originalJson(body);
    }) as Response['json'];

    res.send = ((body: unknown) => {
      if (responseBody === undefined) responseBody = body;
      return originalSend(body);
    }) as Response['send'];

    res.once('finish', () => {
      const context: OperationOutcomeLogContext = {
        source: 'http_response',
        httpStatus: res.statusCode,
        method: req.method,
        // Prefer the parameterized Express route and never include the query string.
        path: requestRoute(req),
      };
      const issueCount = logOperationOutcomeErrors(responseBody, context, sink);
      if (res.statusCode >= 400 && issueCount === 0) {
        sink({
          severity: 'ERROR',
          event: 'http_error_response',
          message: 'GW returned an HTTP error response without a detectable OperationOutcome',
          ...context,
          source: 'http_response',
          operationOutcomeDetected: false,
        });
      }
    });

    next();
  };
}
