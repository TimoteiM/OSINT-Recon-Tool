import { randomUUID } from "crypto";

import { runRecon } from "./recon-runner";

type SherlockJobStatus = "running" | "completed" | "error";

type SherlockProviderResult = {
  status: string;
  notes: string[];
  progress_logs: string[];
  duration_ms: number | null;
  emails: string[];
  email_sources: Array<Record<string, unknown>>;
  social_profiles: Record<string, { url: string; status: string; source?: string }>;
  impersonation_candidates: Array<Record<string, unknown>>;
  subdomains: string[];
  repos: Array<Record<string, unknown>>;
  breach_hints: Array<Record<string, unknown>>;
  dns_records: Array<Record<string, unknown>>;
  whois: Array<Record<string, unknown>>;
  ssl: Array<Record<string, unknown>>;
  tech: Array<Record<string, unknown>>;
  ports: Array<Record<string, unknown>>;
  hosting: Array<{ value: string; type: string }>;
  mentions: Array<Record<string, unknown>>;
};

type SherlockProviderId = "sherlock";

type SherlockJob = {
  job_id: string;
  provider_id: SherlockProviderId;
  scan_id: string;
  company_name: string;
  target_domain: string;
  status: SherlockJobStatus;
  started_at: string;
  updated_at: string;
  elapsed_ms: number;
  progress_logs: string[];
  provider_result: SherlockProviderResult;
  report: Record<string, unknown> | null;
  error?: string;
};

type StartSherlockJobOptions = {
  companyName: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  runReconImpl?: typeof runRecon;
  schedulePolling?: boolean;
};

const jobs = new Map<string, SherlockJob>();

function nowIso(): string {
  return new Date().toISOString();
}

function nowMs(): number {
  return Date.now();
}

function refreshElapsed(job: SherlockJob): void {
  job.updated_at = nowIso();
  job.elapsed_ms = nowMs() - Date.parse(job.started_at);
  job.provider_result.duration_ms = job.elapsed_ms;
}

function trimLogs(logs: string): string[] {
  return logs
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(-200);
}

function normalizeTargetDomain(value: string): string {
  const lowered = value.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (!lowered || lowered.includes(" ") || !lowered.includes(".")) {
    return value.trim();
  }
  return lowered;
}

function makeRunningSherlockProviderResult(): SherlockProviderResult {
  return {
    status: "running",
    notes: ["Sherlock background scan queued"],
    progress_logs: [],
    duration_ms: null,
    emails: [],
    email_sources: [],
    social_profiles: {},
    impersonation_candidates: [],
    subdomains: [],
    repos: [],
    breach_hints: [],
    dns_records: [],
    whois: [],
    ssl: [],
    tech: [],
    ports: [],
    hosting: [],
    mentions: [],
  };
}

function createErrorSherlockProviderResult(message: string): SherlockProviderResult {
  return {
    ...makeRunningSherlockProviderResult(),
    status: "error",
    notes: [message],
    progress_logs: [],
  };
}

function extractProviderResult(report: Record<string, unknown> | null): SherlockProviderResult {
  const providerResult = report?.provider_results && typeof report.provider_results === "object"
    ? (report.provider_results as Record<string, unknown>).sherlock
    : undefined;

  if (!providerResult || typeof providerResult !== "object") {
    return makeRunningSherlockProviderResult();
  }

  const result = providerResult as Record<string, unknown>;
  return {
    status: typeof result.status === "string" ? result.status : "completed",
    notes: Array.isArray(result.notes) ? result.notes.filter((note): note is string => typeof note === "string") : [],
    progress_logs: Array.isArray(result.progress_logs)
      ? result.progress_logs.filter((line): line is string => typeof line === "string")
      : [],
    duration_ms: typeof result.duration_ms === "number" ? result.duration_ms : null,
    emails: Array.isArray(result.emails) ? result.emails.filter((item): item is string => typeof item === "string") : [],
    email_sources: Array.isArray(result.email_sources) ? result.email_sources.filter((item) => Boolean(item)) : [],
    social_profiles: result.social_profiles && typeof result.social_profiles === "object"
      ? (result.social_profiles as Record<string, { url: string; status: string; source?: string }>)
      : {},
    impersonation_candidates: Array.isArray(result.impersonation_candidates)
      ? result.impersonation_candidates.filter((item) => Boolean(item))
      : [],
    subdomains: Array.isArray(result.subdomains) ? result.subdomains.filter((item): item is string => typeof item === "string") : [],
    repos: Array.isArray(result.repos) ? result.repos.filter((item) => Boolean(item)) : [],
    breach_hints: Array.isArray(result.breach_hints) ? result.breach_hints.filter((item) => Boolean(item)) : [],
    dns_records: Array.isArray(result.dns_records) ? result.dns_records.filter((item) => Boolean(item)) : [],
    whois: Array.isArray(result.whois) ? result.whois.filter((item) => Boolean(item)) : [],
    ssl: Array.isArray(result.ssl) ? result.ssl.filter((item) => Boolean(item)) : [],
    tech: Array.isArray(result.tech) ? result.tech.filter((item) => Boolean(item)) : [],
    ports: Array.isArray(result.ports) ? result.ports.filter((item) => Boolean(item)) : [],
    hosting: Array.isArray(result.hosting)
      ? result.hosting.filter((item): item is { value: string; type: string } => Boolean(item))
      : [],
    mentions: Array.isArray(result.mentions) ? result.mentions.filter((item) => Boolean(item)) : [],
  };
}

async function finalizeSherlockJob(
  job: SherlockJob,
  result: Awaited<ReturnType<typeof runRecon>>,
): Promise<void> {
  const report = (result.data && typeof result.data === "object" ? result.data : null) as Record<string, unknown> | null;
  const providerResult = extractProviderResult(report);
  const normalizedReport = report ? { ...report } : {};
  normalizedReport.provider_results = {
    ...(normalizedReport.provider_results && typeof normalizedReport.provider_results === "object"
      ? (normalizedReport.provider_results as Record<string, unknown>)
      : {}),
    sherlock: providerResult,
  };

  job.report = normalizedReport;
  job.provider_result = providerResult;
  job.progress_logs = trimLogs(result.logs || "");
  job.provider_result.progress_logs = job.progress_logs;
  job.status = providerResult.status === "error" ? "error" : "completed";
  refreshElapsed(job);
}

async function runSherlockBackgroundScan(job: SherlockJob, options: StartSherlockJobOptions): Promise<void> {
  try {
    const result = await (options.runReconImpl || runRecon)({
      companyName: job.company_name,
      selectedSources: ["sherlock"],
      cwd: options.cwd,
      env: options.env,
    });
    await finalizeSherlockJob(job, result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown Sherlock startup failure";
    job.status = "error";
    job.error = message;
    job.provider_result = createErrorSherlockProviderResult(`Sherlock startup failed: ${message}`);
    job.provider_result.progress_logs = [];
    job.progress_logs = [];
    job.report = {
      provider_results: {
        sherlock: job.provider_result,
      },
    };
    refreshElapsed(job);
  }
}

export async function startSherlockJob(options: StartSherlockJobOptions): Promise<SherlockJob> {
  const startedAt = nowIso();
  const job: SherlockJob = {
    job_id: randomUUID(),
    provider_id: "sherlock",
    scan_id: randomUUID(),
    company_name: options.companyName,
    target_domain: normalizeTargetDomain(options.companyName),
    status: "running",
    started_at: startedAt,
    updated_at: startedAt,
    elapsed_ms: 0,
    progress_logs: [],
    provider_result: makeRunningSherlockProviderResult(),
    report: null,
  };

  jobs.set(job.job_id, job);
  refreshElapsed(job);
  void runSherlockBackgroundScan(job, options);
  return job;
}

export function getSherlockJob(jobId: string): SherlockJob | undefined {
  return jobs.get(jobId);
}

export function createRunningSherlockProviderResult(): SherlockProviderResult {
  return makeRunningSherlockProviderResult();
}
