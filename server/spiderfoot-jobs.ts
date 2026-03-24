import { randomUUID } from "crypto";
import { spawn, type ChildProcess } from "child_process";
import fs from "fs";
import path from "path";

import { resolvePythonCommand } from "./recon-runner";

type SpiderfootJobStatus = "running" | "completed" | "error";

type SpiderfootEmailSource = {
  email: string;
  module: string;
  module_type: "api" | "public" | "unknown";
  event_type: string;
  source: string;
  api_backed: boolean;
};

type SpiderfootProviderResult = {
  status: string;
  notes: string[];
  progress_logs: string[];
  duration_ms: number | null;
  emails: string[];
  email_sources: SpiderfootEmailSource[];
  social_profiles: Record<string, { url: string; status: string; source?: string }>;
  impersonation_candidates: unknown[];
  subdomains: string[];
  repos: unknown[];
  breach_hints: unknown[];
  dns_records: unknown[];
  whois: unknown[];
  ssl: unknown[];
  tech: unknown[];
  ports: unknown[];
  hosting: Array<{ value: string; type: string }>;
  mentions: Array<Record<string, unknown>>;
};

type SpiderfootProviderId = "spiderfoot" | "spiderfoot_deep";

type SpiderfootJob = {
  job_id: string;
  provider_id: SpiderfootProviderId;
  scan_id: string;
  company_name: string;
  target_domain: string;
  status: SpiderfootJobStatus;
  started_at: string;
  updated_at: string;
  elapsed_ms: number;
  progress_logs: string[];
  provider_result: SpiderfootProviderResult;
  report: Record<string, unknown> | null;
  error?: string;
  last_log_row_id: number;
  seen_event_ids: Set<string>;
};

type SpiderfootTransport = {
  postJson: (path: string, params?: Record<string, unknown>) => Promise<unknown>;
  getJson: (path: string, params?: Record<string, unknown>) => Promise<unknown>;
};

type SpiderfootModuleOption = {
  mod: string;
  opt: string;
  val: string;
};

type StartSpiderfootJobOptions = {
  companyName: string;
  providerId: SpiderfootProviderId;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  transport?: SpiderfootTransport;
  ensureService?: () => Promise<void>;
  schedulePolling?: boolean;
};

type PollSpiderfootJobOptions = {
  transport?: SpiderfootTransport;
  env?: NodeJS.ProcessEnv;
};

type SpiderfootServiceState = {
  process: ChildProcess | null;
  startPromise: Promise<void> | null;
  baseUrl: string;
};

const jobs = new Map<string, SpiderfootJob>();
const pollTimers = new Map<string, NodeJS.Timeout>();
const spiderfootService: SpiderfootServiceState = {
  process: null,
  startPromise: null,
  baseUrl: "",
};

const DEFAULT_POLL_INTERVAL_MS = 2500;
const DEFAULT_SERVICE_PORT = 5001;
const PASSIVE_EVENT_TYPES = [
  "EMAILADDR",
  "EMAILADDR_GENERIC",
  "INTERNET_NAME",
  "DOMAIN_NAME",
  "SOCIAL_MEDIA",
  "LINKED_URL_EXTERNAL",
  "URL_STATIC",
  "WEBSERVER_HTTPHEADERS",
  "IP_ADDRESS",
  "AFFILIATE_INTERNET_NAME",
].join(",");

function findReusableJob(companyName: string, providerId: SpiderfootProviderId): SpiderfootJob | undefined {
  if (providerId === "spiderfoot_deep") {
    return undefined;
  }
  const normalizedCompany = companyName.trim().toLowerCase();
  for (const job of Array.from(jobs.values())) {
    if (job.provider_id !== providerId) continue;
    if (job.company_name.trim().toLowerCase() !== normalizedCompany) continue;
    if (job.status !== "running") continue;
    return job;
  }
  return undefined;
}
const DEEP_EVENT_TYPES = [
  "EMAILADDR",
  "EMAILADDR_GENERIC",
  "EMAILADDR_COMPROMISED",
  "PASSWORD_COMPROMISED",
  "HASH_COMPROMISED",
  "LEAKSITE_URL",
  "LEAKSITE_CONTENT",
  "MALICIOUS_EMAILADDR",
  "INTERNET_NAME",
  "DOMAIN_NAME",
  "SOCIAL_MEDIA",
  "LINKED_URL_EXTERNAL",
  "URL_STATIC",
  "WEBSERVER_HTTPHEADERS",
  "IP_ADDRESS",
  "AFFILIATE_INTERNET_NAME",
  "AFFILIATE_DOMAIN_NAME",
  "USERNAME",
  "ACCOUNT_EXTERNAL_OWNED_COMPROMISED",
  "ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED",
].join(",");

const DEEP_MODULE_LIST = [
  "sfp_accounts",
  "sfp_socialprofiles",
  "sfp_hunter",
  "sfp_skymem",
  "sfp_emailformat",
  "sfp_haveibeenpwned",
  "sfp_dehashed",
].join(",");

function nowIso(): string {
  return new Date().toISOString();
}

function nowMs(): number {
  return Date.now();
}

function refreshElapsed(job: SpiderfootJob): void {
  job.updated_at = nowIso();
  job.elapsed_ms = nowMs() - Date.parse(job.started_at);
  job.provider_result.duration_ms = job.elapsed_ms;
}

function makeEmptyProviderResult(note: string): SpiderfootProviderResult {
  return {
    status: "running",
    notes: [note],
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

function trimLogs(lines: string[]): string[] {
  return lines.slice(-200);
}

function normalizeTargetDomain(target: string): string {
  const lowered = target.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  if (lowered.includes(" ") || !lowered.includes(".")) {
    return "";
  }
  return lowered;
}

function uniqStrings(values: string[]): string[] {
  return Array.from(new Set(values));
}

function classifySpiderfootEmailModule(moduleName: string): SpiderfootEmailSource["module_type"] {
  const normalized = moduleName.trim().toLowerCase();
  if (["sfp_hunter", "sfp_haveibeenpwned", "sfp_dehashed"].includes(normalized)) {
    return "api";
  }
  if (["sfp_skymem", "sfp_emailformat"].includes(normalized)) {
    return "public";
  }
  return "unknown";
}

function mergeUniqueByKey<T>(current: T[], incoming: T[], keyFn: (value: T) => string): T[] {
  const next = new Map<string, T>();
  for (const value of current) next.set(keyFn(value), value);
  for (const value of incoming) next.set(keyFn(value), value);
  return Array.from(next.values());
}

function hasFindings(provider: SpiderfootProviderResult): boolean {
  return provider.emails.length > 0
    || provider.subdomains.length > 0
    || Object.keys(provider.social_profiles).length > 0
    || provider.hosting.length > 0
    || provider.mentions.length > 0;
}

function socialProfileFromUrl(value: string): [string, { url: string; status: string; source?: string }] | null {
  const normalized = value.trim().replace(/\/+$/, "");
  const patterns: Array<[string, RegExp]> = [
    ["LinkedIn", /^https?:\/\/(?:www\.)?linkedin\.com\/company\/[\w-]+/i],
    ["Twitter/X", /^https?:\/\/(?:www\.)?(?:twitter\.com|x\.com)\/[\w.]+/i],
    ["GitHub", /^https?:\/\/(?:www\.)?github\.com\/[\w-]+/i],
    ["Facebook", /^https?:\/\/(?:www\.)?facebook\.com\/[\w.-]+/i],
    ["Instagram", /^https?:\/\/(?:www\.)?instagram\.com\/[\w.]+/i],
    ["YouTube", /^https?:\/\/(?:www\.)?youtube\.com\/(?:@|c\/|user\/|channel\/)[\w-]+/i],
    ["TikTok", /^https?:\/\/(?:www\.)?tiktok\.com\/@[\w.]+/i],
    ["Reddit", /^https?:\/\/(?:www\.)?reddit\.com\/r\/[\w_]+/i],
    ["Bluesky", /^https?:\/\/(?:www\.)?bsky\.app\/profile\/[\w.-]+/i],
  ];

  for (const [platform, pattern] of patterns) {
    if (pattern.test(normalized)) {
      return [platform, { url: normalized, status: "found", source: "spiderfoot" }];
    }
  }
  return null;
}

function decodeSpiderfootValue(value: string): string {
  return value
    .replace(/\\n/g, " ")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&amp;/gi, "&")
    .trim();
}

function extractSpiderfootUrl(value: string): string | null {
  const decoded = decodeSpiderfootValue(value);
  const sfurlMatch = decoded.match(/<SFURL>(https?:\/\/[^<\s]+)<\/SFURL>/i);
  if (sfurlMatch?.[1]) {
    return sfurlMatch[1].trim().replace(/\/+$/, "");
  }

  const plainUrlMatch = decoded.match(/https?:\/\/[^\s<>"']+/i);
  if (plainUrlMatch?.[0]) {
    return plainUrlMatch[0].trim().replace(/\/+$/, "");
  }

  return null;
}

function parseProfileCandidate(value: string): {
  platform?: string;
  username?: string;
  url: string;
} | null {
  const url = extractSpiderfootUrl(value);
  if (!url) return null;
  const decoded = decodeSpiderfootValue(value);

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const host = parsed.hostname.toLowerCase();
  const pathParts = parsed.pathname.split("/").filter(Boolean);

  if ((host === "hub.docker.com" || host === "www.hub.docker.com") && pathParts[0] === "u" && pathParts[1]) {
    return {
      platform: "Docker Hub",
      username: pathParts[1],
      url,
    };
  }

  if ((host === "github.com" || host === "www.github.com") && pathParts[0]) {
    return {
      platform: "GitHub",
      username: pathParts[0],
      url,
    };
  }

  if ((host === "linkedin.com" || host === "www.linkedin.com") && pathParts[0] === "company" && pathParts[1]) {
    return {
      platform: "LinkedIn",
      username: pathParts[1],
      url,
    };
  }

  if ((host === "x.com" || host === "twitter.com" || host === "www.x.com" || host === "www.twitter.com") && pathParts[0]) {
    return {
      platform: "Twitter/X",
      username: pathParts[0].replace(/^@/, ""),
      url,
    };
  }

  if ((host === "instagram.com" || host === "www.instagram.com") && pathParts[0]) {
    return {
      platform: "Instagram",
      username: pathParts[0].replace(/^@/, ""),
      url,
    };
  }

  if ((host === "facebook.com" || host === "www.facebook.com") && pathParts[0]) {
    return {
      platform: "Facebook",
      username: pathParts[0],
      url,
    };
  }

  if ((host === "youtube.com" || host === "www.youtube.com") && pathParts[0] && ["@", "c", "user", "channel"].some((prefix) => pathParts[0].startsWith(prefix) || pathParts[0] === prefix)) {
    const username = pathParts[0].startsWith("@") ? pathParts[0].slice(1) : pathParts[1];
    if (username) {
      return {
        platform: "YouTube",
        username,
        url,
      };
    }
  }

  if ((host === "tiktok.com" || host === "www.tiktok.com") && pathParts[0]?.startsWith("@")) {
    return {
      platform: "TikTok",
      username: pathParts[0].slice(1),
      url,
    };
  }

  const labelMatch = decoded.match(/^([^<(]+?)(?:\s*\(.*?\))?\s*<SFURL>/i);
  const labelPlatform = labelMatch?.[1]?.trim();
  const username = pathParts[pathParts.length - 1];
  if (labelPlatform && username) {
    return {
      platform: labelPlatform,
      username: username.replace(/^@/, ""),
      url,
    };
  }

  return null;
}

function classifyMention(url: string, domain: string): Record<string, unknown> {
  let sourceDomain = "";
  try {
    sourceDomain = new URL(url).hostname.toLowerCase();
  } catch {
    sourceDomain = "";
  }
  return {
    category: "reference",
    title: url,
    url,
    snippet: "SpiderFoot",
    source_domain: sourceDomain,
    matched_domain: domain,
    query: domain || url,
  };
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function targetDomainEmailPattern(job: SpiderfootJob): RegExp | null {
  if (!job.target_domain) return null;
  return new RegExp(`[a-z0-9._%+-]+@${escapeRegExp(job.target_domain)}`, "i");
}

function brandTokens(job: SpiderfootJob): string[] {
  const sources = [job.target_domain, job.company_name]
    .map((value) => value.toLowerCase())
    .flatMap((value) => value.split(/[^a-z0-9]+/))
    .filter((token) => token.length >= 4);
  return Array.from(new Set(sources));
}

function looksLikeMeaningfulAffiliateDomain(job: SpiderfootJob, value: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (normalized.includes("/") || normalized.includes(" ")) return false;
  if (!/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(normalized)) return false;
  if (job.target_domain && normalized.endsWith(job.target_domain)) return false;
  return brandTokens(job).some((token) => normalized.includes(token));
}

function addProgressLogs(job: SpiderfootJob, rows: unknown): void {
  if (!Array.isArray(rows)) return;
  const nextLogs: string[] = [];
  let lastRowId = job.last_log_row_id;
  for (const row of rows) {
    if (!Array.isArray(row)) continue;
    const rowId = Number(row[4]);
    if (Number.isFinite(rowId) && rowId <= lastRowId) {
      continue;
    }
    if (Number.isFinite(rowId)) {
      lastRowId = rowId;
    }
    const message = [row[1], row[3]].filter(Boolean).join(": ").trim();
    if (message) {
      nextLogs.push(message);
    }
  }
  if (nextLogs.length > 0) {
    job.last_log_row_id = lastRowId;
    job.progress_logs = trimLogs([...job.progress_logs, ...nextLogs]);
    job.provider_result.progress_logs = job.progress_logs;
  }
}

function addUniqueString(values: string[], value: string): string[] {
  return uniqStrings([...values, value]);
}

function addHosting(provider: SpiderfootProviderResult, value: string, type: string): void {
  provider.hosting = mergeUniqueByKey(
    provider.hosting,
    [{ value, type }],
    (item) => `${item.type}:${item.value.toLowerCase()}`,
  );
}

function addMention(provider: SpiderfootProviderResult, mention: Record<string, unknown>): void {
  provider.mentions = mergeUniqueByKey(
    provider.mentions,
    [mention],
    (item) => JSON.stringify(item),
  );
}

function addBreachHint(provider: SpiderfootProviderResult, hint: unknown): void {
  provider.breach_hints = mergeUniqueByKey(
    provider.breach_hints,
    [hint],
    (item) => typeof item === "string" ? item : JSON.stringify(item),
  );
}

function addImpersonationCandidate(provider: SpiderfootProviderResult, candidate: Record<string, unknown>): void {
  provider.impersonation_candidates = mergeUniqueByKey(
    provider.impersonation_candidates,
    [candidate],
    (item) => JSON.stringify(item),
  );
}

function normalizeStoredImpersonationCandidate(candidate: unknown): Record<string, unknown> | null {
  if (!candidate || typeof candidate !== "object") return null;
  const record = candidate as Record<string, unknown>;
  if (typeof record.url === "string" && record.url.startsWith("http")) {
    return record;
  }

  const parsed = typeof record.username === "string"
    ? parseProfileCandidate(record.username)
    : null;
  if (!parsed) return null;

  return {
    platform: parsed.platform,
    username: parsed.username,
    url: parsed.url,
    reason: typeof record.reason === "string" ? record.reason : "SpiderFoot deep account candidate",
    source: typeof record.source === "string" ? record.source : "spiderfoot_deep",
  };
}

function normalizeStoredImpersonationCandidates(provider: SpiderfootProviderResult): void {
  provider.impersonation_candidates = provider.impersonation_candidates
    .map((candidate) => normalizeStoredImpersonationCandidate(candidate))
    .filter((candidate): candidate is Record<string, unknown> => Boolean(candidate));
}

function maybeAddDeepImpersonationCandidate(job: SpiderfootJob, eventType: string, value: string): void {
  if (job.provider_id !== "spiderfoot_deep") return;

  if (eventType === "USERNAME" || eventType.startsWith("ACCOUNT_EXTERNAL_")) {
    const candidate = parseProfileCandidate(value);
    if (!candidate) return;
    addImpersonationCandidate(job.provider_result, {
      platform: candidate.platform,
      username: candidate.username,
      url: candidate.url,
      reason: "SpiderFoot deep account candidate",
      source: "spiderfoot_deep",
    });
  }
}

function getSpiderfootScanConfig(providerId: SpiderfootProviderId): {
  typelist: string;
  usecase: string;
  modulelist: string;
} {
  if (providerId === "spiderfoot_deep") {
    return {
      typelist: DEEP_EVENT_TYPES,
      usecase: "all",
      modulelist: DEEP_MODULE_LIST,
    };
  }

  return {
    typelist: PASSIVE_EVENT_TYPES,
    usecase: "passive",
    modulelist: "",
  };
}

function getSpiderfootModuleOptions(providerId: SpiderfootProviderId, env: NodeJS.ProcessEnv): SpiderfootModuleOption[] {
  if (providerId !== "spiderfoot_deep") {
    return [];
  }

  const options: SpiderfootModuleOption[] = [];
  const hunterKey = env.Hunter_API_KEY || env.HunterIO_API_KEY;
  if (hunterKey) {
    options.push({ mod: "sfp_hunter", opt: "api_key", val: hunterKey });
  }

  const hibpKey = env.HaveIBeenPwned_API_KEY;
  if (hibpKey) {
    options.push({ mod: "sfp_haveibeenpwned", opt: "api_key", val: hibpKey });
  }

  return options;
}

async function applySpiderfootModuleOptions(
  transport: SpiderfootTransport,
  moduleOptions: SpiderfootModuleOption[],
): Promise<void> {
  if (moduleOptions.length === 0) {
    return;
  }

  const payload = await transport.getJson("/optsraw");
  if (!Array.isArray(payload) || payload[0] !== "SUCCESS" || !payload[1] || typeof payload[1] !== "object") {
    throw new Error(`SpiderFoot optsraw failed: ${JSON.stringify(payload)}`);
  }

  const token = typeof (payload[1] as Record<string, unknown>).token === "string"
    ? (payload[1] as Record<string, unknown>).token
    : "";
  if (!token) {
    throw new Error("SpiderFoot optsraw did not return a token");
  }

  for (const option of moduleOptions) {
    const savePayload = await transport.postJson("/savesettingsraw", {
      allopts: JSON.stringify({
        [`module.${option.mod}.${option.opt}`]: option.val,
      }),
      token,
    });
    if (!Array.isArray(savePayload) || savePayload[0] !== "SUCCESS") {
      throw new Error(`SpiderFoot savesettingsraw failed: ${JSON.stringify(savePayload)}`);
    }
  }
}

function mergeEventRows(job: SpiderfootJob, rows: unknown): void {
  if (!Array.isArray(rows)) return;
  for (const row of rows) {
    if (!Array.isArray(row)) continue;
    const eventType = String(row[10] ?? "").toUpperCase();
    const value = String(row[1] ?? "").trim();
    const sourceValue = String(row[2] ?? "").trim();
    const moduleValue = String(row[3] ?? "").trim();
    const eventId = String(row[7] ?? `${eventType}:${value}:${sourceValue}`);
    if (job.seen_event_ids.has(eventId)) {
      continue;
    }
    job.seen_event_ids.add(eventId);

    if (!value) continue;
    const lowered = value.toLowerCase();

    if ((eventType === "EMAILADDR" || eventType === "EMAILADDR_GENERIC")
      && (!job.target_domain || lowered.endsWith(`@${job.target_domain}`))) {
      job.provider_result.emails = addUniqueString(job.provider_result.emails, lowered);
      const moduleType = classifySpiderfootEmailModule(moduleValue);
      job.provider_result.email_sources = mergeUniqueByKey(
        job.provider_result.email_sources,
        [{
          email: lowered,
          module: moduleValue || "unknown",
          module_type: moduleType,
          event_type: eventType,
          source: sourceValue,
          api_backed: moduleType === "api",
        }],
        (entry) => JSON.stringify([entry.email, entry.module, entry.event_type, entry.source]),
      );
      continue;
    }

    if (["EMAILADDR_COMPROMISED", "PASSWORD_COMPROMISED", "HASH_COMPROMISED", "LEAKSITE_URL", "LEAKSITE_CONTENT", "MALICIOUS_EMAILADDR"].includes(eventType)) {
      const emailEvidence = targetDomainEmailPattern(job);
      if (job.provider_id !== "spiderfoot_deep" || (emailEvidence && emailEvidence.test(value))) {
        addBreachHint(job.provider_result, {
          type: eventType,
          value,
          source: sourceValue,
        });
      }
      continue;
    }

    if ((eventType === "INTERNET_NAME" || eventType === "DOMAIN_NAME")
      && job.target_domain
      && lowered.endsWith(job.target_domain)
      && lowered !== job.target_domain) {
      job.provider_result.subdomains = addUniqueString(job.provider_result.subdomains, lowered);
      continue;
    }

    if (["SOCIAL_MEDIA", "LINKED_URL_EXTERNAL", "URL_STATIC", "WEBSERVER_HTTPHEADERS"].includes(eventType)) {
      const social = socialProfileFromUrl(value);
      if (social) {
        job.provider_result.social_profiles[social[0]] = social[1];
        maybeAddDeepImpersonationCandidate(job, eventType, value);
      } else if (/^https?:\/\//i.test(value)) {
        addMention(job.provider_result, classifyMention(value, job.target_domain));
      }
      continue;
    }

    if (eventType === "IP_ADDRESS" || eventType === "AFFILIATE_INTERNET_NAME") {
      addHosting(job.provider_result, value, eventType);
      maybeAddDeepImpersonationCandidate(job, eventType, value);
      continue;
    }

    maybeAddDeepImpersonationCandidate(job, eventType, value);
  }
}

function buildSpiderfootPartialReport(providerId: SpiderfootProviderId, provider: SpiderfootProviderResult): Record<string, unknown> {
  normalizeStoredImpersonationCandidates(provider);
  return {
    identities: {
      emails: provider.emails,
      email_sources: provider.email_sources,
      social_profiles: provider.social_profiles,
      impersonation_candidates: provider.impersonation_candidates,
    },
    dns: {
      subdomains: provider.subdomains.map((subdomain) => ({ subdomain, type: "SpiderFoot" })),
    },
    provider_results: {
      [providerId]: provider,
    },
  };
}

function finalizeJobState(job: SpiderfootJob, scanState: string): void {
  if (scanState === "FINISHED") {
    job.status = "completed";
    job.provider_result.status = hasFindings(job.provider_result) ? "ok" : "partial";
    job.provider_result.notes = hasFindings(job.provider_result)
      ? ["SpiderFoot scan completed"]
      : ["SpiderFoot scan completed without exact findings"];
    job.report = buildSpiderfootPartialReport(job.provider_id, job.provider_result);
    clearPollTimer(job.job_id);
    return;
  }

  if (scanState === "ABORTED" || scanState === "ERROR-FAILED") {
    job.status = "error";
    job.provider_result.status = "error";
    job.provider_result.notes = [`SpiderFoot scan ended with state ${scanState}`];
    job.error = `SpiderFoot scan ended with state ${scanState}`;
    job.report = buildSpiderfootPartialReport(job.provider_id, job.provider_result);
    clearPollTimer(job.job_id);
    return;
  }

  job.status = "running";
  job.provider_result.status = "running";
  job.provider_result.notes = ["SpiderFoot is running in the background"];
  job.report = buildSpiderfootPartialReport(job.provider_id, job.provider_result);
}

function buildQuery(params?: Record<string, unknown>): string {
  if (!params) return "";
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
}

function createHttpTransport(baseUrl: string): SpiderfootTransport {
  return {
    async postJson(requestPath, params = {}) {
      const body = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) {
        if (value === undefined || value === null) continue;
        body.set(key, String(value));
      }
      const response = await fetch(`${baseUrl}${requestPath}`, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body,
      });
      if (!response.ok) {
        throw new Error(`SpiderFoot API ${requestPath} failed with ${response.status}`);
      }
      return response.json();
    },
    async getJson(requestPath, params = {}) {
      const response = await fetch(`${baseUrl}${requestPath}${buildQuery(params)}`, {
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`SpiderFoot API ${requestPath} failed with ${response.status}`);
      }
      return response.json();
    },
  };
}

function spiderfootScanName(companyName: string, providerId: SpiderfootProviderId): string {
  return providerId === "spiderfoot_deep" ? `${companyName} [Deep]` : companyName;
}

function findReusableScanId(
  scanListPayload: unknown,
  companyName: string,
  targetDomain: string,
  providerId: SpiderfootProviderId,
): string | null {
  if (providerId === "spiderfoot_deep") {
    return null;
  }
  if (!Array.isArray(scanListPayload)) return null;
  const normalizedCompany = spiderfootScanName(companyName, providerId).trim().toLowerCase();
  const normalizedTarget = targetDomain.trim().toLowerCase();

  for (const entry of scanListPayload) {
    if (!Array.isArray(entry)) continue;
    const scanId = typeof entry[0] === "string" ? entry[0] : "";
    const scanName = String(entry[1] ?? "").trim().toLowerCase();
    const scanTarget = String(entry[2] ?? "").trim().toLowerCase();
    const status = String(entry[6] ?? "").trim().toUpperCase();
    if (!scanId) continue;
    if (!["RUNNING", "STARTING"].includes(status)) continue;
    if (scanName === normalizedCompany) return scanId;
    if (providerId === "spiderfoot" && normalizedTarget && scanTarget === normalizedTarget) return scanId;
  }

  return null;
}

async function isSpiderfootReady(baseUrl: string): Promise<boolean> {
  try {
    const response = await fetch(`${baseUrl}/scanlist`, { headers: { Accept: "application/json" } });
    return response.ok;
  } catch {
    return false;
  }
}

async function waitForSpiderfootReady(baseUrl: string, timeoutMs: number): Promise<void> {
  const deadline = nowMs() + timeoutMs;
  while (nowMs() < deadline) {
    if (await isSpiderfootReady(baseUrl)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("SpiderFoot web service did not become ready in time");
}

function resolveSpiderfootBaseUrl(env: NodeJS.ProcessEnv): string {
  if (env.SPIDERFOOT_API_BASE_URL) {
    return env.SPIDERFOOT_API_BASE_URL.replace(/\/+$/, "");
  }
  const port = Number(env.SPIDERFOOT_API_PORT || DEFAULT_SERVICE_PORT);
  return `http://127.0.0.1:${Number.isFinite(port) ? port : DEFAULT_SERVICE_PORT}`;
}

async function startSpiderfootService(cwd: string, env: NodeJS.ProcessEnv): Promise<void> {
  const baseUrl = resolveSpiderfootBaseUrl(env);
  spiderfootService.baseUrl = baseUrl;
  if (await isSpiderfootReady(baseUrl)) {
    return;
  }
  if (spiderfootService.startPromise) {
    return spiderfootService.startPromise;
  }

  spiderfootService.startPromise = (async () => {
    const repoRoot = cwd;
    const pythonCommand = resolvePythonCommand({ cwd: repoRoot, env, fileExists: fs.existsSync, platform: process.platform });
    const scriptPath = path.resolve(repoRoot, "tools", "spiderfoot", "sf.py");
    const port = new URL(baseUrl).port || String(DEFAULT_SERVICE_PORT);
    const host = new URL(baseUrl).hostname || "127.0.0.1";
    const child = spawn(pythonCommand, [scriptPath, "-l", `${host}:${port}`], {
      cwd: path.dirname(scriptPath),
      env: {
        ...env,
        PYTHONUNBUFFERED: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    spiderfootService.process = child;
    child.once("exit", () => {
      spiderfootService.process = null;
      spiderfootService.startPromise = null;
    });
    await waitForSpiderfootReady(baseUrl, Number(env.SPIDERFOOT_API_STARTUP_TIMEOUT_MS || 60000));
  })();

  try {
    await spiderfootService.startPromise;
  } finally {
    spiderfootService.startPromise = null;
  }
}

function clearPollTimer(jobId: string): void {
  const timer = pollTimers.get(jobId);
  if (timer) {
    clearTimeout(timer);
    pollTimers.delete(jobId);
  }
}

function schedulePoll(jobId: string, env: NodeJS.ProcessEnv): void {
  clearPollTimer(jobId);
  const timer = setTimeout(async () => {
    try {
      await pollSpiderfootJob(jobId, { env });
    } catch {
      // keep the last known state visible in the UI
    }
  }, Number(env.SPIDERFOOT_POLL_INTERVAL_MS || DEFAULT_POLL_INTERVAL_MS));
  timer.unref();
  pollTimers.set(jobId, timer);
}

export function createRunningSpiderfootProviderResult(): SpiderfootProviderResult {
  return makeEmptyProviderResult("SpiderFoot is running in the background");
}

export async function startSpiderfootJob({
  companyName,
  providerId,
  cwd = process.cwd(),
  env = process.env,
  transport,
  ensureService,
  schedulePolling = true,
}: StartSpiderfootJobOptions): Promise<SpiderfootJob> {
  const existingJob = findReusableJob(companyName, providerId);
  if (existingJob) {
    refreshElapsed(existingJob);
    return existingJob;
  }

  const ensure = ensureService || (() => startSpiderfootService(cwd, env));
  await ensure();

  const effectiveTransport = transport || createHttpTransport(spiderfootService.baseUrl || resolveSpiderfootBaseUrl(env));
  const targetDomain = normalizeTargetDomain(companyName);
  const scanTarget = targetDomain || companyName;
  const startedAt = nowIso();
  const scanConfig = getSpiderfootScanConfig(providerId);
  const moduleOptions = getSpiderfootModuleOptions(providerId, env);
  const existingScans = await effectiveTransport.getJson("/scanlist");
  const reusableScanId = findReusableScanId(existingScans, companyName, targetDomain, providerId);
  const scanId = reusableScanId || await (async () => {
    await applySpiderfootModuleOptions(effectiveTransport, moduleOptions);
    const startPayload = await effectiveTransport.postJson("/startscan", {
      scanname: spiderfootScanName(companyName, providerId),
      scantarget: scanTarget,
      modulelist: scanConfig.modulelist,
      typelist: scanConfig.typelist,
      usecase: scanConfig.usecase,
    });

    if (!Array.isArray(startPayload) || startPayload[0] !== "SUCCESS" || typeof startPayload[1] !== "string") {
      throw new Error(`SpiderFoot scan failed to start: ${JSON.stringify(startPayload)}`);
    }

    return startPayload[1];
  })();

  const job: SpiderfootJob = {
    job_id: randomUUID(),
    provider_id: providerId,
    scan_id: scanId,
    company_name: companyName,
    target_domain: targetDomain,
    status: "running",
    started_at: startedAt,
    updated_at: startedAt,
    elapsed_ms: 0,
    progress_logs: [],
    provider_result: createRunningSpiderfootProviderResult(),
    report: buildSpiderfootPartialReport(providerId, createRunningSpiderfootProviderResult()),
    last_log_row_id: 0,
    seen_event_ids: new Set<string>(),
  };

  jobs.set(job.job_id, job);
  if (schedulePolling) {
    schedulePoll(job.job_id, env);
  }
  return job;
}

export async function pollSpiderfootJob(jobId: string, { transport, env = process.env }: PollSpiderfootJobOptions = {}): Promise<SpiderfootJob | undefined> {
  const job = jobs.get(jobId);
  if (!job) return undefined;

  const effectiveTransport = transport || createHttpTransport(spiderfootService.baseUrl || resolveSpiderfootBaseUrl(env));
  try {
    const [scanStatus, scanLog, scanEvents] = await Promise.all([
      effectiveTransport.getJson("/scanstatus", { id: job.scan_id }),
      effectiveTransport.getJson("/scanlog", { id: job.scan_id }),
      effectiveTransport.getJson("/scaneventresults", { id: job.scan_id }),
    ]);

    addProgressLogs(job, scanLog);
    mergeEventRows(job, scanEvents);
    normalizeStoredImpersonationCandidates(job.provider_result);

    const scanState = Array.isArray(scanStatus) ? String(scanStatus[5] || "RUNNING") : "RUNNING";
    finalizeJobState(job, scanState);
    refreshElapsed(job);
  } catch (error) {
    job.status = "error";
    job.provider_result.status = "error";
    job.error = error instanceof Error ? error.message : String(error);
    job.provider_result.notes = [`SpiderFoot polling failed: ${job.error}`];
    job.report = buildSpiderfootPartialReport(job.provider_id, job.provider_result);
    refreshElapsed(job);
    clearPollTimer(job.job_id);
    return job;
  }

  if (job.status === "running") {
    schedulePoll(job.job_id, env);
  }

  return job;
}

export function getSpiderfootJob(jobId: string): SpiderfootJob | undefined {
  const job = jobs.get(jobId);
  if (!job) return undefined;
  normalizeStoredImpersonationCandidates(job.provider_result);
  refreshElapsed(job);
  return job;
}
