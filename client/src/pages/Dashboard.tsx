import { useState, useRef, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  getDefaultSelectedProviderIds,
  getSelectableProviderIds,
  osintProviders,
  type OsintProvider,
} from "@shared/osint-providers";
import {
  Globe, Shield, Server, Mail, AlertTriangle, Database,
  ChevronRight, Wifi, Lock, Unlock, ExternalLink, Copy,
  CheckCircle, XCircle, AlertCircle, Activity, Search,
  Terminal, Eye, Zap, Code, Users, Key, Network, FileText
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────

interface ReconData {
  meta: { company: string; generated_at: string; version: string; selected_sources?: string[] };
  timings?: ReconTimings;
  spiderfoot_job?: SpiderfootJob;
  website: { company: string; domain: string; url: string; found_via: string };
  dns: DnsData;
  whois: WhoisData;
  ssl: SslData;
  hosting: HostingData;
  technologies: TechData;
  identities: IdentityData;
  breaches: BreachData;
  provider_results: Record<string, ProviderResult>;
  errors: string[];
}

interface DnsData {
  domain: string;
  records: Record<string, string[]>;
  subdomains: Subdomain[];
  nameservers: string[];
  mx_records: { priority: number; host: string }[];
  txt_records: string[];
  spf: string | null;
  dmarc: string | null;
  ct_log_count?: number;
}

interface Subdomain {
  subdomain: string;
  ips?: string[];
  cname?: string[];
  source?: string;
  type: string;
}

interface WhoisData {
  domain: string;
  registrar: string | null;
  registered: string | null;
  expires: string | null;
  updated: string | null;
  org: string | null;
  country: string | null;
  status: string[];
  nameservers: string[];
  error?: string;
}

interface SslData {
  domain: string;
  valid: boolean;
  subject: Record<string, string> | null;
  issuer: Record<string, string> | null;
  issuer_cn: string;
  san: string[];
  not_before: string | null;
  not_after: string | null;
  days_remaining: number | null;
  version: string | null;
  serial: string | null;
  extended_validation: boolean;
  wildcard: boolean;
  ct_entries?: number;
  error?: string;
}

interface HostingData {
  domain: string;
  ipv4: string[];
  ipv6: string[];
  reverse_dns: string[];
  asn: string | null;
  asn_description: string | null;
  isp: string | null;
  country: string | null;
  cloud_provider: string | null;
  cdn: string | null;
  open_ports: number[];
}

interface TechData {
  url: string;
  server: string | null;
  powered_by: string | null;
  technologies: { name: string; category: string }[];
  cms: string | null;
  analytics: string[];
  security_headers: Record<string, { present: boolean; value: string | null }>;
  cookies: { name: string; secure: boolean; httponly: boolean; samesite: string | null; domain: string }[];
  headers: Record<string, string>;
}

interface IdentityData {
  domain: string;
  emails: string[];
  email_format: string | null;
  github_repos: { name: string; url: string; stars: number; description: string }[];
  social_profiles: Record<string, { url: string; status: string; source?: string }>;
  impersonation_candidates?: Array<{
    platform?: string;
    username?: string;
    url?: string;
    matched_candidate?: string;
    reason?: string;
    source?: string;
  }>;
  breaches: unknown[];
  provider_results?: Record<string, ProviderResult>;
}

function sourceLabel(source?: string) {
  if (!source) return "unknown";
  if (source.startsWith("slug:")) return "social_probe";
  return source;
}

interface ProviderResult {
  status: "ok" | "partial" | "skipped" | "error" | "running";
  notes: string[];
  duration_ms?: number | null;
  progress_logs?: string[];
  emails?: string[];
  mentions?: Array<{
    category?: string;
    title?: string;
    url?: string;
    snippet?: string;
    source_domain?: string;
    matched_domain?: string;
    query?: string;
  }>;
  social_profiles?: Record<string, { url: string; status: string; source?: string }> | Array<Record<string, unknown>>;
  subdomains?: string[];
  repos?: Array<Record<string, unknown>>;
  breach_hints?: Array<Record<string, unknown> | string>;
  dns_records?: Array<Record<string, unknown> | string>;
  whois?: Array<Record<string, unknown> | string>;
  ssl?: Array<Record<string, unknown> | string>;
  tech?: Array<Record<string, unknown> | string>;
  ports?: Array<Record<string, unknown> | string>;
  hosting?: Array<Record<string, unknown> | string>;
  impersonation_candidates?: Array<Record<string, unknown>>;
}

interface BreachData {
  domain: string;
  domain_breaches: unknown[];
  email_validation: { email: string; format_valid: boolean }[];
  dehashed_hint?: string;
}

interface ReconTimings {
  total_ms: number;
  stages: Record<string, number>;
  providers?: Record<string, number>;
}

interface SpiderfootJob {
  job_id: string;
  provider_id?: "spiderfoot" | "spiderfoot_deep";
  scan_id?: string;
  status: "running" | "completed" | "error";
  started_at: string;
  updated_at?: string;
  elapsed_ms?: number;
  progress_logs?: string[];
  provider_result?: ProviderResult;
  report?: Partial<ReconData>;
  error?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────

const RISKY_PORTS = new Set([21, 23, 445, 3389, 5900, 27017, 6379]);
const WEB_PORTS = new Set([80, 443, 8080, 8443]);

function portClass(p: number) {
  if (RISKY_PORTS.has(p)) return "port-risky";
  if (WEB_PORTS.has(p)) return "port-web";
  return "port-normal";
}

function portLabel(p: number) {
  const labels: Record<number, string> = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "Postgres", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Alt",
    9200: "Elastic", 27017: "MongoDB",
  };
  return labels[p] || String(p);
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text).catch(() => {});
}

function formatDate(dateStr: string | null) {
  if (!dateStr) return "—";
  try {
    return new Date(dateStr).toLocaleDateString("en-GB", { year: "numeric", month: "short", day: "numeric" });
  } catch { return dateStr; }
}

function formatDuration(ms?: number | null) {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${ms}ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(seconds >= 10 ? 1 : 2)}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = Math.round(seconds % 60);
  return `${minutes}m ${remainder}s`;
}

function mergeUniqueStrings(current: string[], incoming: string[]) {
  return Array.from(new Set([...current, ...incoming]));
}

function mergeUniqueObjects<T>(current: T[], incoming: T[], keyFn: (value: T) => string) {
  const next = new Map<string, T>();
  for (const value of current) next.set(keyFn(value), value);
  for (const value of incoming) next.set(keyFn(value), value);
  return Array.from(next.values());
}

function mergeSpiderfootJobIntoResult(current: ReconData, job: SpiderfootJob): ReconData {
  const providerKey = job.provider_id || "spiderfoot";
  const next: ReconData = {
    ...current,
    spiderfoot_job: {
      ...(current.spiderfoot_job || { job_id: job.job_id, started_at: job.started_at, status: "running" as const }),
      ...job,
    },
    provider_results: {
      ...current.provider_results,
      [providerKey]: {
        ...(current.provider_results[providerKey] || { status: "running", notes: [], progress_logs: [] }),
        ...(job.provider_result || {}),
        notes: job.provider_result?.notes || current.provider_results[providerKey]?.notes || [],
        progress_logs: job.progress_logs || job.provider_result?.progress_logs || current.provider_results[providerKey]?.progress_logs || [],
      },
    },
  };

  if (next.timings) {
    next.timings = {
      ...next.timings,
      providers: {
        ...(next.timings.providers || {}),
        ...(job.provider_result?.duration_ms !== null && job.provider_result?.duration_ms !== undefined
          ? { [providerKey]: job.provider_result.duration_ms }
          : {}),
      },
    };
  }

  if (!job.report) {
    return next;
  }

  const report = job.report;
  const spiderfootSubdomains = (report.provider_results?.[providerKey]?.subdomains || []) as string[];
  const spiderfootEmails = (report.identities?.emails || []) as string[];
  const spiderfootSocialProfiles = (report.identities?.social_profiles || {}) as Record<string, { url: string; status: string; source?: string }>;
  const spiderfootImpersonation = (report.identities?.impersonation_candidates || []) as Array<Record<string, unknown>>;

  next.identities = {
    ...next.identities,
    emails: mergeUniqueStrings(next.identities.emails, spiderfootEmails),
    social_profiles: {
      ...next.identities.social_profiles,
      ...spiderfootSocialProfiles,
    },
    impersonation_candidates: mergeUniqueObjects(
      next.identities.impersonation_candidates || [],
      spiderfootImpersonation,
      (value) => JSON.stringify(value),
    ),
  };

  next.dns = {
    ...next.dns,
    subdomains: mergeUniqueObjects(
      next.dns.subdomains,
      spiderfootSubdomains.map((subdomain) => ({ subdomain, type: "SpiderFoot" })),
      (value) => value.subdomain,
    ),
  };

  return next;
}

function RiskBadge({ level }: { level: "critical" | "high" | "medium" | "low" | "info" | "none" }) {
  const classes = {
    critical: "badge-open",
    high: "badge-open",
    medium: "badge-warn",
    low: "badge-info",
    info: "badge-info",
    none: "badge-secure",
  };
  const labels = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", none: "OK" };
  return (
    <span className={`${classes[level]} text-[0.65rem] font-mono font-semibold px-2 py-0.5 rounded uppercase tracking-wide`}>
      {labels[level]}
    </span>
  );
}

function providerStatusClass(status: OsintProvider["status"]) {
  return {
    active: "badge-secure",
    limited: "badge-info",
    needs_api_key: "badge-warn",
    planned: "badge-neutral",
  }[status];
}

function providerStatusLabel(status: OsintProvider["status"]) {
  return {
    active: "Available Now",
    limited: "Limited",
    needs_api_key: "Needs API Key",
    planned: "Planned",
  }[status];
}

function providerReliabilityLabel(reliability: OsintProvider["reliability"]) {
  return {
    stable: "Stable",
    medium: "Medium",
    fragile: "Fragile",
  }[reliability];
}

function evidenceLabel(evidence: string) {
  return {
    websites: "Websites",
    subdomains: "Subdomains",
    dns: "DNS",
    whois: "WHOIS",
    ssl: "SSL",
    hosting: "Hosting",
    ports: "Ports",
    tech: "Tech",
    emails: "Emails",
    social: "Social",
    repos: "Repos",
    breaches: "Breaches",
    certificates: "Certs",
  }[evidence] || evidence;
}

function mentionSectionLabel(category: string) {
  return {
    forum: "Forums",
    news: "News / Articles",
    social: "Social Mentions",
    docs: "Documents",
    jobs: "Jobs",
    web: "Web Mentions",
    other: "Other Mentions",
  }[category] || "Mentions";
}

function isMentionValue(
  value: string | Record<string, unknown>,
): value is NonNullable<ProviderResult["mentions"]>[number] {
  if (typeof value === "string") return false;
  return "url" in value || "snippet" in value || "query" in value;
}

// ── Section Components ─────────────────────────────────────────────────────

function SectionTitle({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <div className="section-title mb-4">
      <Icon className="w-3.5 h-3.5 shrink-0" />
      <span>{label}</span>
    </div>
  );
}

function FieldRow({ label, value, mono = false, badge }: {
  label: string; value: React.ReactNode; mono?: boolean; badge?: React.ReactNode
}) {
  return (
    <div className="flex items-start gap-3 py-1.5 border-b border-[var(--color-border)] last:border-0 group">
      <span className="text-[var(--color-text-muted)] w-36 shrink-0 text-xs pt-0.5">{label}</span>
      <span className={`text-[var(--color-text)] text-sm flex-1 ${mono ? "font-mono text-xs" : ""}`}>
        {value || <span className="text-[var(--color-text-faint)]">—</span>}
      </span>
      {badge}
    </div>
  );
}

// ── Overview Card ──────────────────────────────────────────────────────────

function OverviewPanel({ data }: { data: ReconData }) {
  const { website, hosting, ssl, identities, dns } = data;
  const riskScore = (() => {
    let score = 0;
    if (hosting.open_ports.some((p) => RISKY_PORTS.has(p))) score += 30;
    if (!ssl.valid) score += 25;
    if ((ssl.days_remaining || 999) < 30) score += 15;
    if (identities.emails.length > 5) score += 10;
    if (!data.technologies.security_headers?.["HSTS"]?.present) score += 10;
    if (!data.technologies.security_headers?.["CSP"]?.present) score += 10;
    return Math.min(100, score);
  })();

  const riskLevel = riskScore >= 60 ? "critical" : riskScore >= 35 ? "high" : riskScore >= 20 ? "medium" : "low";

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
      {/* Target info */}
      <div className="terminal-card p-4 col-span-1 md:col-span-2">
        <div className="flex items-start justify-between mb-3">
          <div>
            <p className="text-[var(--color-text-muted)] text-xs font-mono uppercase tracking-widest mb-1">Target</p>
            <h2 className="text-xl font-semibold text-[var(--color-text)]">{data.meta.company}</h2>
            <a href={website.url} target="_blank" rel="noopener noreferrer"
              className="text-[var(--color-primary)] text-sm font-mono hover:underline flex items-center gap-1 mt-0.5">
              {website.domain} <ExternalLink className="w-3 h-3" />
            </a>
          </div>
          <div className="text-right">
            <p className="text-[var(--color-text-muted)] text-xs font-mono uppercase tracking-widest mb-1">Risk Score</p>
            <div className="text-3xl font-mono font-bold"
              style={{ color: riskScore >= 60 ? "var(--color-error)" : riskScore >= 35 ? "var(--color-warning)" : "var(--color-success)" }}>
              {riskScore}<span className="text-sm text-[var(--color-text-muted)]">/100</span>
            </div>
          </div>
        </div>
        <div className="progress-bar mt-2">
          <div className="progress-fill" style={{
            width: `${riskScore}%`,
            background: riskScore >= 60 ? "linear-gradient(90deg, hsl(0 65% 55%), hsl(0 65% 65%))"
              : riskScore >= 35 ? "linear-gradient(90deg, hsl(38 90% 50%), hsl(38 90% 60%))"
              : "linear-gradient(90deg, hsl(185 80% 55%), hsl(142 60% 55%))"
          }} />
        </div>
        <p className="text-[var(--color-text-muted)] text-xs mt-1.5 font-mono">
          Scanned: {new Date(data.meta.generated_at).toLocaleString()}
        </p>
        {data.timings && (
          <p className="text-[var(--color-text-faint)] text-xs mt-1 font-mono">
            Duration: {formatDuration(data.timings.total_ms)}
          </p>
        )}
        {data.meta.selected_sources && data.meta.selected_sources.length > 0 && (
          <p className="text-[var(--color-text-faint)] text-xs mt-1 font-mono">
            Providers selected: {data.meta.selected_sources.length}
          </p>
        )}
      </div>

      {/* Stats */}
      {[
        { label: "Subdomains", value: dns.subdomains.length, icon: Network, color: "var(--color-primary)" },
        { label: "Open Ports", value: hosting.open_ports.length, icon: Wifi, color: hosting.open_ports.some((p) => RISKY_PORTS.has(p)) ? "var(--color-error)" : "var(--color-success)" },
        { label: "Emails Found", value: identities.emails.length, icon: Mail, color: identities.emails.length > 0 ? "var(--color-warning)" : "var(--color-success)" },
        { label: "SSL Days Left", value: ssl.days_remaining ?? "—", icon: Lock, color: (ssl.days_remaining || 999) < 30 ? "var(--color-error)" : "var(--color-success)" },
      ].map(({ label, value, icon: Icon, color }) => (
        <div key={label} className="terminal-card p-4 flex flex-col justify-between glow-hover">
          <div className="flex items-center justify-between mb-2">
            <p className="text-[var(--color-text-muted)] text-xs font-mono uppercase tracking-widest">{label}</p>
            <Icon className="w-4 h-4" style={{ color }} />
          </div>
          <div className="text-3xl font-mono font-bold" style={{ color }}>{value}</div>
        </div>
      ))}
    </div>
  );
}

function TimingsPanel({ timings }: { timings?: ReconTimings }) {
  if (!timings) return null;

  const stageLabels: Record<string, string> = {
    website: "Website Discovery",
    dns: "DNS",
    whois: "WHOIS",
    ssl: "SSL",
    hosting: "Hosting",
    technologies: "Technologies",
    identities: "Identities",
    breaches: "Breaches",
  };

  const providerLabels = Object.fromEntries(osintProviders.map((provider) => [provider.id, provider.label]));
  const stageRows = Object.entries(timings.stages || {}).map(([id, duration]) => ({
    id,
    label: stageLabels[id] || id,
    duration,
  }));
  const providerRows = Object.entries(timings.providers || {}).map(([id, duration]) => ({
    id,
    label: providerLabels[id] || id,
    duration,
  }));

  return (
    <div className="terminal-card p-5 mb-6">
      <SectionTitle icon={Activity} label="Investigation Timings" />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div>
          <p className="text-[0.65rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-3">Stages</p>
          <div className="space-y-2">
            {stageRows.map((row) => (
              <div key={row.id} className="flex items-center justify-between border-b border-[var(--color-border)] pb-2 last:border-0 last:pb-0">
                <span className="text-sm text-[var(--color-text-muted)]">{row.label}</span>
                <span className="text-xs font-mono text-[var(--color-text)]">{formatDuration(row.duration)}</span>
              </div>
            ))}
          </div>
        </div>
        <div>
          <p className="text-[0.65rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-3">Providers</p>
          {providerRows.length === 0 ? (
            <p className="text-sm text-[var(--color-text-faint)] font-mono">No provider-specific timings captured.</p>
          ) : (
            <div className="space-y-2">
              {providerRows.map((row) => (
                <div key={row.id} className="flex items-center justify-between border-b border-[var(--color-border)] pb-2 last:border-0 last:pb-0">
                  <span className="text-sm text-[var(--color-text-muted)]">{row.label}</span>
                  <span className="text-xs font-mono text-[var(--color-text)]">{formatDuration(row.duration)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── DNS Panel ──────────────────────────────────────────────────────────────

function DnsPanel({ dns }: { dns: DnsData }) {
  const [showAll, setShowAll] = useState(false);
  const visible = showAll ? dns.subdomains : dns.subdomains.slice(0, 20);

  return (
    <div className="space-y-6">
      {/* DNS Records */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Database} label="DNS Records" />
        <div className="overflow-x-auto">
          <table className="data-table w-full">
            <thead>
              <tr><th>Type</th><th>Value</th></tr>
            </thead>
            <tbody>
              {Object.entries(dns.records).map(([type, vals]) =>
                vals.map((v, i) => (
                  <tr key={`${type}-${i}`}>
                    <td><span className="badge-info px-2 py-0.5 rounded text-[0.65rem] font-mono font-semibold">{type}</span></td>
                    <td className="font-mono text-xs text-[var(--color-text)] break-all">{v}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Email Security */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Mail} label="Email Security (SPF / DMARC)" />
        <div className="space-y-3">
          <FieldRow label="SPF" value={dns.spf} mono badge={dns.spf ? <RiskBadge level="none" /> : <RiskBadge level="high" />} />
          <FieldRow label="DMARC" value={dns.dmarc} mono badge={dns.dmarc ? <RiskBadge level="none" /> : <RiskBadge level="high" />} />
          <FieldRow label="Nameservers" value={dns.nameservers.join(", ")} mono />
          {dns.ct_log_count !== undefined && (
            <FieldRow label="CT Log Entries" value={`${dns.ct_log_count} certificate entries found`} mono />
          )}
        </div>
      </div>

      {/* MX Records */}
      {dns.mx_records.length > 0 && (
        <div className="terminal-card p-5">
          <SectionTitle icon={Mail} label="MX Records" />
          <table className="data-table w-full">
            <thead><tr><th>Priority</th><th>Host</th></tr></thead>
            <tbody>
              {dns.mx_records.map((mx, i) => (
                <tr key={i}>
                  <td className="text-[var(--color-text-muted)]">{mx.priority}</td>
                  <td className="font-mono">{mx.host}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Subdomains */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Globe} label={`Subdomains (${dns.subdomains.length} found)`} />
        {dns.subdomains.length === 0 ? (
          <p className="text-[var(--color-text-faint)] text-sm font-mono">No subdomains discovered</p>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="data-table w-full">
                <thead>
                  <tr><th>Subdomain</th><th>IPs / CNAME</th><th>Source</th></tr>
                </thead>
                <tbody>
                  {visible.map((sub, i) => (
                    <tr key={i}>
                      <td className="font-mono text-[var(--color-primary)]">{sub.subdomain}</td>
                      <td className="font-mono text-xs text-[var(--color-text-muted)]">
                        {sub.ips?.join(", ") || sub.cname?.join(", ") || "—"}
                      </td>
                      <td>
                        <span className={sub.source === "crt.sh" ? "badge-warn" : "badge-neutral"}
                          style={{ fontSize: "0.62rem", padding: "1px 6px", borderRadius: "4px" }}>
                          {sub.source || "brute"}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {dns.subdomains.length > 20 && (
              <button onClick={() => setShowAll(!showAll)}
                className="mt-3 text-xs text-[var(--color-primary)] font-mono hover:underline">
                {showAll ? "Show less" : `Show all ${dns.subdomains.length} subdomains`}
              </button>
            )}
          </>
        )}
      </div>

      {/* TXT Records */}
      {dns.txt_records.length > 0 && (
        <div className="terminal-card p-5">
          <SectionTitle icon={FileText} label="TXT Records" />
          <div className="space-y-1.5">
            {dns.txt_records.map((r, i) => (
              <div key={i} className="flex items-start gap-2 py-1 border-b border-[var(--color-border)] last:border-0">
                <ChevronRight className="w-3 h-3 text-[var(--color-text-faint)] mt-0.5 shrink-0" />
                <code className="text-xs text-[var(--color-text-muted)] break-all">{r}</code>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Endpoints Panel ────────────────────────────────────────────────────────

function EndpointsPanel({ hosting, ssl, whois, tech }: {
  hosting: HostingData; ssl: SslData; whois: WhoisData; tech: TechData
}) {
  return (
    <div className="space-y-6">
      {/* Hosting */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Server} label="Hosting & Infrastructure" />
        <div className="space-y-2">
          <FieldRow label="IPv4" value={hosting.ipv4.join(", ")} mono />
          {hosting.ipv6.length > 0 && <FieldRow label="IPv6" value={hosting.ipv6.join(", ")} mono />}
          <FieldRow label="Reverse DNS" value={hosting.reverse_dns.join(", ")} mono />
          <FieldRow label="ASN" value={hosting.asn ? `AS${hosting.asn} — ${hosting.asn_description}` : null} mono />
          <FieldRow label="ISP / Org" value={hosting.isp} mono />
          <FieldRow label="Country" value={hosting.country} />
          <FieldRow label="Cloud Provider" value={hosting.cloud_provider} badge={hosting.cloud_provider ? <RiskBadge level="info" /> : undefined} />
          <FieldRow label="CDN" value={hosting.cdn} />
        </div>
      </div>

      {/* Open Ports */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Wifi} label={`Open Ports (${hosting.open_ports.length} detected)`} />
        {hosting.open_ports.length === 0 ? (
          <p className="text-[var(--color-text-faint)] text-sm font-mono">No open ports detected in scan</p>
        ) : (
          <div className="flex flex-wrap gap-2 mt-1">
            {hosting.open_ports.map((p) => (
              <span key={p} className={`port-chip ${portClass(p)}`}>
                {p} <span className="ml-1 opacity-70">{portLabel(p)}</span>
                {RISKY_PORTS.has(p) && <AlertTriangle className="w-3 h-3 ml-1" />}
              </span>
            ))}
          </div>
        )}
        {hosting.open_ports.some((p) => RISKY_PORTS.has(p)) && (
          <div className="mt-3 flex items-start gap-2 p-3 rounded border border-[hsl(0_65%_55%/0.25)] bg-[hsl(0_65%_55%/0.08)]">
            <AlertTriangle className="w-4 h-4 text-[var(--color-error)] shrink-0 mt-0.5" />
            <p className="text-xs text-[var(--color-error)]">
              Potentially risky ports exposed: {hosting.open_ports.filter((p) => RISKY_PORTS.has(p)).map(portLabel).join(", ")}
            </p>
          </div>
        )}
      </div>

      {/* SSL Certificate */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Lock} label="SSL / TLS Certificate" />
        {ssl.error && !ssl.valid ? (
          <div className="flex items-center gap-2 text-[var(--color-error)] text-sm font-mono">
            <XCircle className="w-4 h-4" />{ssl.error}
          </div>
        ) : (
          <div className="space-y-2">
            <FieldRow label="Valid" value={ssl.valid ? "Yes" : "No"} badge={<RiskBadge level={ssl.valid ? "none" : "critical"} />} />
            <FieldRow label="Issuer" value={ssl.issuer_cn || ssl.issuer?.commonName} mono />
            <FieldRow label="Subject CN" value={ssl.subject?.commonName} mono />
            <FieldRow label="Not Before" value={formatDate(ssl.not_before)} mono />
            <FieldRow label="Expires" value={formatDate(ssl.not_after)}
              badge={<RiskBadge level={(ssl.days_remaining || 999) < 14 ? "critical" : (ssl.days_remaining || 999) < 30 ? "high" : "none"} />} />
            <FieldRow label="Days Left" value={ssl.days_remaining?.toString()} mono />
            <FieldRow label="Protocol" value={ssl.version} mono />
            <FieldRow label="Wildcard" value={ssl.wildcard ? "Yes" : "No"} badge={ssl.wildcard ? <RiskBadge level="low" /> : undefined} />
            <FieldRow label="EV Cert" value={ssl.extended_validation ? "Yes" : "No"} />
            <FieldRow label="Serial" value={ssl.serial} mono />
            {ssl.ct_entries !== undefined && <FieldRow label="CT Log Entries" value={`${ssl.ct_entries} historical certificates`} mono />}
          </div>
        )}
        {ssl.san.length > 0 && (
          <div className="mt-4">
            <p className="text-xs text-[var(--color-text-muted)] font-mono uppercase tracking-widest mb-2">SAN Entries ({ssl.san.length})</p>
            <div className="flex flex-wrap gap-1.5">
              {ssl.san.map((s, i) => (
                <span key={i} className="badge-neutral px-2 py-0.5 rounded text-xs font-mono">{s}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* WHOIS */}
      <div className="terminal-card p-5">
        <SectionTitle icon={FileText} label="WHOIS Registration" />
        {whois.error ? (
          <p className="text-[var(--color-text-faint)] text-sm font-mono">WHOIS lookup failed: {whois.error}</p>
        ) : (
          <div className="space-y-2">
            <FieldRow label="Registrar" value={whois.registrar} />
            <FieldRow label="Organization" value={whois.org} />
            <FieldRow label="Country" value={whois.country} />
            <FieldRow label="Registered" value={formatDate(whois.registered)} mono />
            <FieldRow label="Expires" value={formatDate(whois.expires)} mono />
            <FieldRow label="Updated" value={formatDate(whois.updated)} mono />
            {whois.nameservers.length > 0 && (
              <FieldRow label="Nameservers" value={whois.nameservers.slice(0, 4).join(", ")} mono />
            )}
            {whois.status.length > 0 && (
              <FieldRow label="Status" value={
                <div className="flex flex-wrap gap-1">
                  {whois.status.slice(0, 4).map((s, i) => (
                    <span key={i} className="badge-neutral px-2 py-0.5 rounded text-xs font-mono">{s.split(" ")[0]}</span>
                  ))}
                </div>
              } />
            )}
          </div>
        )}
      </div>

      {/* Security Headers */}
      {tech.security_headers && (
        <div className="terminal-card p-5">
          <SectionTitle icon={Shield} label="HTTP Security Headers" />
          <table className="data-table w-full">
            <thead><tr><th>Header</th><th>Present</th><th>Value</th></tr></thead>
            <tbody>
              {Object.entries(tech.security_headers).map(([name, info]) => (
                <tr key={name}>
                  <td className="font-mono text-xs">{name}</td>
                  <td>
                    {info.present
                      ? <CheckCircle className="w-3.5 h-3.5 text-[var(--color-success)]" />
                      : <XCircle className="w-3.5 h-3.5 text-[var(--color-error)]" />}
                  </td>
                  <td className="font-mono text-xs text-[var(--color-text-muted)] max-w-xs truncate" title={info.value || ""}>
                    {info.value || <span className="text-[var(--color-error)] opacity-60">missing</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Technologies Panel ─────────────────────────────────────────────────────

function TechPanel({ tech }: { tech: TechData }) {
  const grouped: Record<string, { name: string; category: string }[]> = {};
  for (const t of tech.technologies) {
    if (!grouped[t.category]) grouped[t.category] = [];
    grouped[t.category].push(t);
  }

  const catColors: Record<string, string> = {
    "CMS": "badge-warn",
    "E-Commerce": "badge-warn",
    "JS Framework": "badge-info",
    "JS Library": "badge-info",
    "CSS Framework": "badge-neutral",
    "Analytics": "badge-warn",
    "Marketing": "badge-warn",
    "CRM": "badge-warn",
    "CRM/Support": "badge-warn",
    "Backend": "badge-info",
    "Web Server": "badge-secure",
    "CDN": "badge-secure",
    "CDN/WAF": "badge-secure",
    "Cloud": "badge-info",
    "Hosting": "badge-neutral",
    "Security": "badge-secure",
  };

  return (
    <div className="space-y-6">
      {/* Tech Stack */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Code} label="Detected Technologies" />
        {tech.technologies.length === 0 ? (
          <p className="text-[var(--color-text-faint)] text-sm font-mono">No technologies fingerprinted</p>
        ) : (
          <div className="space-y-4">
            {Object.entries(grouped).map(([cat, items]) => (
              <div key={cat}>
                <p className="text-xs text-[var(--color-text-faint)] font-mono uppercase tracking-widest mb-2">{cat}</p>
                <div className="flex flex-wrap gap-2">
                  {items.map((t, i) => (
                    <span key={i} className={`${catColors[t.category] || "badge-neutral"} px-3 py-1 rounded text-xs font-mono`}>
                      {t.name}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Server info */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Server} label="Server Headers" />
        <div className="space-y-2">
          <FieldRow label="Server" value={tech.server} mono />
          <FieldRow label="X-Powered-By" value={tech.powered_by} mono
            badge={tech.powered_by ? <RiskBadge level="medium" /> : undefined} />
          <FieldRow label="CMS" value={tech.cms} />
          {tech.analytics.length > 0 && (
            <FieldRow label="Analytics" value={tech.analytics.join(", ")} />
          )}
        </div>
        {tech.powered_by && (
          <div className="mt-3 flex items-start gap-2 p-3 rounded border border-[hsl(38_90%_55%/0.25)] bg-[hsl(38_90%_55%/0.06)]">
            <AlertCircle className="w-4 h-4 text-[var(--color-warning)] shrink-0 mt-0.5" />
            <p className="text-xs text-[var(--color-warning)]">
              X-Powered-By header exposes backend technology. Consider removing for security hardening.
            </p>
          </div>
        )}
      </div>

      {/* Cookies */}
      {tech.cookies.length > 0 && (
        <div className="terminal-card p-5">
          <SectionTitle icon={Key} label="Cookies" />
          <table className="data-table w-full">
            <thead>
              <tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th></tr>
            </thead>
            <tbody>
              {tech.cookies.map((c, i) => (
                <tr key={i}>
                  <td className="font-mono text-xs text-[var(--color-primary)]">{c.name}</td>
                  <td>{c.secure ? <CheckCircle className="w-3 h-3 text-[var(--color-success)]" /> : <XCircle className="w-3 h-3 text-[var(--color-error)]" />}</td>
                  <td>{c.httponly ? <CheckCircle className="w-3 h-3 text-[var(--color-success)]" /> : <XCircle className="w-3 h-3 text-[var(--color-error)]" />}</td>
                  <td className="font-mono text-xs text-[var(--color-text-muted)]">{c.samesite || "—"}</td>
                  <td className="font-mono text-xs text-[var(--color-text-muted)]">{c.domain}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Raw headers */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Terminal} label="Response Headers" />
        <ScrollArea className="h-64">
          <table className="data-table w-full">
            <thead><tr><th>Header</th><th>Value</th></tr></thead>
            <tbody>
              {Object.entries(tech.headers).map(([k, v]) => (
                <tr key={k}>
                  <td className="font-mono text-xs text-[var(--color-primary)] whitespace-nowrap">{k}</td>
                  <td className="font-mono text-xs text-[var(--color-text-muted)] break-all">{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ScrollArea>
      </div>
    </div>
  );
}

// ── Identities Panel ────────────────────────────────────────────────────────

function IdentitiesPanel({ identities, breaches }: { identities: IdentityData; breaches: BreachData }) {
  return (
    <div className="space-y-6">
      {/* Emails */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Mail} label={`Emails (${identities.emails.length} discovered)`} />
        {identities.emails.length === 0 ? (
          <p className="text-[var(--color-text-faint)] text-sm font-mono">No email addresses discovered</p>
        ) : (
          <>
            {identities.email_format && (
              <div className="mb-3 flex items-center gap-2">
                <span className="badge-info text-xs font-mono px-2 py-0.5 rounded">Format: {identities.email_format}</span>
              </div>
            )}
            <div className="space-y-1.5">
              {identities.emails.map((email, i) => (
                <div key={i} className="flex items-center gap-3 group py-1.5 border-b border-[var(--color-border)] last:border-0">
                  <Mail className="w-3.5 h-3.5 text-[var(--color-text-faint)] shrink-0" />
                  <code className="text-sm text-[var(--color-text)] flex-1">{email}</code>
                  <button onClick={() => copyToClipboard(email)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity">
                    <Copy className="w-3.5 h-3.5 text-[var(--color-text-faint)] hover:text-[var(--color-primary)]" />
                  </button>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* Social profiles */}
      <div className="terminal-card p-5">
        <SectionTitle icon={Users} label="Social Media Presence" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {Object.entries(identities.social_profiles).map(([platform, info]) => {
            const found = info.status === "found";
            return (
              <div key={platform} className={`flex items-center justify-between p-3 rounded border ${found ? "border-[hsl(185_80%_55%/0.25)] bg-[hsl(185_80%_55%/0.06)]" : "border-[var(--color-border)] opacity-40"}`}>
                <div className="flex items-center gap-2.5">
                  {found
                    ? <CheckCircle className="w-4 h-4 text-[var(--color-success)]" />
                    : <XCircle className="w-4 h-4 text-[var(--color-text-faint)]" />}
                  <div className="flex flex-col gap-1">
                    <span className="text-sm font-mono">{platform}</span>
                    {found && (
                      <span className="text-[0.65rem] uppercase tracking-wide font-mono text-[var(--color-text-faint)]">
                        Source: {sourceLabel(info.source)}
                      </span>
                    )}
                  </div>
                </div>
                {found && (
                  <a href={info.url} target="_blank" rel="noopener noreferrer">
                    <ExternalLink className="w-3.5 h-3.5 text-[var(--color-primary)] hover:opacity-70" />
                  </a>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {identities.impersonation_candidates && identities.impersonation_candidates.length > 0 && (
        <div className="terminal-card p-5">
          <SectionTitle icon={AlertTriangle} label="Possible Impersonation" />
          <div className="space-y-3">
            {identities.impersonation_candidates.map((candidate, index) => (
              <div
                key={`${candidate.url || candidate.username || index}`}
                className="rounded border border-[hsl(0_65%_55%/0.28)] bg-[hsl(0_65%_55%/0.08)] p-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-sm font-mono text-[var(--color-text)]">
                      {candidate.platform || "Unknown"}: {candidate.username || "unknown"}
                    </p>
                    <p className="text-xs text-[var(--color-text-muted)] mt-1 font-mono">
                      {candidate.reason || "suspicious variation"}
                    </p>
                    {candidate.source && (
                      <p className="text-[0.65rem] uppercase tracking-wide font-mono text-[var(--color-text-faint)] mt-2">
                        Source: {candidate.source}
                      </p>
                    )}
                  </div>
                  {candidate.url && (
                    <a href={candidate.url} target="_blank" rel="noopener noreferrer">
                      <ExternalLink className="w-3.5 h-3.5 text-[var(--color-primary)] hover:opacity-70" />
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* GitHub repos */}
      {identities.github_repos.length > 0 && (
        <div className="terminal-card p-5">
          <SectionTitle icon={Code} label="GitHub Repositories" />
          <div className="space-y-3">
            {identities.github_repos.map((repo, i) => (
              <div key={i} className="flex items-start justify-between gap-3 py-2 border-b border-[var(--color-border)] last:border-0">
                <div className="flex-1 min-w-0">
                  <a href={repo.url} target="_blank" rel="noopener noreferrer"
                    className="text-[var(--color-primary)] text-sm font-mono hover:underline block">
                    {repo.name}
                  </a>
                  {repo.description && (
                    <p className="text-xs text-[var(--color-text-muted)] mt-0.5 truncate">{repo.description}</p>
                  )}
                </div>
                <span className="text-xs text-[var(--color-text-faint)] font-mono shrink-0">★ {repo.stars}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Breach indicators */}
      <div className="terminal-card p-5">
        <SectionTitle icon={AlertTriangle} label="Breach Indicators" />
        {(identities.breaches?.length > 0 || breaches.dehashed_hint) ? (
          <div className="space-y-2">
            <div className="flex items-start gap-2 p-3 rounded border border-[hsl(0_65%_55%/0.3)] bg-[hsl(0_65%_55%/0.08)]">
              <AlertTriangle className="w-4 h-4 text-[var(--color-error)] shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-[var(--color-error)]">Breach data detected</p>
                {breaches.dehashed_hint && (
                  <p className="text-xs text-[var(--color-text-muted)] mt-1">{breaches.dehashed_hint}</p>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-[var(--color-success)] text-sm">
            <CheckCircle className="w-4 h-4" />
            <span className="font-mono">No breach data found in public sources</span>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Raw JSON view ──────────────────────────────────────────────────────────

function RawPanel({ data }: { data: ReconData }) {
  const [copied, setCopied] = useState(false);
  const raw = JSON.stringify(data, null, 2);

  const handleCopy = () => {
    copyToClipboard(raw);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="terminal-card p-5">
      <div className="flex items-center justify-between mb-4">
        <SectionTitle icon={Terminal} label="Raw JSON Output" />
        <button onClick={handleCopy}
          className="flex items-center gap-1.5 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-primary)] font-mono transition-colors">
          {copied ? <CheckCircle className="w-3.5 h-3.5 text-[var(--color-success)]" /> : <Copy className="w-3.5 h-3.5" />}
          {copied ? "Copied" : "Copy JSON"}
        </button>
      </div>
      <ScrollArea className="h-[600px]">
        <pre className="text-xs font-mono text-[var(--color-text-muted)] leading-relaxed whitespace-pre-wrap break-all">
          {raw}
        </pre>
      </ScrollArea>
    </div>
  );
}

function ProvidersPanel({ providerResults }: { providerResults: Record<string, ProviderResult> }) {
  const selectedProviders = osintProviders.filter((provider) => providerResults[provider.id]);
  const fallbackProviders = Object.keys(providerResults)
    .filter((providerId) => !selectedProviders.some((provider) => provider.id === providerId))
    .map((providerId) => ({
      id: providerId,
      label: providerId,
      category: "Other",
    }));

  const orderedProviders = [
    ...selectedProviders.map((provider) => ({ id: provider.id, label: provider.label, category: provider.category })),
    ...fallbackProviders,
  ];

  return (
    <div className="space-y-6">
      {orderedProviders.length === 0 ? (
        <div className="terminal-card p-5">
          <p className="text-[var(--color-text-faint)] text-sm font-mono">No provider-specific evidence captured for this scan.</p>
        </div>
      ) : (
        orderedProviders.map((provider) => {
          const details = providerResults[provider.id];
          if (!details) return null;
          const socialProfileValues = Array.isArray(details.social_profiles)
            ? details.social_profiles
            : details.social_profiles && typeof details.social_profiles === "object"
              ? Object.entries(details.social_profiles).map(([platform, profile]) => ({
                  platform,
                  ...(profile || {}),
                }))
              : [];

          const mentionSections = Object.entries(
            (details.mentions || []).reduce<Record<string, NonNullable<ProviderResult["mentions"]>>>((groups, mention) => {
              const category = mention.category || "other";
              if (!groups[category]) {
                groups[category] = [];
              }
              groups[category].push(mention);
              return groups;
            }, {}),
          ).map(([category, values]) => ({
            label: mentionSectionLabel(category),
            values,
          }));

          const sections = [
            { label: "Emails", values: details.emails || [] },
            ...mentionSections,
            { label: "Repos", values: details.repos || [] },
            { label: "Subdomains", values: details.subdomains || [] },
            { label: "Breach Hints", values: details.breach_hints || [] },
            { label: "DNS Records", values: details.dns_records || [] },
            { label: "WHOIS", values: details.whois || [] },
            { label: "SSL", values: details.ssl || [] },
            { label: "Tech", values: details.tech || [] },
            { label: "Ports", values: details.ports || [] },
            { label: "Hosting", values: details.hosting || [] },
            { label: "Social Profiles", values: socialProfileValues },
            { label: "Possible Impersonation", values: details.impersonation_candidates || [] },
          ].filter((section) => section.values.length > 0);

          return (
            <div key={provider.id} className="terminal-card p-5">
              <div className="flex flex-wrap items-center gap-2 mb-4">
                <SectionTitle icon={Users} label={provider.label} />
                <span className={`${details.status === "ok" ? "badge-secure" : details.status === "partial" ? "badge-info" : details.status === "skipped" ? "badge-warn" : details.status === "running" ? "badge-info" : "badge-open"} px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase tracking-wide`}>
                  {details.status}
                </span>
                {details.duration_ms !== null && details.duration_ms !== undefined && (
                  <span className="badge-info px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase tracking-wide">
                    {formatDuration(details.duration_ms)}
                  </span>
                )}
                <span className="badge-neutral px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase tracking-wide">
                  {provider.category}
                </span>
              </div>

              {details.progress_logs && details.progress_logs.length > 0 && (
                <div className="mb-4">
                  <p className="text-xs text-[var(--color-text-faint)] font-mono uppercase tracking-widest mb-2">Live Progress</p>
                  <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3 max-h-48 overflow-y-auto space-y-1">
                    {[...details.progress_logs].slice(-12).reverse().map((line, index) => (
                      <p key={`${line}-${index}`} className="text-xs font-mono text-[var(--color-text-muted)] whitespace-pre-wrap break-words">
                        {line}
                      </p>
                    ))}
                  </div>
                </div>
              )}

              {details.notes.length > 0 && (
                <div className="mb-4 space-y-1">
                  {details.notes.map((note, index) => (
                    <p key={index} className="text-xs font-mono text-[var(--color-text-muted)]">{note}</p>
                  ))}
                </div>
              )}

              {sections.length === 0 ? (
                <p className="text-[var(--color-text-faint)] text-sm font-mono">No exact findings captured for this provider.</p>
              ) : (
                <div className="space-y-4">
                  {sections.map((section) => (
                    <div key={section.label}>
                      <p className="text-xs text-[var(--color-text-faint)] font-mono uppercase tracking-widest mb-2">{section.label}</p>
                      <div className="space-y-1.5">
                        {section.values.map((value, index) => (
                          <div key={index} className="border-b border-[var(--color-border)] last:border-0 py-1.5">
                            {typeof value === "string" ? (
                              <code className="text-xs text-[var(--color-text)] break-all whitespace-pre-wrap">{value}</code>
                            ) : isMentionValue(value) ? (
                              <div className="space-y-1">
                                {value.title && <p className="text-sm text-[var(--color-text)] font-medium">{value.title}</p>}
                                {value.url && (
                                  <a
                                    href={value.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="text-xs font-mono text-[var(--color-primary)] break-all inline-flex items-center gap-1"
                                  >
                                    {value.url}
                                    <ExternalLink className="w-3 h-3" />
                                  </a>
                                )}
                                {value.snippet && (
                                  <p className="text-xs text-[var(--color-text-muted)] whitespace-pre-wrap">{value.snippet}</p>
                                )}
                                <div className="flex flex-wrap gap-2 text-[0.65rem] font-mono uppercase tracking-wide text-[var(--color-text-faint)]">
                                  {value.source_domain && <span>{value.source_domain}</span>}
                                  {value.query && <span>Query: {value.query}</span>}
                                </div>
                              </div>
                            ) : (
                              <code className="text-xs text-[var(--color-text)] break-all whitespace-pre-wrap">
                                {JSON.stringify(value, null, 2)}
                              </code>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })
      )}
    </div>
  );
}

function ProviderSelectionPanel({
  selectedProviderIds,
  onToggleProvider,
  onSelectDefaults,
  onSelectAllAvailable,
  onClearSelections,
  disabled,
}: {
  selectedProviderIds: string[];
  onToggleProvider: (providerId: string) => void;
  onSelectDefaults: () => void;
  onSelectAllAvailable: () => void;
  onClearSelections: () => void;
  disabled: boolean;
}) {
  const groupedProviders = osintProviders.reduce<Record<string, OsintProvider[]>>((groups, provider) => {
    if (!groups[provider.category]) {
      groups[provider.category] = [];
    }
    groups[provider.category].push(provider);
    return groups;
  }, {});

  const selectedSet = new Set(selectedProviderIds);
  const selectableProviderIds = getSelectableProviderIds();

  return (
    <div className="terminal-card p-6 mb-8">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between mb-5">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Users className="w-4 h-4 text-[var(--color-primary)]" />
            <h2 className="text-sm font-mono font-semibold text-[var(--color-text)]">Provider Selection</h2>
          </div>
          <p className="text-xs text-[var(--color-text-faint)] font-mono max-w-3xl">
            Review every provider, see what evidence it contributes, and choose which supported sources should run for this investigation.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onSelectDefaults}
            disabled={disabled}
            className="px-3 py-1.5 rounded border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] disabled:opacity-50"
          >
            Defaults
          </button>
          <button
            type="button"
            onClick={onSelectAllAvailable}
            disabled={disabled}
            className="px-3 py-1.5 rounded border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] disabled:opacity-50"
          >
            Select All Available
          </button>
          <button
            type="button"
            onClick={onClearSelections}
            disabled={disabled}
            className="px-3 py-1.5 rounded border border-[var(--color-border)] text-xs font-mono text-[var(--color-text-muted)] hover:text-[var(--color-text)] hover:border-[var(--color-primary)] disabled:opacity-50"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-3 mb-5">
        <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
          <p className="text-[0.65rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-1">Selected Now</p>
          <p className="text-2xl font-mono font-bold text-[var(--color-primary)]">{selectedProviderIds.length}</p>
        </div>
        <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
          <p className="text-[0.65rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-1">Selectable Today</p>
          <p className="text-2xl font-mono font-bold text-[var(--color-text)]">{selectableProviderIds.length}</p>
        </div>
        <div className="rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] p-3">
          <p className="text-[0.65rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-1">Visible Providers</p>
          <p className="text-2xl font-mono font-bold text-[var(--color-text)]">{osintProviders.length}</p>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 mb-5">
        {(["active", "limited", "needs_api_key", "planned"] as const).map((status) => (
          <span key={status} className={`${providerStatusClass(status)} px-2 py-1 rounded text-[0.65rem] font-mono uppercase tracking-wide`}>
            {providerStatusLabel(status)}
          </span>
        ))}
      </div>

      <ScrollArea className="h-[720px] pr-3">
        <div className="space-y-6">
          {Object.entries(groupedProviders).map(([category, providers]) => (
            <div key={category}>
              <div className="flex items-center gap-2 mb-3">
                <Badge variant="outline" className="font-mono text-[0.65rem] uppercase tracking-widest">
                  {category}
                </Badge>
                <span className="text-xs font-mono text-[var(--color-text-faint)]">{providers.length} providers</span>
              </div>
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                {providers.map((provider) => {
                  const checked = selectedSet.has(provider.id);
                  return (
                    <label
                      key={provider.id}
                      className={`block rounded-md border p-4 transition-colors ${
                        checked
                          ? "border-[hsl(185_80%_55%/0.4)] bg-[hsl(185_80%_55%/0.07)]"
                          : "border-[var(--color-border)] bg-[var(--color-surface)]"
                      } ${provider.selectable && !disabled ? "cursor-pointer" : "cursor-not-allowed opacity-80"}`}
                    >
                      <div className="flex items-start gap-3">
                        <Checkbox
                          checked={checked}
                          disabled={!provider.selectable || disabled}
                          onCheckedChange={() => onToggleProvider(provider.id)}
                          className="mt-0.5 border-[var(--color-primary)] data-[state=checked]:bg-[var(--color-primary)]"
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-2 mb-2">
                            <span className="text-sm font-mono font-semibold text-[var(--color-text)]">{provider.label}</span>
                            <span className={`${providerStatusClass(provider.status)} px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase tracking-wide`}>
                              {providerStatusLabel(provider.status)}
                            </span>
                            <span className="badge-neutral px-2 py-0.5 rounded text-[0.65rem] font-mono uppercase tracking-wide">
                              {provider.implementation}
                            </span>
                          </div>

                          <div className="flex flex-wrap gap-1.5 mb-3">
                            {provider.evidence.map((item) => (
                              <span key={item} className="badge-info px-2 py-0.5 rounded text-[0.65rem] font-mono">
                                {evidenceLabel(item)}
                              </span>
                            ))}
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 mb-3">
                            <div className="rounded border border-[var(--color-border)] px-2.5 py-2">
                              <p className="text-[0.6rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)]">Auth</p>
                              <p className="text-xs font-mono text-[var(--color-text)] mt-1">{provider.auth}</p>
                            </div>
                            <div className="rounded border border-[var(--color-border)] px-2.5 py-2">
                              <p className="text-[0.6rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)]">Cost</p>
                              <p className="text-xs font-mono text-[var(--color-text)] mt-1">{provider.cost}</p>
                            </div>
                            <div className="rounded border border-[var(--color-border)] px-2.5 py-2">
                              <p className="text-[0.6rem] font-mono uppercase tracking-widest text-[var(--color-text-faint)]">Reliability</p>
                              <p className="text-xs font-mono text-[var(--color-text)] mt-1">{providerReliabilityLabel(provider.reliability)}</p>
                            </div>
                          </div>

                          <div className="space-y-2 text-xs">
                            <div>
                              <p className="font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-1">What You Get</p>
                              <p className="text-[var(--color-text-muted)] leading-relaxed">{provider.details}</p>
                            </div>
                            <div>
                              <p className="font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-1">Why Keep It</p>
                              <p className="text-[var(--color-text-muted)] leading-relaxed">{provider.whyKeep}</p>
                            </div>
                            <div>
                              <p className="font-mono uppercase tracking-widest text-[var(--color-text-faint)] mb-1">Known Limits</p>
                              <p className="text-[var(--color-text-muted)] leading-relaxed">{provider.limits}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

// ── Loading state ──────────────────────────────────────────────────────────

const SCAN_STEPS = [
  { label: "Resolving domain via pattern matching...", delay: 0 },
  { label: "Running DNS enumeration (A, MX, TXT, NS, SOA)...", delay: 1200 },
  { label: "Checking Certificate Transparency logs (crt.sh)...", delay: 2500 },
  { label: "Enumerating subdomains (wordlist + CT)...", delay: 4000 },
  { label: "Inspecting SSL/TLS certificate...", delay: 5500 },
  { label: "Running WHOIS lookup...", delay: 6500 },
  { label: "Probing open ports...", delay: 8000 },
  { label: "ASN / IP WHOIS lookup...", delay: 10000 },
  { label: "Technology fingerprinting (headers, body)...", delay: 11500 },
  { label: "Harvesting email addresses...", delay: 13000 },
  { label: "Checking social media presence...", delay: 16000 },
  { label: "Checking breach databases...", delay: 18000 },
  { label: "Compiling report...", delay: 20000 },
];

function LoadingView() {
  const [currentStep, setCurrentStep] = useState(0);
  const [dots, setDots] = useState("");

  useEffect(() => {
    const stepTimers = SCAN_STEPS.map((step, i) =>
      setTimeout(() => setCurrentStep(i), step.delay)
    );
    const dotsTimer = setInterval(() => setDots((d) => d.length >= 3 ? "" : d + "."), 400);
    return () => {
      stepTimers.forEach(clearTimeout);
      clearInterval(dotsTimer);
    };
  }, []);

  return (
    <div className="terminal-card p-8 relative overflow-hidden scanning">
      <div className="flex items-center gap-3 mb-6">
        <Activity className="w-5 h-5 text-[var(--color-primary)] animate-pulse" />
        <h3 className="text-sm font-mono font-semibold text-[var(--color-primary)] uppercase tracking-widest">
          OSINT Scan in Progress{dots}
        </h3>
      </div>
      <div className="space-y-2 mb-6">
        {SCAN_STEPS.slice(0, currentStep + 1).map((step, i) => (
          <div key={i} className={`flex items-center gap-2.5 animate-fade-in-up ${i === currentStep ? "opacity-100" : "opacity-40"}`}>
            {i < currentStep
              ? <CheckCircle className="w-3.5 h-3.5 text-[var(--color-success)] shrink-0" />
              : <span className="w-3.5 h-3.5 border border-[var(--color-primary)] rounded-full shrink-0 animate-pulse" />}
            <span className={`font-mono text-xs ${i === currentStep ? "text-[var(--color-primary)]" : "text-[var(--color-text-faint)]"}`}>
              {step.label}
            </span>
          </div>
        ))}
      </div>
      <div className="progress-bar">
        <div className="progress-fill transition-all duration-700"
          style={{ width: `${Math.round((currentStep / (SCAN_STEPS.length - 1)) * 100)}%` }} />
      </div>
    </div>
  );
}

// ── Main Dashboard ─────────────────────────────────────────────────────────

export default function Dashboard() {
  const [company, setCompany] = useState("");
  const [result, setResult] = useState<ReconData | null>(null);
  const [logs, setLogs] = useState<string>("");
  const [selectedProviderIds, setSelectedProviderIds] = useState<string[]>(() => getDefaultSelectedProviderIds());
  const { toast } = useToast();
  const inputRef = useRef<HTMLInputElement>(null);

  const mutation = useMutation({
    mutationFn: async ({ name, sources }: { name: string; sources: string[] }) => {
      const res = await apiRequest("POST", "/api/recon", { company: name, sources });
      return res.json();
    },
    onSuccess: (data) => {
      if (data.success && data.data) {
        setResult(data.data);
        setLogs(data.logs || "");
      } else {
        toast({ title: "Scan failed", description: data.error || "Unknown error", variant: "destructive" });
      }
    },
    onError: (err) => {
      toast({ title: "Request failed", description: String(err), variant: "destructive" });
    },
  });

  useEffect(() => {
    const jobId = result?.spiderfoot_job?.job_id;
    const jobStatus = result?.spiderfoot_job?.status;
    if (!jobId || jobStatus !== "running") {
      return;
    }

    let cancelled = false;
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    const poll = async () => {
      try {
        const res = await fetch(`/api/recon/jobs/${jobId}`);
        if (!res.ok) {
          throw new Error(`SpiderFoot poll failed with ${res.status}`);
        }
        const payload = await res.json();
        if (cancelled || !payload.success || !payload.job) {
          return;
        }
        setResult((current) => (current ? mergeSpiderfootJobIntoResult(current, payload.job as SpiderfootJob) : current));
        if ((payload.job as SpiderfootJob).status === "running") {
          timeoutId = setTimeout(poll, 2500);
        }
      } catch {
        if (!cancelled) {
          timeoutId = setTimeout(poll, 4000);
        }
      }
    };

    timeoutId = setTimeout(poll, 1500);

    return () => {
      cancelled = true;
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    };
  }, [result?.spiderfoot_job?.job_id, result?.spiderfoot_job?.status]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!company.trim()) return;
    if (selectedProviderIds.length === 0) {
      toast({
        title: "No providers selected",
        description: "Choose at least one provider before starting the scan.",
        variant: "destructive",
      });
      return;
    }
    setResult(null);
    mutation.mutate({ name: company.trim(), sources: selectedProviderIds });
  };

  const toggleProvider = (providerId: string) => {
    const provider = osintProviders.find((item) => item.id === providerId);
    if (!provider?.selectable || mutation.isPending) {
      return;
    }
    setSelectedProviderIds((current) =>
      current.includes(providerId)
        ? current.filter((id) => id !== providerId)
        : [...current, providerId],
    );
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {/* SVG Logo */}
              <svg width="32" height="32" viewBox="0 0 32 32" fill="none" aria-label="OSINT Recon" xmlns="http://www.w3.org/2000/svg">
                <rect width="32" height="32" rx="6" fill="hsl(185 80% 55% / 0.12)" />
                <circle cx="16" cy="16" r="8" stroke="hsl(185, 80%, 55%)" strokeWidth="1.5" strokeDasharray="3 2" />
                <circle cx="16" cy="16" r="3" fill="hsl(185, 80%, 55%)" />
                <line x1="16" y1="4" x2="16" y2="8" stroke="hsl(185, 80%, 55%)" strokeWidth="1.5" strokeLinecap="round" />
                <line x1="16" y1="24" x2="16" y2="28" stroke="hsl(185, 80%, 55%)" strokeWidth="1.5" strokeLinecap="round" />
                <line x1="4" y1="16" x2="8" y2="16" stroke="hsl(185, 80%, 55%)" strokeWidth="1.5" strokeLinecap="round" />
                <line x1="24" y1="16" x2="28" y2="16" stroke="hsl(185, 80%, 55%)" strokeWidth="1.5" strokeLinecap="round" />
              </svg>
              <div>
                <h1 className="text-sm font-mono font-bold text-[var(--color-text)] tracking-wide">OSINT RECON</h1>
                <p className="text-[0.6rem] font-mono text-[var(--color-text-faint)] uppercase tracking-widest">Passive Intelligence Gathering</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[var(--color-success)] animate-pulse" />
              <span className="text-xs font-mono text-[var(--color-text-faint)]">ACTIVE</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
        {/* Search form */}
        <div className="terminal-card p-6 mb-8">
          <div className="flex items-center gap-2 mb-4">
            <Eye className="w-4 h-4 text-[var(--color-primary)]" />
            <h2 className="text-sm font-mono font-semibold text-[var(--color-text)]">Target Company Reconnaissance</h2>
          </div>
          <form onSubmit={handleSubmit} className="flex gap-3" data-testid="recon-form">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[var(--color-text-faint)]" />
              <input
                ref={inputRef}
                data-testid="input-company"
                type="text"
                value={company}
                onChange={(e) => setCompany(e.target.value)}
                placeholder="Enter company name (e.g. Cloudflare, Tesla, ESET)"
                className="w-full pl-10 pr-4 py-2.5 bg-[var(--color-surface-2)] border border-[var(--color-border)] rounded-md text-sm font-mono text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus:outline-none focus:ring-1 focus:ring-[var(--color-primary)] focus:border-[var(--color-primary)] transition-colors"
                disabled={mutation.isPending}
              />
            </div>
            <button
              data-testid="button-scan"
              type="submit"
              disabled={mutation.isPending || !company.trim()}
              className="flex items-center gap-2 px-5 py-2.5 bg-[var(--color-primary)] text-[hsl(224_20%_7%)] rounded-md text-sm font-mono font-semibold disabled:opacity-50 disabled:cursor-not-allowed hover:brightness-110 transition-all"
            >
              {mutation.isPending ? (
                <><Activity className="w-4 h-4 animate-spin" /> Scanning</>
              ) : (
                <><Zap className="w-4 h-4" /> Scan</>
              )}
            </button>
          </form>
          <p className="text-xs text-[var(--color-text-faint)] font-mono mt-3">
            Performs passive reconnaissance: DNS enumeration, SSL inspection, WHOIS, port scanning, tech fingerprinting, email harvesting, breach detection.
          </p>
        </div>

        <ProviderSelectionPanel
          selectedProviderIds={selectedProviderIds}
          onToggleProvider={toggleProvider}
          onSelectDefaults={() => setSelectedProviderIds(getDefaultSelectedProviderIds())}
          onSelectAllAvailable={() => setSelectedProviderIds(getSelectableProviderIds())}
          onClearSelections={() => setSelectedProviderIds([])}
          disabled={mutation.isPending}
        />

        {/* Loading */}
        {mutation.isPending && <LoadingView />}

        {/* Results */}
        {result && !mutation.isPending && (
          <div className="animate-fade-in-up">
            <OverviewPanel data={result} />
            <TimingsPanel timings={result.timings} />

            <Tabs defaultValue="endpoints" className="w-full">
              <TabsList className="w-full justify-start bg-[var(--color-surface)] border border-[var(--color-border)] rounded-md p-1 mb-6 overflow-x-auto flex gap-1 h-auto">
                {[
                  { value: "endpoints", label: "Endpoints", icon: Server },
                  { value: "dns", label: "DNS", icon: Database },
                  { value: "technologies", label: "Technologies", icon: Code },
                  { value: "identities", label: "Identities", icon: Users },
                  { value: "providers", label: "Providers", icon: Key },
                  { value: "raw", label: "Raw JSON", icon: Terminal },
                ].map(({ value, label, icon: Icon }) => (
                  <TabsTrigger key={value} value={value} data-testid={`tab-${value}`}
                    className="flex items-center gap-1.5 px-3 py-2 text-xs font-mono rounded data-[state=active]:bg-[var(--color-primary)] data-[state=active]:text-[hsl(224_20%_7%)] text-[var(--color-text-muted)] hover:text-[var(--color-text)] transition-colors whitespace-nowrap">
                    <Icon className="w-3.5 h-3.5" />
                    {label}
                  </TabsTrigger>
                ))}
              </TabsList>

              <TabsContent value="endpoints">
                <EndpointsPanel hosting={result.hosting} ssl={result.ssl} whois={result.whois} tech={result.technologies} />
              </TabsContent>
              <TabsContent value="dns">
                <DnsPanel dns={result.dns} />
              </TabsContent>
              <TabsContent value="technologies">
                <TechPanel tech={result.technologies} />
              </TabsContent>
              <TabsContent value="identities">
                <IdentitiesPanel identities={result.identities} breaches={result.breaches} />
              </TabsContent>
              <TabsContent value="providers">
                <ProvidersPanel providerResults={result.provider_results} />
              </TabsContent>
              <TabsContent value="raw">
                <RawPanel data={result} />
              </TabsContent>
            </Tabs>

            {result.errors.length > 0 && (
              <div className="mt-6 terminal-card p-4 border border-[hsl(38_90%_55%/0.25)] bg-[hsl(38_90%_55%/0.05)]">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-[var(--color-warning)]" />
                  <span className="text-xs font-mono text-[var(--color-warning)] uppercase tracking-widest">Scan Warnings</span>
                </div>
                {result.errors.map((e, i) => (
                  <p key={i} className="text-xs font-mono text-[var(--color-text-muted)]">— {e}</p>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Empty state */}
        {!result && !mutation.isPending && (
          <div className="terminal-card p-12 text-center">
            <div className="flex justify-center mb-4">
              <div className="w-16 h-16 rounded-full border border-[var(--color-border)] flex items-center justify-center">
                <Eye className="w-7 h-7 text-[var(--color-text-faint)]" />
              </div>
            </div>
            <h3 className="text-sm font-mono font-semibold text-[var(--color-text)] mb-2">No active target</h3>
            <p className="text-xs text-[var(--color-text-faint)] font-mono max-w-md mx-auto">
              Enter a company name above to begin passive OSINT reconnaissance. The scan will discover DNS records, subdomains, SSL certificates, hosting infrastructure, email addresses, and more.
            </p>
          </div>
        )}
      </main>

      <footer className="border-t border-[var(--color-border)] mt-16 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 flex items-center justify-between">
          <p className="text-xs font-mono text-[var(--color-text-faint)]">
            OSINT Recon — For authorized security research only
          </p>
          <a href="https://www.perplexity.ai/computer" target="_blank" rel="noopener noreferrer"
            className="text-xs text-[var(--color-text-faint)] hover:text-[var(--color-primary)] transition-colors">
            Created with Perplexity Computer
          </a>
        </div>
      </footer>
    </div>
  );
}
