import { cleanImpersonationCandidates, type IdentityCandidate } from "./impersonation-candidates";

export type EmailSourceEntry = {
  email: string;
  module: string;
  module_type: "api" | "public" | "unknown";
  event_type: string;
  source: string;
  api_backed: boolean;
};

export type SocialProfileEntry = {
  url: string;
  status: string;
  source?: string;
};

export type IdentityNormalizationInput = {
  emails?: string[];
  email_sources?: EmailSourceEntry[];
  social_profiles?: Record<string, SocialProfileEntry> | Array<Record<string, unknown>>;
  impersonation_candidates?: IdentityCandidate[];
};

export type IdentityNormalizationOutput = {
  emails: string[];
  email_sources?: EmailSourceEntry[];
  social_profiles: Record<string, SocialProfileEntry>;
  impersonation_candidates: IdentityCandidate[];
};

function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeUrl(value: string): string {
  const trimmed = value.trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(trimmed);
    parsed.hostname = parsed.hostname.replace(/^www\./i, "");
    return `${parsed.protocol}//${parsed.hostname}${parsed.pathname}${parsed.search}${parsed.hash}`.replace(/\/+$/, "");
  } catch {
    return trimmed;
  }
}

function normalizePlatform(value: string): string {
  return value.trim().toLowerCase();
}

function scoreSocialProfile(entry: SocialProfileEntry): number {
  let score = 0;
  if ((entry.status || "").toLowerCase() === "found") score += 100;
  if (entry.source) score += 10;
  return score;
}

function scoreEmailSource(entry: EmailSourceEntry): number {
  let score = 0;
  if (entry.api_backed) score += 100;
  if (entry.module_type === "api") score += 20;
  if (entry.event_type === "EMAILADDR") score += 10;
  if (entry.event_type !== "EMAILADDR_GENERIC") score += 5;
  if (entry.module && entry.module !== "unknown") score += 1;
  return score;
}

function mergeEmailSources(entries: EmailSourceEntry[]): EmailSourceEntry[] {
  const byEmail = new Map<string, EmailSourceEntry>();

  for (const entry of entries) {
    const email = normalizeEmail(entry.email);
    if (!email) continue;

    const candidate: EmailSourceEntry = {
      ...entry,
      email,
      module: entry.module || "unknown",
      module_type: entry.module_type || "unknown",
      event_type: entry.event_type || "unknown",
      source: entry.source || "unknown",
      api_backed: Boolean(entry.api_backed),
    };

    const current = byEmail.get(email);
    if (!current || scoreEmailSource(candidate) > scoreEmailSource(current)) {
      byEmail.set(email, candidate);
    }
  }

  return Array.from(byEmail.values());
}

function normalizeSocialProfiles(
  socialProfiles: IdentityNormalizationInput["social_profiles"],
): Record<string, SocialProfileEntry> {
  const entries: Array<[string, SocialProfileEntry]> = [];

  if (Array.isArray(socialProfiles)) {
    for (const item of socialProfiles) {
      for (const [platform, profile] of Object.entries(item)) {
        const value = profile as SocialProfileEntry;
        if (!value || typeof value !== "object" || typeof value.url !== "string") continue;
        entries.push([platform, value]);
      }
    }
  } else if (socialProfiles && typeof socialProfiles === "object") {
    for (const [platform, profile] of Object.entries(socialProfiles)) {
      const value = profile as SocialProfileEntry;
      if (!value || typeof value !== "object" || typeof value.url !== "string") continue;
      entries.push([platform, value]);
    }
  }

  const normalized = new Map<string, { platform: string; profile: SocialProfileEntry; order: number }>();

  entries.forEach(([platform, profile], index) => {
    const normalizedPlatform = normalizePlatform(platform);
    const normalizedUrl = normalizeUrl(profile.url);
    const key = `${normalizedPlatform}|${normalizedUrl.toLowerCase()}`;
    if (!key || !normalizedUrl) return;

    if (!normalized.has(key)) {
      normalized.set(key, {
        platform,
        profile: {
          ...profile,
          url: normalizedUrl,
        },
        order: index,
      });
      return;
    }

    const current = normalized.get(key);
    if (!current) {
      return;
    }

    const candidateProfile: SocialProfileEntry = {
      ...profile,
      url: normalizedUrl,
    };

    if (scoreSocialProfile(candidateProfile) > scoreSocialProfile(current.profile)) {
      normalized.set(key, {
        platform: current.platform,
        profile: candidateProfile,
        order: current.order,
      });
      return;
    }

    if (profile.source && !current.profile.source) {
      normalized.set(key, {
        ...current,
        profile: {
          ...current.profile,
          source: profile.source,
        },
      });
    }
  });

  const result: Record<string, SocialProfileEntry> = {};
  for (const item of normalized.values()) {
    result[item.platform] = item.profile;
  }

  return result;
}

export function normalizeIdentityData(input: IdentityNormalizationInput): IdentityNormalizationOutput {
  const emails = Array.from(
    new Set((input.emails || []).map((email) => normalizeEmail(email)).filter(Boolean)),
  );

  const email_sources = input.email_sources ? mergeEmailSources(input.email_sources) : undefined;

  return {
    emails,
    email_sources,
    social_profiles: normalizeSocialProfiles(input.social_profiles),
    impersonation_candidates: cleanImpersonationCandidates(input.impersonation_candidates),
  };
}
