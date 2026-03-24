import { type IdentityCandidate } from "./impersonation-candidates";
import {
  normalizeIdentityData,
  type EmailSourceEntry,
  type SocialProfileEntry,
} from "./identity-normalization";

type ProviderResult = {
  emails?: string[];
  email_sources?: EmailSourceEntry[];
  social_profiles?: Record<string, SocialProfileEntry> | Array<Record<string, unknown>>;
  impersonation_candidates?: IdentityCandidate[];
  mentions?: Array<{
    category?: string;
    title?: string;
    url?: string;
    snippet?: string;
    source_domain?: string;
    matched_domain?: string;
    query?: string;
  }>;
  repos?: Array<Record<string, unknown>>;
};

type BaseIdentityData = {
  domain: string;
  emails: string[];
  email_sources?: EmailSourceEntry[];
  email_format: string | null;
  github_repos: Array<Record<string, unknown>>;
  social_profiles: Record<string, SocialProfileEntry>;
  impersonation_candidates?: IdentityCandidate[];
  breaches: unknown[];
};

function mentionToSocialProfile(
  mention: NonNullable<ProviderResult["mentions"]>[number],
  providerId: string,
): Record<string, SocialProfileEntry> | null {
  const url = typeof mention.url === "string" ? mention.url : "";
  if (!url || mention.category !== "social") return null;

  let hostname = "";
  try {
    hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }

  const platformMap: Record<string, string> = {
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "x.com": "Twitter/X",
    "twitter.com": "Twitter/X",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
    "reddit.com": "Reddit",
  };
  const platform = platformMap[hostname];
  if (!platform) return null;

  return {
    [platform]: {
      url,
      status: "found",
      source: `derived:${providerId}`,
    },
  };
}

export function buildCanonicalIdentitiesFromProviders(
  baseIdentities: BaseIdentityData,
  providerResults: Record<string, ProviderResult>,
): BaseIdentityData {
  const emails = [...(baseIdentities.emails || [])];
  const emailSources = [...(baseIdentities.email_sources || [])];
  const socialProfiles: Array<Record<string, unknown>> = [baseIdentities.social_profiles || {}];
  const impersonationCandidates = [...(baseIdentities.impersonation_candidates || [])];
  const githubRepos = [...(baseIdentities.github_repos || [])];

  for (const [providerId, details] of Object.entries(providerResults || {})) {
    emails.push(...(details.emails || []));
    emailSources.push(...(details.email_sources || []));

    if (details.social_profiles) {
      if (Array.isArray(details.social_profiles)) {
        socialProfiles.push(...details.social_profiles);
      } else {
        socialProfiles.push(details.social_profiles as Record<string, unknown>);
      }
    }

    for (const mention of details.mentions || []) {
      const socialProfile = mentionToSocialProfile(mention, providerId);
      if (socialProfile) {
        socialProfiles.push(socialProfile);
      }
    }

    impersonationCandidates.push(...(details.impersonation_candidates || []));
    githubRepos.push(...(details.repos || []));
  }

  const normalized = normalizeIdentityData({
    emails,
    email_sources: emailSources,
    social_profiles: socialProfiles,
    impersonation_candidates: impersonationCandidates,
  });

  return {
    ...baseIdentities,
    emails: normalized.emails,
    email_sources: normalized.email_sources,
    social_profiles: normalized.social_profiles,
    impersonation_candidates: normalized.impersonation_candidates,
    github_repos: Array.from(new Map(githubRepos.map((repo) => [JSON.stringify(repo), repo])).values()),
  };
}
