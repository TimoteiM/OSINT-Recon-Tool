export type IdentityCandidate = {
  platform?: string;
  username?: string;
  url?: string;
  matched_candidate?: string;
  reason?: string;
  source?: string;
};

function mergeUniqueObjects<T>(current: T[], incoming: T[], keyFn: (value: T) => string) {
  const next = new Map<string, T>();
  for (const value of current) next.set(keyFn(value), value);
  for (const value of incoming) next.set(keyFn(value), value);
  return Array.from(next.values());
}

function isClickableHttpUrl(value: unknown): value is string {
  if (typeof value !== "string" || !/^https?:\/\//i.test(value)) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
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
  if (sfurlMatch?.[1]) return sfurlMatch[1].trim().replace(/\/+$/, "");

  const plainUrlMatch = decoded.match(/https?:\/\/[^\s<>"']+/i);
  if (plainUrlMatch?.[0]) return plainUrlMatch[0].trim().replace(/\/+$/, "");

  return null;
}

function normalizeImpersonationCandidate(candidate: IdentityCandidate): IdentityCandidate | null {
  if (isClickableHttpUrl(candidate.url)) {
    return {
      ...candidate,
      url: candidate.url.replace(/\/+$/, ""),
    };
  }

  if (!candidate.username) {
    return null;
  }

  const decoded = decodeSpiderfootValue(candidate.username);
  const url = extractSpiderfootUrl(decoded);
  if (!url) {
    return null;
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }

  const pathParts = parsed.pathname.split("/").filter(Boolean);
  const labelMatch = decoded.match(/^([^<(]+?)(?:\s*\(.*?\))?\s*<SFURL>/i);
  const labelPlatform = labelMatch?.[1]?.trim();
  const username = pathParts[pathParts.length - 1]?.replace(/^@/, "");

  return {
    platform: candidate.platform || labelPlatform || "Profile",
    username: username || candidate.username,
    url,
    reason: candidate.reason,
    source: candidate.source,
  };
}

export function cleanImpersonationCandidates(candidates: IdentityCandidate[] | undefined): IdentityCandidate[] {
  const normalized = (candidates || [])
    .map((candidate) => normalizeImpersonationCandidate(candidate))
    .filter((candidate): candidate is IdentityCandidate => Boolean(candidate));

  return mergeUniqueObjects(
    [],
    normalized,
    (candidate) => JSON.stringify([candidate.url || "", candidate.username || "", candidate.platform || ""]),
  );
}
