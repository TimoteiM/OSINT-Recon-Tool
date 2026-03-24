import type { Express } from "express";
import type { Server } from "http";
import { runRecon } from "./recon-runner";
import { getDefaultSelectedProviderIds, isKnownProviderId, sanitizeSelectedProviderIds } from "@shared/osint-providers";
import { createRunningSpiderfootProviderResult, getSpiderfootJob, startSpiderfootJob } from "./spiderfoot-jobs";
import { createRunningSherlockProviderResult, getSherlockJob, startSherlockJob } from "./sherlock-jobs";

export function splitBackgroundSelection(selectedSources: string[]): {
  inlineSources: string[];
  backgroundProviderIds: Array<"spiderfoot" | "spiderfoot_deep" | "sherlock">;
} {
  const hasDeep = selectedSources.includes("spiderfoot_deep");
  const hasSpiderfoot = selectedSources.includes("spiderfoot");
  const hasSherlock = selectedSources.includes("sherlock");
  const backgroundProviderIds: Array<"spiderfoot" | "spiderfoot_deep" | "sherlock"> = [];
  if (hasDeep) backgroundProviderIds.push("spiderfoot_deep");
  else if (hasSpiderfoot) backgroundProviderIds.push("spiderfoot");
  if (hasSherlock) backgroundProviderIds.push("sherlock");
  return {
    inlineSources: selectedSources.filter((source) => source !== "spiderfoot" && source !== "spiderfoot_deep" && source !== "sherlock"),
    backgroundProviderIds,
  };
}

export function normalizeReconError(error: unknown): {
  status: number;
  body: Record<string, unknown>;
} {
  if (error instanceof Error) {
    try {
      const parsed = JSON.parse(error.message) as Record<string, unknown>;
      const message = typeof parsed.error === "string" ? parsed.error : "";
      if (message.includes("exceeded the configured timeout")) {
        return {
          status: 200,
          body: { success: false, ...parsed },
        };
      }
      return { status: 500, body: parsed };
    } catch {
      return { status: 500, body: { error: error.message } };
    }
  }

  return { status: 500, body: { error: "Unknown recon failure" } };
}

export function hasInvalidRequestedProviderIds(sources: unknown): boolean {
  if (!Array.isArray(sources) || sources.length === 0) {
    return false;
  }

  return sources.some((value) => {
    if (typeof value !== "string") {
      return true;
    }
    const normalized = value === "google" ? "google_dorks" : value;
    return !isKnownProviderId(normalized);
  });
}

function createSpiderfootErrorProviderResult(message: string) {
  return {
    ...createRunningSpiderfootProviderResult(),
    status: "error",
    notes: [message],
    progress_logs: [],
  };
}

export async function attachSpiderfootBackgroundScan(
  report: Record<string, any>,
  companyName: string,
  backgroundProviderId: "spiderfoot" | "spiderfoot_deep",
  startJob: typeof startSpiderfootJob = startSpiderfootJob,
): Promise<void> {
  report.provider_results = report.provider_results || {};

  try {
    const job = await startJob({ companyName, providerId: backgroundProviderId });
    report.provider_results[backgroundProviderId] = createRunningSpiderfootProviderResult();
    report.spiderfoot_job = {
      job_id: job.job_id,
      provider_id: job.provider_id,
      scan_id: job.scan_id,
      status: job.status,
      started_at: job.started_at,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown SpiderFoot startup failure";
    report.provider_results[backgroundProviderId] = createSpiderfootErrorProviderResult(
      `SpiderFoot startup failed: ${message}`,
    );
  }
}

export async function attachSherlockBackgroundScan(
  report: Record<string, any>,
  companyName: string,
  startJob: typeof startSherlockJob = startSherlockJob,
): Promise<void> {
  report.provider_results = report.provider_results || {};

  try {
    const job = await startJob({ companyName });
    report.provider_results.sherlock = createRunningSherlockProviderResult();
    const jobSummary = {
      job_id: job.job_id,
      provider_id: job.provider_id,
      scan_id: job.scan_id,
      status: job.status,
      started_at: job.started_at,
    };
    report.sherlock_job = jobSummary;
    report.background_jobs = [...(report.background_jobs || []), jobSummary];
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown Sherlock startup failure";
    report.provider_results.sherlock = {
      ...createRunningSherlockProviderResult(),
      status: "error",
      notes: [`Sherlock startup failed: ${message}`],
      progress_logs: [],
    };
  }
}

export async function registerRoutes(_httpServer: Server, app: Express): Promise<void> {
  // POST /api/recon — run the Python OSINT engine
  app.post("/api/recon", async (req, res) => {
    const { company, sources } = req.body as { company?: string; sources?: unknown };
    if (!company || typeof company !== "string" || company.trim().length < 2) {
      return res.status(400).json({ error: "Company name is required (min 2 characters)." });
    }
    const companyName = company.trim();
    const selectedSources = sanitizeSelectedProviderIds(sources);

    if (hasInvalidRequestedProviderIds(sources)) {
      return res.status(400).json({ error: "One or more provider IDs are invalid." });
    }

    try {
      const effectiveSelectedSources = selectedSources.length > 0 ? selectedSources : getDefaultSelectedProviderIds();
      const { inlineSources, backgroundProviderIds } = splitBackgroundSelection(effectiveSelectedSources);
      const result = await runRecon({
        companyName,
        selectedSources: inlineSources,
      });
      const report = result.data as Record<string, any>;

      for (const backgroundProviderId of backgroundProviderIds) {
        if (backgroundProviderId === "sherlock") {
          await attachSherlockBackgroundScan(report, companyName);
          continue;
        }
        await attachSpiderfootBackgroundScan(report, companyName, backgroundProviderId);
        if (!report.background_jobs) {
          report.background_jobs = [];
        }
        if (report.spiderfoot_job) {
          report.background_jobs.push(report.spiderfoot_job);
        }
      }

      return res.json({ success: true, ...result });
    } catch (error) {
      const normalized = normalizeReconError(error);
      return res.status(normalized.status).json(normalized.body);
    }
  });

  app.get("/api/recon/jobs/:jobId", (req, res) => {
    const job = getSpiderfootJob(req.params.jobId) || getSherlockJob(req.params.jobId);
    if (!job) {
      return res.status(404).json({ error: "Background job not found" });
    }

    return res.json({
      success: true,
      job: {
        job_id: job.job_id,
        provider_id: job.provider_id,
        scan_id: "scan_id" in job ? job.scan_id : undefined,
        company_name: job.company_name,
        status: job.status,
        started_at: job.started_at,
        updated_at: job.updated_at,
        elapsed_ms: job.elapsed_ms,
        progress_logs: job.progress_logs,
        provider_result: job.provider_result,
        report: job.report,
        error: job.error,
      },
    });
  });

  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", time: new Date().toISOString() });
  });
}
