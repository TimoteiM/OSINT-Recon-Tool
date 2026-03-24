import type { Express } from "express";
import type { Server } from "http";
import { runRecon } from "./recon-runner";
import { getDefaultSelectedProviderIds, sanitizeSelectedProviderIds } from "@shared/osint-providers";
import { createRunningSpiderfootProviderResult, getSpiderfootJob, startSpiderfootJob } from "./spiderfoot-jobs";

export function splitSpiderfootSelection(selectedSources: string[]): {
  inlineSources: string[];
  backgroundProviderId: "spiderfoot" | "spiderfoot_deep" | null;
} {
  const hasDeep = selectedSources.includes("spiderfoot_deep");
  const hasSpiderfoot = selectedSources.includes("spiderfoot");
  return {
    inlineSources: selectedSources.filter((source) => source !== "spiderfoot" && source !== "spiderfoot_deep"),
    backgroundProviderId: hasDeep ? "spiderfoot_deep" : hasSpiderfoot ? "spiderfoot" : null,
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

export async function registerRoutes(_httpServer: Server, app: Express): Promise<void> {
  // POST /api/recon — run the Python OSINT engine
  app.post("/api/recon", async (req, res) => {
    const { company, sources } = req.body as { company?: string; sources?: unknown };
    if (!company || typeof company !== "string" || company.trim().length < 2) {
      return res.status(400).json({ error: "Company name is required (min 2 characters)." });
    }
    const companyName = company.trim();
    const selectedSources = sanitizeSelectedProviderIds(sources);

    if (Array.isArray(sources) && sources.length > 0 && selectedSources.length !== new Set(sources).size) {
      return res.status(400).json({ error: "One or more provider IDs are invalid." });
    }

    try {
      const effectiveSelectedSources = selectedSources.length > 0 ? selectedSources : getDefaultSelectedProviderIds();
      const { inlineSources, backgroundProviderId } = splitSpiderfootSelection(effectiveSelectedSources);
      const result = await runRecon({
        companyName,
        selectedSources: inlineSources,
      });
      const report = result.data as Record<string, any>;

      if (backgroundProviderId) {
        const job = await startSpiderfootJob({ companyName, providerId: backgroundProviderId });
        report.provider_results = report.provider_results || {};
        report.provider_results[backgroundProviderId] = createRunningSpiderfootProviderResult();
        report.spiderfoot_job = {
          job_id: job.job_id,
          provider_id: job.provider_id,
          scan_id: job.scan_id,
          status: job.status,
          started_at: job.started_at,
        };
      }

      return res.json({ success: true, ...result });
    } catch (error) {
      const normalized = normalizeReconError(error);
      return res.status(normalized.status).json(normalized.body);
    }
  });

  app.get("/api/recon/jobs/:jobId", (req, res) => {
    const job = getSpiderfootJob(req.params.jobId);
    if (!job) {
      return res.status(404).json({ error: "SpiderFoot job not found" });
    }

    return res.json({
      success: true,
      job: {
        job_id: job.job_id,
        provider_id: job.provider_id,
        scan_id: job.scan_id,
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
