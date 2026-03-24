# SpiderFoot Background Job Design

## Goal

Move SpiderFoot out of the synchronous recon request so the main scan returns quickly while SpiderFoot continues in the background and updates the current report in place.

## Architecture

The normal recon request will stop executing SpiderFoot inline. When SpiderFoot is selected, the backend will create an in-memory job record, launch a background SpiderFoot worker, and return the main report immediately with `spiderfoot` marked as `running` plus a `job_id`. The frontend will poll for job updates and merge SpiderFoot progress, partial findings, and final results into the current report.

## Backend

- Add an in-memory SpiderFoot job store in Node.
- Exclude SpiderFoot from the synchronous Python recon request.
- Add a background runner that executes SpiderFoot-only work and captures:
  - status
  - elapsed time
  - progress log entries
  - partial provider data
  - final provider data
- Add routes to fetch current job state.

## Frontend

- If the main scan returns a SpiderFoot job, start polling automatically.
- Show SpiderFoot as `running` in the Providers tab.
- Render a live progress panel with:
  - status
  - elapsed time
  - progress messages
  - partial findings
- Merge partial SpiderFoot findings into the current report without resetting the rest of the scan output.

## Non-Goals

- No persistence across server restarts in this version.
- No SSE/WebSocket transport in this version.
