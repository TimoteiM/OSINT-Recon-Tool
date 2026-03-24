# SpiderFoot Timeout and Timings Design

## Goal

Raise SpiderFoot's default live-scan timeout to improve completion odds, and expose real backend timings in the UI so each investigation stage shows how long it took.

## Approach

The Python engine remains the source of truth for timing data. It will measure the total recon duration and the major investigation stages, plus provider-specific durations for long-running tools such as SpiderFoot and Sherlock. The UI will render those durations from the API payload rather than estimating them client-side.

## Scope

- Increase SpiderFoot default timeout from 45s to 90s while keeping `SPIDERFOOT_TIMEOUT_MS` as an override.
- Add timing capture to the Python report for total scan time, major stages, and selected provider runs where useful.
- Render total and per-investigation timings in the dashboard.

## Non-Goals

- No background-job architecture for SpiderFoot in this change.
- No frontend-only stopwatch estimates.
