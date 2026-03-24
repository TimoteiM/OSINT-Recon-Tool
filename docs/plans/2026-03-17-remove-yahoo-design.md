# Remove Yahoo Design

**Goal:** Remove the Yahoo provider completely from the application so it no longer appears in the frontend or executes in the backend.

**Problem**

Yahoo was added as a selectable no-key search provider, but the user wants it removed entirely rather than hidden or disabled. That requires deleting both the visible catalog entry and the engine logic so the application does not retain dead or hidden references.

**Approved Direction**

- Remove the `yahoo` provider entry from the shared provider catalog
- Remove Yahoo-specific engine behavior from:
  - website discovery
  - passive search evidence
  - provider attribution maps
- Remove Yahoo-specific tests
- Leave the rest of the no-key provider wave intact

**Scope**

Files expected to change:
- `shared/osint-providers.ts`
- `osint_engine.py`
- `osint_engine_test.py`
- `server/provider-catalog.test.ts`

**Testing**

- Add or adjust tests first so the expected selectable-provider set and engine behavior no longer reference Yahoo
- Run Python tests, provider catalog tests, typecheck, and build after removal
