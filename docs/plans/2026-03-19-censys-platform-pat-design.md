# Censys Platform PAT Design

**Date:** 2026-03-19

## Goal

Switch the app's Censys integration from the Legacy Search credential model to the newer Platform API Personal Access Token model, using `Censys_Token` from the local `.env`.

## Current Problem

The app currently treats Censys as a Legacy Search integration and expects `Censys_API_KEY` to contain `API_ID:API_SECRET`. The user has instead configured a valid Personal Access Token in `Censys_Token`, so the current runtime never exercises the correct auth model.

## Design

### Runtime contract

- Read `Censys_Token` from `.env`
- Authenticate with `Authorization: Bearer <token>`
- Remove the old credential-shape validation that required `API_ID:API_SECRET`

### Provider behavior

- `401`: `Censys rejected the configured PAT`
- `403`: `Censys accepted the PAT but denied access`
- `200`: record exact subdomain/certificate evidence into `provider_results`
- preserve concise response-body detail when present

### Catalog and docs

- Update `.env.example` to document `Censys_Token`
- Update the provider catalog text to describe PAT-based Platform API use

## Testing

Use TDD to:

- replace legacy Censys tests with PAT-based tests
- verify bearer auth is used
- verify live app behavior after restart
