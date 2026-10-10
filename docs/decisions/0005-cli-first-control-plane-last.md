# 0005: CLI first; control plane last

- Status: Accepted
- Date: 2026-10-10

## Context
The operator already knows NestJS/Postgres/BullMQ/Next.js well. The novel, hard parts are the VMM, networking, capture and isolation layers.

## Decision
Phases 1–6 are driven by a CLI talking gRPC to `urljaild`. The NestJS/Next.js control plane is Phase 7. `urljaild` remains the only privileged component forever; the control plane is a client.

## Alternatives considered
- **Dashboard early:** visible progress, but time spent on the least novel part, and an API shaped by UI needs before the core is understood.

## Consequences
- The gRPC API is designed for a CLI first, then reused by NestJS.
- Reports are JSON files on disk until P7 introduces Postgres.
