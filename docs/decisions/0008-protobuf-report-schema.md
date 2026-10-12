# 0008: Protobuf as the report schema source of truth

- Status: Accepted
- Date: 2026-10-12

## Context
`report.json` is read by the CLI, later by the NestJS control plane, and by outside tools. Its pieces (events, artifacts) already travel over gRPC (see [0007](./0007-grpc-over-vsock.md)). The schema needs one source of truth so Go structs, the wire format and the JSON file can't drift apart (open question Q6).

## Decision
The report schema is defined in **protobuf** under `api/proto/`. `report.json` is produced with `protojson` using fixed options, and a **JSON Schema is generated from the proto** and published with each schema version for outside readers.

`protojson` settings:
- `UseProtoNames: true`, so JSON keys stay snake_case as in [report-schema.md](../report-schema.md).
- `EmitUnpopulated: false`, so empty sections are left out rather than filled with zero values.
- Fields that need to stay JSON numbers (byte counts, durations) use int32/uint32 or double where the range allows. protojson writes 64-bit integers as strings.

Run IDs are **UUIDv7** (RFC 9562): they sort by time like ULIDs, use the standard UUID format, are produced by `google/uuid`'s `NewV7()`, and Postgres 18 can generate them natively with `uuidv7()` for the P7 control plane (open question Q14).

## Alternatives considered
- **JSON Schema first, generating Go:** good for outside readers, but Go code generated from JSON Schema is weak, and the gRPC messages would need a second definition.
- **Go structs first:** fastest to start, but there's no language-neutral contract for NestJS or outside tools.
- **ULID run IDs:** equivalent ordering, but not a standard UUID type in Postgres or most tools.

## Consequences
- One `.proto` change updates Go, the TypeScript control plane (via codegen) and the JSON Schema.
- Schema versions follow the proto package (`urljail.report.v0`).
- A JSON Schema generator (e.g. `protoc-gen-jsonschema`) joins the build.
