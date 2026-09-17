# ATI — v0.2 Deployment Target

No broker dependency is introduced by the documentation or early PR 28 domain slices. PR 28D provides an ATI-owned in-process `InMemoryEvidenceLog` for deterministic local/test operation; it is deliberately non-durable and not a production broker. PR 28G owns Kafka/Redpanda-compatible infrastructure, configuration, partitioning/consumer-group semantics, and deployment changes while preserving application publisher/consumer contracts.

`DEPLOYMENT.md` and `CONFIGURATION.md` remain current delivered behavior until those implementation changes land.
