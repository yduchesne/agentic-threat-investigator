# ATI — v0.2 Agent and Evaluation Target

Under the v0.2 global Evidence model, analytical execution must use the exact EvidenceObservations admitted to an Investigation, not a mutable/global-latest projection. Direct source-fact provenance ultimately identifies an exact observation; graph provenance identifies a RelationshipObservation supported by an exact observation. Newer global observations do not retroactively change an Investigation's factual basis.

`AGENT_DESIGN.md` and `EVALUATION.md` remain current delivered contracts until the corresponding PR 28 implementation changes land. PR 28H owns end-to-end replay/crash/reproducibility closure in addition to the existing analytical evaluation gates.
