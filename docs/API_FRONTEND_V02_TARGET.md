# ATI — v0.2 API and Frontend Target

PR 89 authorizes no immediate public API or UI behavior change. As PR 28 migrates read models, Investigation-facing reads must preserve exact admitted EvidenceObservation state rather than silently resolving stable Evidence to the newest global observation. Analyst drill-down may expose the full global EvidenceObservation history while clearly identifying which observations were admitted to the current Investigation.

Exact endpoint, DTO, map/table, report, and frontend changes must be derived from fresh `main` in the implementation PR that owns them. `API.md` and `FRONTEND.md` remain delivered contracts until then.
