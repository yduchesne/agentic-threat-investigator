# ATI — v0.2 Configuration Target

PR 28D local/test operation requires no external broker configuration beyond selecting the in-process Evidence log implementation. PR 28G owns Kafka/Redpanda-compatible connection/topic/consumer-group configuration and secret references. Configuration must select infrastructure adapters without changing Evidence semantics or converter selection.

`CONFIGURATION.md` remains current delivered behavior until those implementation changes land.
