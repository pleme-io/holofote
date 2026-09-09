;; holofote deployment bounds — the (defholofote) authoring face.
;;
;; ONE struct, two faces: this form and the shikumi YAML overlay both
;; deserialize into `HolofoteConfig`. Every field here is a BOUND on what
;; the observe-only server will do against one Splunk host; none of them is
;; a credential, a host, or a label — those are argv, per host.
;;
;; A test (`prescribed_mirrors_the_authored_lisp`) pins this form to
;; `TieredConfig::prescribed_default()`, so the two faces cannot drift.

(defholofote
  ;; The hard cap on any search's `limit` (also sent as max_count and as
  ;; the results `count`). A request above it is REFUSED, never clamped —
  ;; clamping would answer a different question than the one asked.
  :max-results 1000
  ;; How many indexes `splunk_indexes` lists when the caller names no limit.
  :default-indexes-limit 100
  ;; How often a running job is polled for its dispatch state.
  :poll-interval-ms 500
  ;; The wall-clock bound on one search, holofote-side; also sent to Splunk
  ;; as max_time so the server stops working when the client stops waiting.
  :max-search-seconds 60
  ;; Sent as `timeout`: how long Splunk keeps a finished job's artifacts.
  ;; holofote DELETEs its own jobs anyway; this is the backstop if it dies.
  :job-ttl-seconds 300
  ;; Sent as `auto_cancel`: idle seconds before Splunk cancels a job nobody
  ;; is polling. The second backstop.
  :job-auto-cancel-seconds 120
  ;; TCP connect + TLS handshake budget. A host behind a VPN that is down
  ;; should answer `blind` after five seconds rather than hang.
  :connect-timeout-ms 5000
  ;; Whole-request budget for any one REST call.
  :request-timeout-ms 30000
  ;; How many terms one search may carry. Over it is REFUSED by key.
  :max-terms 32
  ;; How many bytes one term value may carry — the one free-form string a
  ;; caller can put in a search, bounded so a value is never a payload.
  :max-term-bytes 4096
  ;; How many names each of `fields` / `stats_count_by` may carry.
  :max-fields 32)
