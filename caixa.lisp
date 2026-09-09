;; holofote — the typed SDLC manifest. One file, one source of truth.
;;
;; Substrate-side renderers consume this and emit:
;;   caixa-publish        → release flow + git tag (crates.io for the library)
;;   caixa-publish-tlisp  → tatara-lisp publishing path (the specs/*.lisp surface)
;;   caixa-validate       → CSE invariant check (layout, slot coverage)
;;   caixa-forge          → repo + workflow regeneration
;;
;; Author edits HERE; everything downstream re-derives from these slots.
;;
;; Kind rationale: holofote is a Binario (a stdio MCP server that READS one
;; Splunk host and never writes to it). It carries no in-cluster runtime,
;; which is why CLAUDE.md declares skip-urdume / skip-helm-native /
;; skip-gitops / skip-magma / skip-continuous-convergence /
;; skip-platform-mediated.

(defcaixa
  :nome "holofote"
  :versao "0.1.0"
  :kind Binario
  :edicao "2026"
  :descricao "holofote (searchlight) — a typed Splunk REST client and observe-only MCP server. A closed route enum with no mutating arm, a typed SPL AST with exactly one renderer, a results route derived from the server version, credentials read at call time into zeroizing memory, and every answer one of kotae's four outcomes (found / empty / refused / blind) so an unreachable host is never read as an empty index."
  :repositorio "github:pleme-io/holofote"
  :licenca "MIT"
  :autores ("pleme-io")
  :etiquetas ("rust"
    "tatara-lisp"
    "splunk"
    "spl"
    "mcp"
    "observability"
    "observe-only"
    "kotae"
    "handan"
    "shikumi"
    "caixa-binario")

  ;; Workspace deps that need to vendor at build time.
  :deps ()
  :deps-dev ()

  ;; The wired-up binary is what `feira publish` releases.
  :exe ("holofote-mcp")

  ;; The downstream-consumable typed surface.
  ;;
  ;; holofote — the library: the `Transport` seam (reqwest impl + scripted
  ;; mock), the closed `Route` enum, `Credential` + zeroizing session
  ;; handling, `ServerVersion` → `ResultsRoute`, the typed `Search` AST with
  ;; its single `Display` renderer, `HolofoteConfig` (shikumi tiers +
  ;; `(defholofote …)`), and `SplunkClient<T: Transport>` returning `Outcome`.
  ;; A consumer that wants the client without the MCP framing depends on
  ;; this alone; it has no rmcp dependency.
  :bibliotecas ("holofote"))
