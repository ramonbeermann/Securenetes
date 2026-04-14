# Securenetes

Securenetes ist ein professionelles, lokal ausführbares Rust-CLI-Tool zur automatisierten Sicherheits- und Compliance-Prüfung von Kubernetes-Clustern.
Der Ergebnisbericht ist strukturell an einen **BSI C5-orientierten Prüfbericht** angelehnt.

## Architekturüberblick

- **CLI-Orchestrator (`src/main.rs`)**
  - lädt YAML-Konfiguration
  - initialisiert Kubernetes-Client
  - führt aktivierte Prüfmodule aus
  - schreibt Bericht in Markdown, JSON oder HTML
- **Checks (`src/checks/*`)**
  - jede Prüfung ist als separates Modul mit gemeinsamer `Check`-Trait umgesetzt
  - unterstützt reale Abfragen gegen Clusterressourcen via `kube`
  - kennzeichnet Heuristiken explizit
- **Domänenmodell (`src/models.rs`)**
  - zentrale C5-orientierte Strukturen (`Finding`, `Evidence`, `AuditReport`, `Severity`)
- **Reporting (`src/reporting/*`)**
  - Renderer für Terminal-nahe Artefakte (Markdown/JSON/HTML)

## Umfang (MVP)

Enthaltene Prüfbereiche:

- RBAC (Wildcards, cluster-admin Bindings)
- Secrets (sensible Namensmuster, Opaque-Nutzung)
- Pod Security (privileged, host namespaces, escalation, rofs, limits)
- Network Policies (Namespaces ohne Policies)
- Ingress/Exposure (LoadBalancer/NodePort, Ingress ohne TLS)
- Images (latest/ungepinnte Tags)
- Logging/Monitoring (heuristische Auditierbarkeitsprüfung)
- API-Server-Konfiguration (heuristische Ergänzungspflicht)
- etcd (heuristische Risikoindikation)
- TLS/Web-Exposure (HTTPS, HSTS, Server-Banner)
- E-Mail-Validierung aus Config

## Installation

### Voraussetzungen

- Linux
- Rust (stable, empfohlen ≥ 1.80)
- Zugriff auf Kubernetes-Cluster (`KUBECONFIG` oder In-Cluster Konfiguration)

### Build

```bash
cargo build --release
```

## Nutzung

### Beispielkonfiguration

Siehe `examples/config.yaml`.

### CLI-Aufruf

```bash
cargo run -- \
  --config examples/config.yaml \
  --output-dir reports \
  --format markdown
```

Alternative Formate:

```bash
cargo run -- --config examples/config.yaml --output-dir reports --format json
cargo run -- --config examples/config.yaml --output-dir reports --format html
```

## Berichtsstruktur (C5-orientiert)

Jede Feststellung enthält:

- eindeutige ID
- Titel
- Prüfbereich
- Prüfkriterium
- Feststellung
- Risiko
- Handlungsempfehlung
- Schweregrad (Kritisch/Hoch/Mittel/Niedrig/Hinweis)
- technische Evidenz
- betroffene Ressource (wenn vorhanden)
- Heuristik-Markierung (`heuristic: true/false`)

Beispielberichte:

- `examples/sample_report.md`
- `examples/sample_report.json`

## Repository-Struktur

```text
Securenetes/
├── Cargo.toml
├── README.md
├── examples/
│   ├── config.yaml
│   ├── sample_report.json
│   └── sample_report.md
├── src/
│   ├── lib.rs
│   ├── main.rs
│   ├── config.rs
│   ├── models.rs
│   ├── checks/
│   │   ├── mod.rs
│   │   ├── rbac.rs
│   │   ├── secrets.rs
│   │   ├── pod_security.rs
│   │   ├── network.rs
│   │   ├── ingress.rs
│   │   ├── images.rs
│   │   ├── logging_monitoring.rs
│   │   ├── api_config.rs
│   │   ├── etcd.rs
│   │   └── tls.rs
│   └── reporting/
│       ├── mod.rs
│       ├── markdown.rs
│       ├── json.rs
│       └── html.rs
└── reports/
```

## Erweiterbarkeit (Roadmap)

- CVE-Scanner-Adapter (Trivy/Grype) für Image Findings
- OPA/Gatekeeper/Kyverno Policy-Integrationen
- Signaturprüfung (Cosign/SBOM)
- persistente, revisionssichere Ergebnisablage (z. B. immutable object storage)
- Diff-/Trendberichte über mehrere Audit-Läufe
- optionale Web-GUI (z. B. Axum + SPA) mit Rollen- und Freigabeworkflow
- Firewall-/IP-Change-Analyse als neues Check-Modul

## Sicherheits- und Compliance-Hinweis

Das Tool liefert automatisierte und teilweise heuristische Bewertungen. Für formelle C5-Prüfungen sollten Ergebnisse durch manuelle Nachweise, organisatorische Kontrollen und unabhängige Prüfhandlungen ergänzt werden.
