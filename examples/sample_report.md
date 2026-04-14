# Securenetes Audit Report (c5-baseline)

- Report-ID: `SNET-20260414090000`
- Zielcluster: `prod-cluster-eu-1`
- Zeitpunkt: `2026-04-14T09:00:00Z`

## Prüfbereich: rbac

### RBAC-WILDCARD-cluster-admin-custom - Wildcard-Berechtigungen erkannt
- **Schweregrad:** Critical
- **Prüfkriterium:** Rollen dürfen nicht unbeschränkt (*) berechtigen
- **Feststellung:** ClusterRole enthält Wildcards in verbs/resources.
- **Risiko:** Missbrauch mit vollständiger Clusterkontrolle möglich
- **Handlungsempfehlung:** Least-Privilege durch explizite verbs/resources implementieren.
- **Evidenz:** Wildcard in Rule gefunden
- **Betroffene Ressource:** cluster/cluster-admin-custom (ClusterRole)

## Prüfbereich: pod_security

### POD-PRIV-prod-api-7df7 - Privilegierter Container
- **Schweregrad:** Critical
- **Prüfkriterium:** Pod Hardening nach Least Privilege
- **Feststellung:** Sicherheitsrelevante Pod-Konfiguration weicht von Best Practices ab.
- **Risiko:** Erhöhte Privilegien oder schwache Isolation können zur Cluster-Kompromittierung führen.
- **Handlungsempfehlung:** SecurityContext hart setzen (non-root, no privilege escalation, readonly FS, Limits).
- **Evidenz:** Container api privileged=true
- **Betroffene Ressource:** production/prod-api-7df7 (Pod)
