# Enterprise High-Availability Kubernetes Infrastructure
### Production Architecture & Design Document

| | |
|---|---|
| **Scope** | On-premises / bare-metal or private-cloud HA Kubernetes platform |
| **Target scale** | 500+ workloads, 100+ developers, 5,000+ Wazuh-monitored endpoints |
| **SLA target** | 99.99% (≈ 52 min unplanned downtime / year) |
| **Standards** | CNCF best practices, Kubernetes production guidelines, CIS Benchmarks, ISO 27001-aligned controls |
| **Document version** | 1.0 — June 2026 |

> **Read this first — one critical platform change you must plan around:** Upstream **ingress-nginx was retired by the Kubernetes project on March 24, 2026** (no further releases, bugfixes, or CVE patches). Rancher's own RKE2 distribution switched its default ingress controller to **Traefik** starting with v1.36. The original requirements list below names "NGINX Ingress Controller" — it is documented here exactly as requested, but **Section 5.5** explains why this design recommends Traefik (or another actively-maintained Gateway-API-based controller) as the production default, with NGINX Ingress kept only as a documented legacy/migration option. Don't build a 2026+ production platform on a dead ingress controller.

---

## Table of Contents

1. Design Principles & Architecture Overview
2. Kubernetes Cluster Design (Nodes, etcd, Hardware)
3. Networking Architecture (Topology, LB, Failover, VLAN/IP Plan)
4. Security Architecture (Wazuh, Falco, Trivy, Kyverno, RBAC, Zero Trust)
5. Ingress Architecture & the ingress-nginx Retirement
6. Monitoring Architecture (Prometheus/Grafana/Alertmanager)
7. Infrastructure Monitoring (Zabbix) & Grafana Integration
8. Logging Architecture (Loki/Promtail Pipeline)
9. Storage Architecture (Longhorn)
10. Rancher Management Architecture
11. High Availability Design & Failover Scenarios
12. Disaster Recovery (RTO/RPO)
13. CI/CD & GitOps
14. Backup Strategy
15. DNS, Naming Convention & Certificate Management
16. Implementation Roadmap
17. Production Deployment Checklist
18. Common Failure Scenarios
19. Performance Optimization
20. Scaling Strategy (8 → 100+ Nodes)
21. Risks & Mitigations
22. Alternative Architecture Options
23. Recommended Production Configuration (Summary)

---

## 1. Design Principles & Architecture Overview

### 1.1 Core Principles

| Principle | How this design achieves it |
|---|---|
| **No Single Point of Failure** | 3x control plane, 3x external etcd, 2x HAProxy + Keepalived VIP, 3x Longhorn replicas, multi-replica every stateful service |
| **Fault Tolerance** | Pod anti-affinity across nodes/racks, PodDisruptionBudgets, automatic etcd/Longhorn self-healing |
| **Horizontal Scalability** | Stateless control plane + worker pool scales independently; storage and monitoring scale by adding nodes, not redesigning |
| **Security by Default** | Pod Security Standards, NetworkPolicies default-deny, mTLS where possible, signed images, runtime detection (Falco), SIEM (Wazuh) |
| **Observability** | Metrics (Prometheus), Logs (Loki), Infra/SNMP (Zabbix), Security events (Wazuh) — all converge in Grafana |
| **GitOps-driven Operations** | Git is the single source of truth; ArgoCD reconciles cluster state continuously |
| **Disaster Recovery** | 3-2-1 backup rule applied to etcd, PVs, and app config; tested restore runbooks, not just backups |

### 1.2 High-Level Enterprise Architecture (ASCII)

```
                                    ┌─────────────────────────┐
                                    │        INTERNET          │
                                    └────────────┬─────────────┘
                                                 │
                                    ┌────────────▼─────────────┐
                                    │   Perimeter Firewall     │  (FortiGate / pfSense pair, HA)
                                    │   IDS/IPS, WAF rules     │
                                    └────────────┬─────────────┘
                                                 │  VIP 10.10.10.10 (Keepalived VRRP)
                          ┌──────────────────────┼──────────────────────┐
                          │                                             │
                ┌─────────▼─────────┐                         ┌─────────▼─────────┐
                │   HAProxy-01      │◄──── VRRP heartbeat ───►│   HAProxy-02      │
                │   (MASTER)        │      (keepalived)       │   (BACKUP)        │
                └─────────┬─────────┘                         └─────────┬─────────┘
                          │                                             │
                          └───────────────────┬─────────────────────────┘
                                               │  TCP/6443 (API)  +  TCP/443,80 (Ingress)
                  ┌────────────────────────────┼────────────────────────────┐
                  │                            │                            │
         ┌─────────▼─────────┐       ┌─────────▼─────────┐       ┌─────────▼─────────┐
         │ Control Plane 1   │       │ Control Plane 2   │       │ Control Plane 3   │
         │ kube-apiserver    │       │ kube-apiserver    │       │ kube-apiserver    │
         │ scheduler/ctrlmgr │       │ scheduler/ctrlmgr │       │ scheduler/ctrlmgr │
         └─────────┬─────────┘       └─────────┬─────────┘       └─────────┬─────────┘
                   │                           │                           │
                   └─────────────┬─────────────┴─────────────┬─────────────┘
                                 │       External etcd (RAFT) │
                       ┌─────────▼────────┐  ┌────────▼───────┐  ┌────────▼───────┐
                       │   etcd-01        │  │   etcd-02      │  │   etcd-03      │
                       └──────────────────┘  └────────────────┘  └────────────────┘

                            Worker Node Pool (5 → N nodes, autoscaling-ready)
        ┌───────────┬───────────┬───────────┬───────────┬───────────┬─── … ───┐
        │ Worker-01 │ Worker-02 │ Worker-03 │ Worker-04 │ Worker-05 │   …     │
        │ Ingress   │ Ingress   │ App Pods  │ App Pods  │ Storage   │         │
        │ CNI/CSI   │ CNI/CSI   │ Longhorn  │ Longhorn  │ Longhorn  │         │
        └───────────┴───────────┴───────────┴───────────┴───────────┴─────────┘

   Cluster-wide platform services (run as Deployments/StatefulSets on the worker pool):
   Rancher (HA) · MetalLB · Traefik/Ingress · Cert-Manager · CoreDNS · Metrics-Server
   Prometheus/Grafana/Alertmanager/Loki · Wazuh Manager/Indexer/Dashboard · Falco · Kyverno
   GitLab Runner · ArgoCD · Harbor (or external)

   Out-of-cluster infrastructure tier (own VMs/hosts, NOT inside K8s):
   Zabbix Server + DB + Frontend + Proxies · GitLab (or SaaS) · Harbor Registry (HA pair)
```

### 1.3 Why some components live *outside* the cluster

A common mistake in "put everything in Kubernetes" designs is hosting the tools you'd need *to fix Kubernetes* **inside** Kubernetes. This design deliberately keeps a few systems external:

- **Zabbix** monitors physical hosts, switches, firewalls, UPS and the hypervisors that *run* your Kubernetes nodes — if it lived inside the cluster it couldn't tell you the cluster's host died.
- **GitLab / Harbor** can run in-cluster at smaller scale, but for 100+ developers and 500+ workloads, running these on dedicated VMs avoids them competing with production workloads for resources and avoids a chicken-and-egg problem during cluster disaster recovery (you need Harbor to pull images to *rebuild* the cluster).
- **HAProxy + Keepalived** sit in front of the cluster, not in it, because they're your path *into* the API server itself.

---

## 2. Kubernetes Cluster Design

### 2.1 Node Layout

| Role | Count | Naming convention | Purpose |
|---|---|---|---|
| Load Balancer | 2 | `lb-01`, `lb-02` | HAProxy + Keepalived, VRRP active/passive |
| Control Plane | 3 | `cp-01..03` | kube-apiserver, scheduler, controller-manager |
| External etcd | 3 | `etcd-01..03` | Dedicated etcd RAFT cluster (decoupled from control plane for clean DR) |
| Worker (general) | 3 | `wk-01..03` | Application workloads, ingress pods |
| Worker (storage-tagged) | 2 | `wk-storage-01..02` | Longhorn-heavy workloads, labeled `node-role=storage` |
| Infra/Bastion | 1–2 | `infra-01` | Zabbix, GitLab, Harbor, jump host (can be split across more VMs at scale) |

This matches the requested baseline (3 CP / 5 Worker / 3 etcd) while explicitly tagging 2 of the 5 workers for storage I/O, which matters a lot for Longhorn performance.

### 2.2 Why External etcd (vs. stacked)

| | Stacked etcd (on control plane) | **External etcd (this design)** |
|---|---|---|
| Node count | 3 | 6 (3 CP + 3 etcd) |
| Blast radius of a CP node failure | Loses both API and etcd vote simultaneously | API and etcd failures are independent — you can lose 1 CP node *and* 1 etcd node (different ones) and stay quorate |
| DR/backup | etcd snapshot tied to CP lifecycle | etcd cluster can be restored/rebuilt without touching control plane nodes |
| Recommended for | Small clusters, labs | **Production, 99.99% SLA targets** |

### 2.3 Hardware Specifications

| Node Role | vCPU | RAM | Disk (OS) | Disk (Data) | NIC | Qty |
|---|---|---|---|---|---|---|
| Load Balancer (HAProxy/Keepalived) | 4 | 8 GB | 100 GB SSD | — | 2× 10GbE (bonded) | 2 |
| Control Plane | 8 | 16 GB | 100 GB NVMe | — | 2× 10GbE (bonded) | 3 |
| External etcd | 4 | 8 GB | 100 GB **NVMe** (latency-sensitive) | — | 2× 10GbE | 3 |
| Worker (general) | 16 | 64 GB | 100 GB SSD | — | 2× 10GbE | 3 |
| Worker (storage) | 16 | 64 GB | 100 GB SSD (OS) | 4× 2 TB NVMe (Longhorn) | 2× 10GbE | 2 |
| Infra (Zabbix/GitLab/Harbor) | 8 | 32 GB | 100 GB SSD | 2 TB SSD | 2× 10GbE | 1–2 |

**Sizing notes:**
- etcd is **latency-sensitive, not throughput-heavy** — NVMe and a quiet, dedicated disk matter more than raw capacity. fsync latency above ~10ms causes leader election instability.
- Worker RAM/CPU above assumes general microservice workloads (~150–300 pods/node at moderate request sizes). Recalculate against your actual workload's average pod resource requests.
- 10GbE is specified because Longhorn replication traffic, etcd replication, and east-west pod traffic all share the fabric — 1GbE becomes the bottleneck well before 500 workloads.
- All node counts above are minimums for HA; see Section 20 for scaling math.

### 2.4 Core Cluster Add-ons

| Component | Purpose | HA notes |
|---|---|---|
| **CNI** (Calico recommended) | Pod networking + NetworkPolicy enforcement | Runs as DaemonSet — inherently HA per-node |
| **CoreDNS** | Cluster DNS | Minimum 2 replicas, anti-affinity, autoscaled via cluster-proportional-autoscaler |
| **Metrics Server** | Resource metrics for HPA/VPA | 2 replicas with leader election |
| **MetalLB** | LoadBalancer IPs for bare-metal | Layer2 mode for simplicity, or BGP mode if your TOR switches support it (recommended at 50+ nodes) |
| **Cert-Manager** | Automated TLS issuance/renewal | 1 replica is fine (CRD-based reconciliation, restarts cleanly) but use `--leader-election` ready manifests |

> **Kubernetes version recommendation:** As of mid-2026 the upstream supported (N-2) versions are **1.34, 1.35, 1.36**. For a new production build, this design recommends pinning to **1.35.x** — current enough to receive 12+ months of further patches, while skipping the "freshest minor" churn of 1.36. Re-validate this recommendation against the live support window at build time; Kubernetes ships a new minor roughly every 4 months.

---

## 3. Networking Architecture

### 3.1 Traffic Flow (request path)

```
Client
  │
  ▼
[1] Perimeter Firewall  ── stateful inspection, IPS, geo/IP ACLs
  │
  ▼
[2] Keepalived VIP (VRRP) ── single floating IP, owned by whichever HAProxy node is MASTER
  │
  ▼
[3] HAProxy (active node) ── TCP/HTTP load balancing, TLS passthrough or termination, health checks
  │
  ▼
[4] Ingress Controller (Traefik/NGINX) ── L7 routing by Host/Path, TLS termination, cert-manager-issued certs
  │
  ▼
[5] Kubernetes Service (ClusterIP) ── stable virtual IP, kube-proxy iptables/IPVS rules
  │
  ▼
[6] Pod (via Endpoints/EndpointSlice) ── actual application container
```

### 3.2 Failover Process — Step by Step

**Scenario: `lb-01` (HAProxy MASTER) dies.**

1. Keepalived on `lb-02` stops receiving VRRP advertisement packets from `lb-01` (default interval 1s).
2. After `dead_interval` (≈3× advertisement interval, configurable — typically 3–4 seconds) `lb-02` promotes itself to MASTER.
3. `lb-02` performs gratuitous ARP, claiming the VIP `10.10.10.10` on its own interface.
4. Upstream switches/routers update their ARP/MAC tables (sub-second on modern switches).
5. New connections now land on `lb-02`'s HAProxy instance, which already holds an identical config (synced via config management / GitOps) and independently health-checks all backend API servers and ingress nodes.
6. **In-flight TCP connections to the dead node are dropped** — this is why clients should retry idempotent requests, and why session state belongs in Redis/etcd, not in the LB or app pod itself.
7. Total observed downtime: **~3–6 seconds**, zero manual intervention.

### 3.3 Load Balancing Algorithm & Session Persistence

| Layer | Algorithm | Session persistence |
|---|---|---|
| HAProxy → kube-apiserver (6443) | `roundrobin` with `check` (TCP health check on 6443) | None needed — API server is stateless |
| HAProxy → Ingress (80/443) | `leastconn` (better under uneven request duration than roundrobin) | None at this layer — handled below |
| Ingress → Service | Controller-default (Traefik: weighted round robin; can switch to consistent-hashing) | **Cookie-based** (`stickiness.cookieName`) for stateful apps; prefer **stateless apps + external session store (Redis)** for true HA |
| Service → Pod | `iptables`/IPVS random or `ipvs rr` | N/A (Service is the abstraction boundary) |

### 3.4 Health Checks

| Check | Target | Method | Interval | Failure threshold |
|---|---|---|---|---|
| HAProxy → API server | `:6443/livez` | HTTPS GET | 2s | 3 consecutive fails |
| HAProxy → Ingress node | `:80/healthz` | HTTP GET | 2s | 3 consecutive fails |
| Keepalived → local HAProxy | local process/socket check via `track_script` | Script | 2s | 2 consecutive fails (triggers priority reduction → failover) |
| kubelet → Pod | Liveness/Readiness probes | HTTP/TCP/exec, app-defined | App-defined | App-defined |

### 3.5 VLAN Design & IP Addressing Plan

| VLAN ID | Purpose | Subnet (example) | Notes |
|---|---|---|---|
| 10 | Management/OOB (IPMI/iDRAC/iLO) | 10.10.10.0/24 | Isolated, jump-host only access |
| 20 | Kubernetes nodes (control plane, workers, etcd) | 10.10.20.0/23 | Allows 500+ host addresses for growth |
| 30 | Pod network (CNI overlay, e.g. Calico) | 10.244.0.0/16 | Internal only, never routed externally |
| 40 | Service network (ClusterIP range) | 10.96.0.0/12 | Internal only |
| 50 | MetalLB address pool | 10.10.50.0/24 | Externally routable LB IPs |
| 60 | Storage replication (Longhorn east-west traffic) | 10.10.60.0/24 | Dedicated NIC/VLAN recommended to isolate replication I/O from app traffic |
| 70 | Infra services (Zabbix, GitLab, Harbor) | 10.10.70.0/24 | |
| 80 | DMZ / Load balancer front-end | 10.10.80.0/28 | Faces the firewall, smallest possible subnet |

### 3.6 Firewall Rules (representative set)

| Source | Destination | Port/Proto | Purpose |
|---|---|---|---|
| Internet | VIP (VLAN 80) | 443/tcp | Public HTTPS ingress |
| LB nodes | Control plane nodes | 6443/tcp | API proxying |
| Control plane | etcd nodes | 2379-2380/tcp | etcd client + peer |
| Control plane | Worker nodes | 10250/tcp | kubelet API |
| Worker nodes | Worker nodes | All CNI overlay ports (e.g., Calico: 179/tcp BGP, 4789/udp VXLAN) | Pod-to-pod networking |
| Storage VLAN (internal only) | Storage VLAN | 9500-9504/tcp (Longhorn engine/replica) | Replication traffic |
| Admin jump host | All VLANs (mgmt only) | 22/tcp, IPMI | Break-glass admin access |
| Worker nodes | Zabbix proxy | 10050,10051/tcp | Agent → proxy reporting |
| Cluster nodes | DNS/NTP/Harbor | 53/udp, 123/udp, 443/tcp | Resolution, time sync, image pulls |
| **Default** | **Default** | **DENY ALL** | Explicit allow-list only — zero trust posture |


---

## 4. Security Architecture

### 4.1 Defense-in-Depth Layers

```
 Layer 1: Perimeter        Firewall, IPS, WAF, geo-blocking
 Layer 2: Network          NetworkPolicies (default-deny), VLAN segmentation, mTLS (service mesh optional)
 Layer 3: Cluster Admission Kyverno policies, Pod Security Standards, OPA-style validation
 Layer 4: Workload          Image signing (Cosign), Trivy scanning in CI, non-root/read-only-fs enforcement
 Layer 5: Runtime            Falco syscall detection, Wazuh FIM/rootkit/active-response
 Layer 6: Identity            RBAC, LDAP/AD-backed SSO, MFA everywhere
 Layer 7: Data                 Secrets encryption at rest (etcd), TLS everywhere in transit, Longhorn volume encryption
 Layer 8: Audit                  Kubernetes audit logs → Loki/Wazuh, immutable retention
```

### 4.2 Wazuh (SIEM / XDR) Architecture

| Component | Role | HA Pattern |
|---|---|---|
| Wazuh Manager | Rule correlation, agent management, active response | Cluster mode (master + worker nodes) — Wazuh 4.x supports clustering for HA |
| Wazuh Indexer | Stores/searches alerts (OpenSearch-based) | 3-node indexer cluster, replica shards = 1 minimum |
| Wazuh Dashboard | Web UI (OpenSearch Dashboards-based) | 2+ replicas behind the ingress/LB |
| Wazuh Agents | FIM, rootkit detection, vulnerability detection, log collection, active response | One per Kubernetes node (DaemonSet or host-installed) **plus** every monitored endpoint outside the cluster (up to 5,000+) |

**Capability mapping:**

| Requirement | Wazuh feature used |
|---|---|
| File Integrity Monitoring | `syscheck` module, real-time + scheduled scans |
| Rootkit Detection | `rootcheck` module |
| Vulnerability Detection | Vulnerability Detector module (CVE feed correlation against installed packages) |
| Log Collection | `logcollector` — ingests syslog, Windows Event Log, application logs, **and Kubernetes/audit logs via integration** |
| Active Response | Scripted automated response (e.g., firewall-drop, account-lock) triggered by rule matches |

At 5,000+ endpoints, **do not run a single Wazuh manager** — deploy a manager cluster with regional **Wazuh proxies** to reduce WAN chatter, matching how Zabbix proxies are used below for the same reason.

### 4.3 Runtime & Supply-Chain Security

| Tool | Function | Where it runs |
|---|---|---|
| **Falco** | eBPF/kernel-level syscall monitoring — detects shell-in-container, unexpected outbound connections, privilege escalation in real time | DaemonSet, every node |
| **Trivy** | Container image + IaC + SBOM vulnerability scanning | CI pipeline (blocks build on critical CVEs) + scheduled in-cluster scans via Trivy Operator |
| **Kyverno** | Policy-as-code admission control (no images from untrusted registries, mandatory resource limits, disallow `:latest` tag, require non-root) | ValidatingAdmissionPolicy / Kyverno admission webhook |
| **Cosign** (recommended addition) | Image signing + verification | CI signs, Kyverno's `verifyImages` policy enforces signature presence before scheduling |

### 4.4 Network Policy Model

- **Default-deny** NetworkPolicy applied to every namespace on creation (enforced via Kyverno policy that auto-generates one, so teams can't "forget" it).
- Explicit allow rules per app: namespace-scoped ingress/egress, label-selector based.
- DNS (port 53 to CoreDNS) and the monitoring namespace (for scraping) are the only cluster-wide exceptions.

### 4.5 RBAC & Pod Security Standards

| Tier | Pod Security Standard | Typical namespace |
|---|---|---|
| Platform/system | `privileged` | `kube-system`, `longhorn-system`, `calico-system` |
| Security tooling | `baseline` (Falco/Wazuh need elevated host access but not full privileged) | `security`, `wazuh` |
| Application workloads | `restricted` (non-root, no privilege escalation, dropped capabilities) | `app-*` namespaces |

RBAC follows least-privilege, role-per-team, bound via Groups synced from LDAP/AD (Section 4.6) — never bind roles to individual user accounts directly.

### 4.6 Identity, MFA & Secrets

- **LDAP/Active Directory integration**: Rancher, GitLab, Grafana, Wazuh Dashboard, and Zabbix Frontend all bind to the same central AD/LDAP, with **group-based** RBAC mapping (e.g., `cn=k8s-admins` → Rancher cluster-admin).
- **MFA**: Enforced at the AD/IdP level (TOTP or hardware token) so it covers every downstream tool through SSO/SAML rather than configuring MFA per-tool.
- **Secrets management**: Kubernetes Secrets are encrypted at rest in etcd (`EncryptionConfiguration` with `aescbc` or `kms` provider). For 100+ developers, layer **HashiCorp Vault** or **External Secrets Operator** on top so secrets never live as plain base64 in Git or in raw `kubectl get secret` output.
- **TLS everywhere**: cert-manager issues/rotates certs for ingress; internal east-west mTLS is the job of a service mesh (Linkerd is the lighter-weight CNCF option if you want this — see Section 22 alternatives) — **note this is an addition beyond the literal component list you specified**, flagged here because "TLS Everywhere" without a mesh only covers ingress, not pod-to-pod.

### 4.7 CIS Kubernetes Benchmark & Zero Trust

- Run **kube-bench** as a scheduled Job against every node role (control plane / etcd / worker profiles differ).
- Zero Trust principles applied: no implicit trust by network location — every hop (LB→Ingress→Service→Pod, and Pod→Pod) is policy-gated; identity (RBAC/service accounts) is checked at every layer, not just the perimeter.

---

## 5. Ingress Architecture & the ingress-nginx Retirement

### 5.1 What changed

Upstream **ingress-nginx was retired by Kubernetes SIG Network and the Security Response Committee on March 24, 2026.** No further releases, bugfixes, or CVE patches will be issued. Existing deployments keep running, but every new CVE found from that date forward will go unpatched. Rancher's RKE2 distribution now ships **Traefik as the default ingress controller** for new clusters as of v1.36; the `rke2-images-ingress-nginx` artifact will be fully removed for community users in v1.37.

### 5.2 Recommendation for this design

| Option | Verdict |
|---|---|
| **Traefik** | **Recommended.** Actively maintained, CNCF project, native Kubernetes CRDs (IngressRoute), built-in Let's-Encrypt/cert-manager integration, now the RKE2 default — least friction with the Rancher stack you've specified. |
| **NGINX Ingress (as originally requested)** | Documented and supported here as a **legacy/transition option only**. If your org has existing NGINX Ingress annotations/configs you can't migrate immediately, keep it air-gapped from the internet-facing path and plan migration within 6–12 months. |
| **Gateway API + any compliant controller** | The longer-term strategic direction from upstream Kubernetes itself. Worth piloting in a non-prod cluster now if you're building greenfield. |

### 5.3 Ingress Layer Responsibilities

- TLS termination (certs from cert-manager, auto-renewed)
- Host/path-based routing to Services
- Rate limiting, request size limits, WAF-style middleware (Traefik middlewares or NGINX annotations)
- Canary/weighted routing for progressive delivery (pairs well with ArgoCD/Argo Rollouts)

---

## 6. Monitoring Architecture (Prometheus / Grafana)

### 6.1 Component Map

```
              ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
              │ node-exporter │      │kube-state-   │      │   cAdvisor    │
              │ (DaemonSet)   │      │metrics        │      │ (kubelet)     │
              └──────┬───────┘      └──────┬───────┘      └──────┬───────┘
                     │                     │                     │
                     └──────────┬──────────┴──────────┬──────────┘
                                │  scrape (15-30s)     │
                       ┌────────▼──────────────────────▼────────┐
                       │     Prometheus (2 replicas, HA pair)     │
                       │     + Thanos/Cortex for long-term store  │  (recommended addition for 99.99% SLA)
                       └────────┬─────────────────────┬──────────┘
                                │ alerts                │ query
                       ┌────────▼────────┐    ┌─────────▼─────────┐
                       │  Alertmanager    │    │      Grafana        │
                       │  (cluster mode,  │    │  (2+ replicas,       │
                       │   3 replicas)    │    │   shared Postgres    │
                       └────────┬────────┘    │   for dashboards/DB)  │
                                │              └─────────────────────┘
                       ┌────────▼────────┐
                       │ PagerDuty/Slack/  │
                       │ Email/Webhook     │
                       └──────────────────┘
```

### 6.2 Why Prometheus HA needs a caveat

Plain Prometheus is **not naturally HA for historical data** — two replicas scrape independently and each holds its own local TSDB. For a 99.99% SLA platform with 500+ workloads, this design recommends adding **Thanos** (sidecar + query + store-gateway) or **Mimir/Cortex** so that:
- Long-term metrics survive any single Prometheus replica's local disk loss
- A single Grafana query pane can deduplicate across both replicas
- Retention can extend past local-disk limits using object storage (e.g., MinIO, which can itself run on Longhorn)

### 6.3 Alertmanager Clustering

Alertmanager replicas gossip over a mesh (`--cluster.peer` flags) so that deduplication and silence state are shared — alerts aren't duplicated 3x just because you have 3 replicas.

### 6.4 Required Grafana Dashboards

| Dashboard | Key panels |
|---|---|
| Kubernetes Cluster Health | Node count/status, API server latency (p50/p99), etcd leader changes, control plane component health |
| Node Monitoring | CPU/mem/disk/load per node, kernel version drift, NTP sync status |
| Pod Monitoring | Restart counts, OOMKilled events, CrashLoopBackOff rate, resource requests vs. limits vs. actual |
| CPU Usage | Per-node, per-namespace, per-workload, throttling (`container_cpu_cfs_throttled_periods_total`) |
| Memory Usage | Per-node, per-namespace, working set vs. limit, OOM events |
| Disk Usage | Node root/disk pressure, PVC usage %, inode exhaustion |
| Network Traffic | Per-node ingress/egress bandwidth, pod-to-pod top talkers, CNI errors |
| Longhorn Storage | Volume health, replica rebuild status, degraded volumes, disk space per storage node |
| HAProxy | Backend health, request rate, error rate (4xx/5xx), queue depth, session count |
| Wazuh Metrics | Alert volume by severity, agent connectivity status, FIM event rate, active-response trigger count |

### 6.5 Loki & Promtail (bridges to Section 8)

Loki and Promtail are listed under both Monitoring and Logging in the original requirements — architecturally they belong to the **logging pipeline** (Section 8), but their query interface lives inside **Grafana**, which is why they're cross-referenced here. Treat Grafana as the single observability pane: metrics (Prometheus/Thanos), logs (Loki), and — via the data source plugin — Zabbix and Wazuh data, all in one UI.

---

## 7. Infrastructure Monitoring (Zabbix) & Grafana Integration

### 7.1 Why Zabbix runs *alongside*, not *instead of*, Prometheus

Prometheus excels at **cloud-native, ephemeral, label-based** monitoring (pods, containers, Kubernetes objects). Zabbix excels at **persistent infrastructure**: physical servers' hardware health (via IPMI), switches, routers, firewalls, and UPS units via **SNMP** — things that don't have a `/metrics` endpoint and never will. Using Zabbix for what it's good at avoids reinventing SNMP polling, trap handling, and template libraries that Zabbix has spent two decades building.

### 7.2 Zabbix Component Architecture

```
                         ┌─────────────────────┐
                         │   Zabbix Frontend     │  (PHP, behind the ingress/LB, LDAP-bound)
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Zabbix Server        │  (active checks, trigger evaluation, HA pair via
                         │   (HA: server + standby)│   Zabbix's native HA feature, 6.0+)
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │   Zabbix Database      │  (PostgreSQL/MySQL, primary+replica or
                         │   (PostgreSQL recomm.) │   Patroni-managed cluster for HA)
                         └──────────────────────┘
                                    ▲
              ┌─────────────────────┼─────────────────────┐
   ┌──────────┴─────────┐ ┌─────────┴──────────┐ ┌────────┴───────────┐
   │  Zabbix Proxy (DC-A) │ │ Zabbix Proxy (DC-B) │ │ Zabbix Proxy (Branch)│
   └──────────┬──────────┘ └─────────┬──────────┘ └────────┬───────────┘
              │                      │                      │
      Agents / SNMP            Agents / SNMP            Agents / SNMP
   (servers, VMs, switches, firewalls, storage arrays, UPS, routers)
```

**Why proxies matter at this scale**: a single Zabbix server polling thousands of devices directly creates a thundering-herd problem and a WAN/latency bottleneck for remote sites. Proxies buffer and locally poll, then forward to the server in batches — this is the same architectural reasoning as Wazuh's manager/proxy split above.

### 7.3 What Zabbix Monitors Here

| Target | Method |
|---|---|
| Physical servers (the bare metal under your K8s nodes) | Zabbix Agent2 + IPMI sensor checks (temp, fan, PSU) |
| Hypervisors (if nodes are VMs) | Agent + hypervisor API templates (vCenter/Proxmox) |
| Network switches/routers | SNMP v3 (encrypted) polling + traps |
| Firewalls (e.g., FortiGate) | SNMP + Fortinet-specific Zabbix template, or syslog correlation |
| Storage arrays / SAN | SNMP or vendor API template |
| UPS | SNMP (battery charge, runtime remaining, load %) |

### 7.4 Zabbix → Grafana Integration

Two supported integration paths:
1. **Grafana Zabbix data source plugin** — query Zabbix items/triggers directly as a Grafana panel, placed alongside Prometheus/Loki panels on the same dashboard.
2. **Zabbix webhook → Alertmanager-compatible webhook receiver**, so Zabbix triggers fire into the *same* Alertmanager routing tree (Slack/PagerDuty/Email) used for Kubernetes alerts — giving on-call staff one alert funnel instead of two.

This design recommends **both**: dashboards for visualization, webhook for unified alert routing.

---

## 8. Logging Architecture (Loki/Promtail Pipeline)

### 8.1 Complete Pipeline

```
 Source                        Collector              Aggregator         Storage              Query/View
 ───────────────────────────────────────────────────────────────────────────────────────────────────────
 Container stdout/stderr  ──►  Promtail (DaemonSet) ──┐
 Kubernetes audit logs    ──►  Promtail / Fluent-bit ─┤
 HAProxy logs (syslog)    ──►  Promtail (syslog scrape)┤──► Loki (distributor → ingester →    ──► Grafana
 Rancher server logs      ──►  Promtail                │     compactor)  ──► Object storage    ──► (Explore /
 Wazuh manager/agent logs ──►  Promtail + Wazuh's own  │     (S3-compatible / MinIO-on-Longhorn) │  Dashboards)
                                indexer (dual path)    │
 etcd/control-plane logs  ──►  Promtail (static pod    │
                                log paths on host)     │
                                                        └──────────────────────────────────────────────
```

### 8.2 Labeling Strategy

Loki indexes only **labels**, not full log content (unlike Elasticsearch) — keep label cardinality low and deliberate:

| Label | Example | Why |
|---|---|---|
| `namespace` | `app-billing` | Primary filter axis |
| `pod` | `billing-7f9c-xk2m` | Drill-down |
| `node` | `wk-03` | Correlate with node-level incidents |
| `app` | `billing-api` | Cross-pod-restart continuity |
| `log_type` | `audit`, `app`, `haproxy`, `wazuh` | Source routing/retention policy per type |

### 8.3 Audit Logging

Kubernetes API server audit logs (`--audit-log-path`, `--audit-policy-file`) are written to each control plane node's local disk, then shipped by Promtail with `log_type=audit`. Audit logs get a **longer, immutable retention** (often a compliance requirement, e.g., 1 year) — store these in a separate Loki retention policy / separate object storage bucket with object-lock if your compliance framework (ISO 27001 A.8.15 logging) requires tamper-evidence.

### 8.4 Retention Policy

| Log type | Hot (Loki, queryable) | Cold (object storage) | Notes |
|---|---|---|---|
| Application logs | 30 days | 90 days | Tune per app criticality |
| HAProxy/Ingress access logs | 30 days | 180 days | Useful for security investigation |
| Audit logs | 90 days | 1 year+ | Compliance-driven, often immutable |
| Wazuh alerts | Lives in Wazuh Indexer, not Loki | Indexer ILM snapshots to object storage | Kept separate — Wazuh's own indexer is the system of record for security alerts; Loki is for general-purpose log search |

---

## 9. Storage Architecture (Longhorn)

### 9.1 Replication Model

```
            Volume "pvc-app-db"  (Replication Factor = 3)
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   Replica A       Replica B       Replica C
  (wk-storage-01) (wk-storage-02) (wk-04)
        │              │              │
        └──────────────┴──────────────┘
                  Synchronous write
         (write acknowledged only after quorum of
          replicas confirm — default: all healthy replicas)
```

- **Replication Factor 3**: tolerates loss of any 2 of 3 replicas without data loss; a single node failure (1 replica down) triggers automatic rebuild onto a healthy node with zero manual action.
- **Automatic recovery**: Longhorn's instance-manager detects a dead replica, schedules a rebuild on another eligible node (respecting the storage-tagged worker labels from Section 2.1), and resyncs from the surviving replicas.
- **Volume snapshots**: point-in-time, copy-on-write, stored on the same backing disks — fast, but not a substitute for off-cluster backup.
- **Backup scheduling**: Longhorn `RecurringJob` CRDs define snapshot + backup cadence (e.g., snapshot hourly, backup to S3/NFS target every 6 hours, retain 7 daily + 4 weekly).
- **Restore procedures**: restore from backup target creates a new volume from the chosen backup point; for full-cluster DR, Longhorn backups stored in **off-cluster** object storage (not just local snapshots) are what actually survive a total cluster loss.

### 9.2 Storage Node Placement

Use node labels + Longhorn's node/disk scheduling so replicas spread across **failure domains**, not just nodes:

```yaml
# Example: tag storage-capable nodes
kubectl label node wk-storage-01 node-role.kubernetes.io/storage=true
kubectl label node wk-storage-02 node-role.kubernetes.io/storage=true
kubectl label node wk-04          node-role.kubernetes.io/storage=true   # 3rd replica target
```

If your 3 storage-eligible nodes sit in 3 different racks/PDUs, you get genuine fault-domain isolation — replicating 3x onto 3 nodes in the same rack on the same PDU defeats much of the purpose.

### 9.3 Performance Considerations

- Dedicate a VLAN (Section 3.5, VLAN 60) to replication traffic so storage I/O doesn't compete with application traffic on the same NIC.
- NVMe strongly preferred over SATA SSD for the storage-tagged workers — Longhorn's synchronous replication amplifies write latency from slow disks across all 3 replicas.
- Monitor replica rebuild time after any node failure (Grafana Longhorn dashboard, Section 6.4) — long rebuild windows mean longer exposure to "degraded" (RF effectively 2) state.

---

## 10. Rancher Management Architecture

### 10.1 HA Deployment Model

Rancher runs as a Deployment **inside** the Kubernetes cluster it manages (the "local" cluster), with ≥3 replicas spread across control-plane-adjacent worker nodes, fronted by the same Ingress/LB path as everything else. Rancher itself stores its state in the cluster's etcd (via CRDs) — meaning **Rancher HA is downstream of cluster/etcd HA**, not a separate concern.

| Aspect | Implementation |
|---|---|
| User Authentication | LDAP/AD or SAML/OIDC connector configured in Rancher's Auth Provider settings; local admin account disabled after setup except as break-glass |
| RBAC | Rancher's Cluster/Project-level roles map onto Kubernetes RBAC under the hood — define custom roles aligned to your org chart (e.g., "namespace-viewer", "billing-team-admin") |
| Multi-cluster Management | Rancher's "local" cluster manages N "downstream" clusters via the Rancher agent — useful if you later split dev/staging/prod into separate physical clusters |
| Cluster Import | Existing clusters (e.g., a staging cluster built without Rancher) are imported via a generated registration manifest — no need to rebuild from scratch |
| Backup | `rancher-backup` operator — CRD-driven backups of Rancher's resources to S3/NFS target, **independent of the underlying cluster's etcd snapshot** |
| Upgrade Strategy | Helm-based upgrade (`helm upgrade rancher rancher-stable/rancher`), always preceded by a `rancher-backup` snapshot; follow Rancher's documented N→N+1 minor-version-only upgrade path (no skipping minors) |

### 10.2 Current Version Note

As of mid-2026 the current stable Rancher line is **v2.14.x**. Validate against `https://github.com/rancher/rancher/releases` at build time — Rancher ships frequent patch releases.

---

## 11. High Availability Design & Failover Scenarios

### 11.1 HA Mechanism Per Component

| Component | HA Mechanism | Minimum replicas |
|---|---|---|
| kube-apiserver | Stateless, fronted by HAProxy; any CP node can serve any request | 3 |
| etcd | RAFT consensus, requires quorum `⌈(n/2)+1⌉` | 3 (tolerates 1 failure) |
| HAProxy | Active/passive via Keepalived VRRP | 2 |
| Keepalived | VRRP protocol itself *is* the HA mechanism | 2 (paired with HAProxy) |
| Rancher | Multiple Deployment replicas behind Ingress, state in cluster etcd | 3 |
| Wazuh Manager | Native clustering (master + worker manager nodes) | 2+ (1 master, 1+ worker) |
| Wazuh Indexer | OpenSearch-style cluster, replica shards | 3 |
| Grafana | Stateless app replicas + shared Postgres backend for dashboards/users | 2 |
| Zabbix Server | Native HA (server + standby, 6.0+) | 2 |
| Prometheus | 2 independent replicas + Thanos for unified long-term view | 2 |
| Longhorn | Volume-level replication (RF3), control-plane (longhorn-manager) is a DaemonSet | RF=3, manager=all nodes |

### 11.2 Failover Scenarios — Step by Step

**A. Control plane node failure (`cp-02` dies)**
1. HAProxy health check to `cp-02:6443` fails 3 consecutive times → HAProxy marks backend DOWN, stops routing new API traffic there.
2. `cp-01` and `cp-03` continue serving API requests — etcd quorum (3 nodes, separate from CP) is unaffected.
3. Kubernetes controller-manager/scheduler use leader election — if the dead leader was on `cp-02`, a new leader is elected on `cp-01` or `cp-03` within the lease timeout (default ~15s).
4. **Impact**: Brief (~15s) pause in *new* scheduling decisions; already-running pods are completely unaffected. Zero API downtime (HAProxy already rerouted).
5. Remediation: replace/repair `cp-02`, rejoin with `kubeadm join --control-plane`, or restore from golden image.

**B. etcd node failure (`etcd-02` dies)**
1. RAFT cluster of 3 drops to 2 — **still quorate** (2 of 3 = majority).
2. Writes continue normally; no API disruption.
3. **Critical**: if a *second* etcd node fails before `etcd-02` is repaired, the cluster loses quorum and the API server goes **read-only** then fully unavailable. This is why etcd member repair is the highest-priority page in this design.
4. Remediation: bring `etcd-02` back online (same identity) → automatic rejoin; or formally remove + add a new member if the disk is unrecoverable.

**C. Worker node failure**
1. kube-controller-manager's node lifecycle controller marks the node `NotReady` after `--node-monitor-grace-period` (default 40s).
2. After the pod eviction timeout (default 5 min, tune lower for critical apps), pods are evicted and rescheduled onto healthy workers.
3. Longhorn detects replicas on the dead node, schedules rebuilds on the remaining storage-tagged nodes (Section 9.1).
4. **Impact**: ~5 minute pod rescheduling delay by default — for tighter SLAs, lower `--pod-eviction-timeout` and rely on PodDisruptionBudgets + readiness probes to keep user-facing impact near-zero via existing replica pods on other nodes absorbing traffic immediately (Service-level failover is near-instant; it's *new* pod placement that takes the ~5 min).

**D. HAProxy/Keepalived failure** — see Section 3.2 (3–6 second VIP failover).

**E. Rancher failure**
1. If 1 of 3 Rancher pods dies, Kubernetes simply reschedules it — Ingress already load-balances across the survivors, near-zero impact.
2. If the **entire local cluster** is down, Rancher (which runs inside it) is down too — this is why Rancher backup (Section 10.1) and full cluster DR (Section 12) are the real safety net, not Rancher's own pod replication.

**F. Wazuh / Zabbix failure**
- Both are designed so an outage means **you temporarily lose visibility, not production traffic** — neither sits on the request path. Treat their HA as protecting *detection capability* (you don't want a blind spot exactly when something goes wrong), prioritized just below the request-path components.

---

## 12. Disaster Recovery

### 12.1 RTO / RPO by Failure Type

| Failure Scenario | RTO (Recovery Time Objective) | RPO (Recovery Point Objective) | Recovery Method |
|---|---|---|---|
| Complete node failure (any single node) | < 10 min (automatic) | 0 (no data loss — replicated state) | Auto-reschedule + Longhorn rebuild |
| Control plane (master) node failure | < 1 min (automatic failover) | 0 | HAProxy reroute + leader election |
| Worker node failure | < 5 min (automatic) | 0 | Pod eviction + reschedule + Longhorn rebuild |
| Storage (Longhorn) failure, single replica | < 15 min (automatic rebuild, depends on volume size) | 0 | Auto-rebuild from healthy replicas |
| Storage failure, RF fully exhausted (rare, 3 simultaneous node loss) | 1–4 hrs (manual) | Up to last backup interval (e.g., 6 hrs) | Restore from off-cluster backup target |
| etcd corruption (single member) | < 15 min (automatic rejoin) | 0 | Member replace/rejoin |
| etcd quorum loss (2+ members down) | 1–2 hrs (manual) | Time since last etcd snapshot (target: 15 min snapshot interval) | Restore from etcd snapshot, rebuild quorum |
| HAProxy/Keepalived failure (1 node) | < 10 sec (automatic) | 0 | VRRP failover |
| HAProxy/Keepalived failure (both nodes) | 30–60 min (manual rebuild) | 0 (config is GitOps-managed, redeployed from Git) | Rebuild from IaC/config management |
| Rancher failure (pods only) | < 2 min (automatic) | 0 | K8s reschedule |
| Rancher failure (full local cluster loss) | Tied to full cluster DR below | Last `rancher-backup` snapshot | Restore cluster, then restore Rancher backup |
| Wazuh failure (manager/indexer node) | 30 min (manual, or automatic if clustered) | Last indexer snapshot | Cluster failover or restore from snapshot |
| Zabbix failure (server) | 15–30 min (manual or native HA failover) | Last DB backup/replica lag | Native HA failover or DB restore |
| **Complete site/cluster loss** | 4–8 hrs (full rebuild) | Last off-cluster backup (etcd snapshot + Longhorn backups + Git state) | Full DR runbook (12.2) |

### 12.2 Full Cluster DR Runbook (Summary)

1. Provision replacement hardware/VMs (or pre-staged DR site).
2. Restore networking (VLANs, firewall rules, DNS) from IaC.
3. Restore etcd from the most recent snapshot → bootstrap new control plane pointing at restored etcd.
4. Rejoin/rebuild worker nodes.
5. Re-deploy platform services via GitOps (ArgoCD points at Git — this step is largely automatic once ArgoCD itself is back up, which is itself just another Helm install pointed at the same Git repo).
6. Restore Longhorn volumes from off-cluster backup target for any data not already replicated/migrated.
7. Restore Rancher via `rancher-backup` restore.
8. Validate: run the production deployment checklist (Section 17) against the recovered environment before reopening to traffic.
9. Post-incident: update the runbook with any deviation encountered — DR runbooks rot if untested; **schedule a DR drill at minimum quarterly.**

### 12.3 The 3-2-1 Rule Applied

- **3** copies of critical data: live (Longhorn replicas) + on-cluster snapshot + off-cluster backup.
- **2** different media/locations: local NVMe (live) + remote object storage (backup).
- **1** copy off-site: backup target physically/logically separate from the cluster's own infrastructure (different power/network domain at minimum; different physical site ideally).

---

## 13. CI/CD & GitOps

### 13.1 Deployment Flow

```
 Developer                GitLab               CI Pipeline            Harbor              ArgoCD              Kubernetes
 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 git push          ──►   GitLab repo    ──►   GitLab Runner job:  ──►  Push image  ──►  ArgoCD detects   ──►  Sync applied
 (feature branch,        receives commit,      - lint/test            (tagged,         new image tag       to cluster:
  MR opened)              triggers pipeline      - build image          Trivy-scanned)    OR new manifest      Deployment/
                                                 - Trivy scan                              commit in the        Service/etc.
                                                 - push to Harbor                          GitOps repo,         reconciled
                                                 - update GitOps repo                      auto-syncs           to match Git
                                                   manifest/Helm                           (or requires
                                                   values with new                          manual approval
                                                   image tag                                for prod)
```

### 13.2 GitOps Principles Applied

- **Git is the single source of truth.** The application source repo (code) and the GitOps repo (declarative manifests/Helm values) are typically **separate repos** — CI writes to the GitOps repo on successful build, it never `kubectl apply`s directly.
- **ArgoCD continuously reconciles.** It doesn't just deploy once — it watches Git and the live cluster state, alerting (and optionally self-healing) on drift. Someone running `kubectl edit` directly on a prod Deployment gets silently reverted (by design) — all changes go through Git.
- **Progressive promotion**: dev auto-syncs on every merge; staging requires passing smoke tests; production requires manual approval (ArgoCD sync-wave / manual sync policy) — this is a deliberate gate, not a Git limitation.
- **Helm + ArgoCD**: Helm charts define *what* an app looks like (templated manifests); ArgoCD Application CRDs define *which* chart + values go to *which* cluster/namespace, tracked declaratively itself in Git ("app of apps" pattern).

### 13.3 Harbor Registry

- Deployed as an HA pair (or backed by external object storage with Harbor itself stateless behind a 2-replica frontend) — Harbor is the trust boundary: only images that passed Trivy scanning and (if using Cosign) signature verification get pulled into production.
- Image retention/garbage-collection policy needed at 100+ developers scale, or storage grows unbounded.
- Robot accounts (not personal credentials) used for CI → Harbor push and Kubernetes → Harbor pull.

### 13.4 GitLab Runner Scaling

- Use the **Kubernetes executor** for GitLab Runner so build jobs themselves run as ephemeral pods in a dedicated `ci` namespace — this scales build capacity with the cluster rather than fixed VM-based runners, and keeps build workloads isolated (resource quotas, NetworkPolicy) from production namespaces.

---

## 14. Backup Strategy

| System | What's backed up | Tool/Method | Schedule | Retention |
|---|---|---|---|---|
| etcd | Full keyspace snapshot | `etcdctl snapshot save` (cron on one etcd member, copied off-node immediately) | Every 15 min (continuous-ish) + pre-upgrade snapshot | 7 days hot, 30 days cold |
| Longhorn volumes | Application PV data | Longhorn `RecurringJob` → backup target (S3/NFS) | Snapshot hourly, backup every 6 hrs | 7 daily, 4 weekly, 3 monthly |
| Rancher | CRDs, cluster registrations, settings | `rancher-backup` operator | Daily + pre-upgrade | 14 days |
| Wazuh | Indexer data, manager rules/config | OpenSearch snapshot API + config repo (rules-as-code in Git) | Indexer: daily snapshot; config: every Git commit | 30 days indexer, indefinite for Git config |
| Grafana | Dashboards, datasources, users | Postgres backend dump (if dashboards aren't fully provisioned-as-code already) | Daily | 30 days |
| Prometheus | Metrics TSDB | Generally **not** snapshot-backed directly — rely on Thanos object-storage retention instead (Section 6.2) | Continuous (Thanos upload) | Per retention policy (e.g., 13 months for capacity planning) |
| Zabbix | Configuration + historical data DB | PostgreSQL/MySQL dump or streaming replica | Daily full + continuous replication | 30 days |
| Kubernetes manifests | All cluster object definitions | Already in Git (GitOps) — this *is* the backup; supplement with `velero` for full namespace/object snapshots including non-GitOps resources | Velero: daily | 30 days |

**General rule applied throughout**: anything that's already declared in Git (manifests, Helm values, Wazuh rules-as-code) doesn't need a separate backup system — Git *is* the backup, and restoring it is just "re-run ArgoCD sync." Backup tooling is reserved for things Git can't represent: live database state, etcd's actual key-value store, and binary volume data.

---

## 15. DNS, Naming Convention & Certificate Management

### 15.1 Domain Naming Convention

```
 <service>.<environment>.<cluster>.k8s.<company>.internal      (internal-only services)
 <service>.<company>.com                                        (public-facing services)

 Examples:
   rancher.prod.cluster1.k8s.acme.internal
   grafana.prod.cluster1.k8s.acme.internal
   api.acme.com                                                   (public app)
   wazuh.prod.cluster1.k8s.acme.internal
```

### 15.2 DNS Architecture

```
 Internal clients ──► Internal DNS (AD-integrated, e.g., Windows DNS or BIND) ──► forwards *.k8s.*.internal
                                                                                    to CoreDNS-exposed zone
                                                                                    OR static A records → VIP
 External clients ──► Public DNS (registrar/Cloudflare/Route53) ──► A/AAAA record → public-facing VIP/LB
```

CoreDNS inside the cluster handles **pod/service** resolution (`*.svc.cluster.local`); it is **not** the same DNS layer that resolves `rancher.prod...internal` for human users — that's your internal corporate DNS, with a delegated zone or static records pointing at the ingress VIP.

### 15.3 Certificate Management

| Cert type | Issuer | Renewal |
|---|---|---|
| Public-facing ingress TLS | cert-manager + Let's Encrypt (`ClusterIssuer`, HTTP-01 or DNS-01 challenge) | Automatic, ~60 days before 90-day expiry |
| Internal-only services | cert-manager + private CA (`CA Issuer`, e.g., your own root CA imported as a Secret) | Automatic |
| etcd peer/client certs | kubeadm-managed or manual PKI, 1-year+ validity | Manual rotation reminder (kubeadm has `kubeadm certs renew`) — automate via cron + alert |
| kubelet serving certs | Kubernetes built-in certificate rotation (`--rotate-certificates`) | Automatic |

---

## 16. Implementation Roadmap

| Phase | Duration (typical) | Deliverables |
|---|---|---|
| **0 — Planning** | 1–2 weeks | Hardware procurement, IP/VLAN plan finalized, DNS zones created, naming convention agreed, AD/LDAP groups pre-created |
| **1 — Foundation** | 1 week | OS provisioned on all nodes, networking (VLANs, bonding) configured, firewall rules applied, NTP/DNS resolution verified cluster-wide |
| **2 — Core Cluster** | 1 week | etcd cluster bootstrapped, control plane joined, HAProxy/Keepalived VIP live, workers joined, CNI installed, cluster passes `kubectl get nodes` all-Ready |
| **3 — Platform Add-ons** | 1 week | MetalLB, Ingress (Traefik), cert-manager, CoreDNS tuning, metrics-server, Longhorn installed and volume test passed |
| **4 — Management Layer** | 1 week | Rancher HA deployed, LDAP/AD auth wired in, RBAC roles defined |
| **5 — Observability** | 1–2 weeks | Prometheus/Grafana/Alertmanager/Loki stack live, dashboards imported, Zabbix deployed + first 50 devices onboarded, Wazuh manager/indexer/dashboard live |
| **6 — Security Hardening** | 1–2 weeks | Falco, Kyverno policies, NetworkPolicies default-deny, kube-bench passing, image signing pipeline, Wazuh agents rolled out fleet-wide |
| **7 — CI/CD** | 1–2 weeks | GitLab/Harbor/ArgoCD live, first app deployed end-to-end via GitOps, promotion gates configured |
| **8 — Backup & DR** | 1 week | All backup jobs scheduled and **verified by an actual test restore**, DR runbook written and walked through |
| **9 — Load/Chaos Testing** | 1 week | Failover scenarios from Section 11.2 deliberately triggered in staging, RTO/RPO numbers validated against Section 12.1 targets |
| **10 — Go-Live** | — | Production cutover, hypercare period (1–2 weeks elevated monitoring attention) |

**Total realistic timeline: 10–16 weeks** for a team of 2–4 engineers building this from bare metal, assuming hardware is already racked. Compress by parallelizing phases 5–7 once phase 4 is stable.

---

## 17. Production Deployment Checklist

- [ ] All node hostnames, IPs, and VLANs match the documented plan (no drift between design doc and reality)
- [ ] etcd cluster healthy: `etcdctl endpoint health --cluster` returns healthy on all 3 members
- [ ] Control plane: `kubectl get cs` / API server `/livez`, `/readyz` green on all 3 nodes
- [ ] VIP failover tested manually (power off active HAProxy node, confirm VIP migrates within expected window)
- [ ] CNI: pod-to-pod connectivity verified across every node pair, NetworkPolicy default-deny confirmed blocking unauthorized traffic
- [ ] Longhorn: test volume created, written to, replica killed manually, confirmed auto-rebuild
- [ ] Ingress: TLS cert issued and valid (not self-signed) for at least one real hostname, HTTP→HTTPS redirect confirmed
- [ ] Rancher: LDAP/AD login works for a test non-admin account, RBAC scoping verified (test user can't see other teams' namespaces)
- [ ] Monitoring: all Grafana dashboards from Section 6.4 render data (not "No Data")
- [ ] Alerting: a test alert fires end-to-end to Slack/PagerDuty/email
- [ ] Zabbix: at least one physical host, one switch, and one firewall reporting via SNMP
- [ ] Wazuh: agent installed on every node, FIM test (touch a monitored file, confirm alert), vulnerability scan completed at least once
- [ ] Falco: test rule triggered (e.g., shell exec in a container) and confirmed visible in Grafana/Loki
- [ ] Kyverno: a deliberately-noncompliant manifest (e.g., `:latest` tag) is rejected at admission
- [ ] kube-bench run on each node role, critical findings remediated or formally risk-accepted
- [ ] CI/CD: a sample app deploys end-to-end (commit → Harbor → ArgoCD → running pod) with no manual `kubectl` step
- [ ] Backups: etcd snapshot, one Longhorn backup, and one Rancher backup each **successfully restored to a scratch environment** (not just "the job ran")
- [ ] DR runbook walked through tabletop-style with the on-call team
- [ ] Audit logging confirmed flowing to Loki/long-term storage
- [ ] Secrets encryption at rest confirmed (`EncryptionConfiguration` active, verified via etcd raw-read test showing ciphertext)
- [ ] All default/example credentials changed (Grafana admin, Rancher bootstrap password, Zabbix Admin, Harbor admin)
- [ ] Capacity headroom confirmed: cluster running at < 60% average CPU/mem so it can absorb a node failure without cascading

---

## 18. Common Failure Scenarios (Beyond Section 11/12)

| Symptom | Likely cause | First diagnostic step |
|---|---|---|
| `kubectl` hangs or times out cluster-wide | VIP/HAProxy issue, or etcd quorum loss | `etcdctl endpoint status --cluster`, check Keepalived state on both LB nodes |
| Pods stuck `Pending` | Insufficient resources, or no eligible node for storage-tagged scheduling | `kubectl describe pod` → check Events for scheduler reasoning |
| Longhorn volume stuck `Degraded` | A storage node is down or disk pressure on remaining replicas | Longhorn UI / Grafana Longhorn dashboard, check `node-role=storage` node health |
| Certificates suddenly invalid cluster-wide | cert-manager `ClusterIssuer` misconfigured after an upgrade, or ACME rate-limited | `kubectl describe certificate`, check cert-manager controller logs |
| Wazuh agents show "disconnected" en masse | Wazuh manager restarted/cluster split-brain, or firewall rule regression on 1514/1515 | Check manager cluster status, verify firewall rule for agent ports |
| Zabbix "Zabbix server is not running" banner | DB connection lost, or both HA nodes down | Check DB connectivity first (most common root cause), then Zabbix server process |
| Grafana dashboards blank for one data source only | That specific data source's pod/service is down (Loki vs. Prometheus vs. Zabbix plugin) — isolate by data source, not by Grafana itself | Test data source connection in Grafana's data source settings page |
| ArgoCD shows "OutOfSync" that won't self-heal | A resource was manually edited outside Git and has a field ArgoCD's diff doesn't normalize (common with mutating webhooks), or sync is paused | `argocd app diff <app>` to see exact field-level drift |
| Sudden spike in 5xx from Ingress | Backend pods failing readiness probes, or HAProxy backend marked down due to flapping health check | Check `kubectl get endpoints` for the Service, then pod logs |

---

## 19. Performance Optimization

- **etcd**: keep DB size under ~2-4 GB (`--quota-backend-bytes`), defrag on a schedule, never colocate with noisy-neighbor workloads.
- **API server**: tune `--max-requests-inflight` / `--max-mutating-requests-inflight` upward only after confirming CP node CPU/mem headroom; watch `apiserver_request_duration_seconds` in Grafana.
- **CoreDNS**: enable the `cache` plugin, scale replicas with `cluster-proportional-autoscaler` rather than a fixed count once you pass ~50 nodes.
- **kube-proxy**: switch from `iptables` to `IPVS` mode at scale (>~250 Services) — iptables rule evaluation is O(n), IPVS uses hash tables.
- **Longhorn**: avoid replication factor higher than 3 unless compliance demands it — RF5 roughly doubles write amplification for marginal extra durability.
- **Image pulls**: enable Harbor proxy-cache for public base images (e.g., `docker.io` pull-through cache) to cut external bandwidth and pull latency.
- **Resource requests/limits**: enforce via Kyverno that every workload sets requests (mandatory) — without this, the scheduler can't bin-pack effectively and you'll see noisy-neighbor CPU starvation invisible until Grafana's throttling panel (Section 6.4) lights up.
- **Node pool tiering**: separate "general compute" from "storage" node pools (already done in this design) so storage I/O contention doesn't degrade unrelated app latency.

---

## 20. Scaling Strategy: 8 Nodes → 100+ Nodes

| Stage | Node count | What changes |
|---|---|---|
| **Baseline (this design)** | 8 core (3 CP + 3 etcd + … wait, control plane/etcd separate from worker count) + 5 workers = 11 nodes minimum, often described as "8" if etcd is stacked | As specified |
| **~20–30 nodes** | Add workers only; CP/etcd stay at 3 each (etcd handles far more than 30 nodes comfortably) | Start watching CoreDNS replica count, Prometheus cardinality |
| **~50 nodes** | Consider IPVS kube-proxy mode if not already; MetalLB BGP mode if layer2 ARP storms appear | Add a 2nd storage-tagged worker tier if Longhorn I/O becomes a bottleneck |
| **~75 nodes** | etcd may need vertical scaling (more RAM/faster NVMe) — etcd is sensitive to *object count*, not just node count, so this tracks workload density too | Consider splitting Prometheus by `shard` (functional sharding) if a single instance's scrape time exceeds the scrape interval |
| **100+ nodes** | Many orgs split into **multiple clusters** (e.g., per-region or per-business-unit) managed centrally by **Rancher's multi-cluster mode** rather than growing one cluster indefinitely | etcd is generally considered to top out comfortably around 5,000 nodes / 150,000 pods per *Kubernetes-documented* limits, but **operational** limits (blast radius, upgrade risk, noisy-neighbor blast radius) usually push orgs to multi-cluster well before hitting etcd's technical ceiling |

**Key principle**: control plane and etcd node *count* stays at 3 far longer than intuition suggests — you scale the **worker pool** for capacity and split into **additional clusters** (not an ever-larger single cluster) for blast-radius and multi-tenancy reasons once you're past ~75-100 nodes or multiple business units need hard isolation.

---

## 21. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| ingress-nginx end-of-life leaves an unpatched CVE exposed | Medium (grows over time) | High (public-facing) | Migrate to Traefik per Section 5; if delayed, isolate ingress-nginx behind WAF rules as a stopgap |
| etcd disk latency causes leader flapping | Low if NVMe used, Medium if not | High (cluster-wide instability) | Dedicated NVMe, isolated disk I/O, monitor `etcd_disk_wal_fsync_duration_seconds` |
| Single team's noisy workload starves others | Medium (common at 100+ devs) | Medium | ResourceQuotas + LimitRanges per namespace, mandatory requests/limits via Kyverno |
| Backup exists but was never restore-tested | Medium-High (very common failure mode) | Critical (discovered only during real DR) | Quarterly restore drills (Section 16, Phase 9) — a backup you haven't restored is a hypothesis, not a backup |
| Secrets sprawl (plaintext in Helm values, CI variables) | Medium-High at 100+ devs | High (credential leak) | Vault/External Secrets Operator (Section 4.6), secret-scanning in CI (e.g., gitleaks) |
| Alert fatigue causes real incidents to be missed | Medium | High | Tune Alertmanager grouping/inhibition rules, route by severity, regularly prune noisy/low-value alerts |
| Single person knows the DR runbook | High in small teams | Critical | Runbook in Git, tabletop exercises with full on-call rotation, not just the original author |
| Version skew between Rancher/RKE/K8s breaks unexpectedly | Medium | Medium-High | Always check the official Rancher support matrix before any upgrade; never skip minor versions |

---

## 22. Alternative Architecture Options

| Decision point | This design's choice | Alternative | When to choose the alternative |
|---|---|---|---|
| Ingress controller | Traefik | NGINX Ingress (legacy), Kong, HAProxy Ingress, Gateway API + Envoy Gateway | If deep existing NGINX annotation investment, or org standardizes on Envoy already |
| Kubernetes distribution | Vanilla kubeadm-built cluster | **RKE2** (Rancher's own distro — tighter Rancher integration, CIS-hardened by default, built-in Traefik/Canal) | Most orgs adopting Rancher should seriously consider RKE2 over vanilla kubeadm — less to hand-build, same HA model |
| CNI | Calico | Cilium (eBPF-based, richer observability/Hubble, can replace kube-proxy) | If you want L3-L7 network policy + built-in service mesh-lite features without adding Istio/Linkerd |
| Service mesh | None specified (TLS at ingress only) | Linkerd (lightweight) or Istio (feature-rich, heavier) | If you need mTLS pod-to-pod, fine-grained traffic splitting, or per-service observability beyond what Prometheus scraping gives you |
| Long-term metrics | Thanos | Grafana Mimir, VictoriaMetrics | VictoriaMetrics is notably lighter-weight and often recommended for smaller ops teams wanting Prometheus-compatible long-term storage without Thanos's operational complexity |
| Centralized SIEM | Wazuh | Elastic Security, Splunk Enterprise Security | If budget allows and you need vendor support contracts / existing Splunk investment |
| GitOps tool | ArgoCD | FluxCD | Flux is more "Kubernetes-native CRD" in philosophy with less UI; ArgoCD's UI is generally preferred by teams wanting visual sync status |
| Image registry | Harbor | GitLab Container Registry (if already running GitLab) | Reduces moving parts if GitLab is already in the stack — but loses Harbor's richer scanning/replication features |

---

## 23. Recommended Production Configuration (Summary)

```
Kubernetes:        v1.35.x (kubeadm or RKE2 — strongly consider RKE2 given Rancher is in-scope)
Control Plane:      3 nodes, external etcd (3 nodes, dedicated NVMe)
Workers:             5 nodes minimum (3 general + 2 storage-tagged), scale horizontally from there
CNI:                  Calico (or Cilium if eBPF observability is a priority)
Ingress:              Traefik (NOT ingress-nginx — retired upstream March 2026)
Load Balancer:      MetalLB (Layer2 at this scale) + HAProxy/Keepalived for the API-server/ingress front door
Storage:             Longhorn, RF=3, dedicated storage VLAN, off-cluster backup target (S3-compatible)
Management:        Rancher v2.14.x, HA (3 replicas), LDAP/AD-bound
Monitoring:        Prometheus (2 replicas) + Thanos, Grafana (2 replicas), Alertmanager (3, clustered)
Infra Monitoring:  Zabbix (HA server pair + regional proxies), SNMP v3
Logging:             Loki + Promtail, object-storage-backed, audit logs on extended retention
Security:            Wazuh (clustered) + Falco (DaemonSet) + Trivy (CI + in-cluster) + Kyverno (admission)
CI/CD:                GitLab + Kubernetes-executor Runners + Harbor (HA) + ArgoCD (app-of-apps, GitOps)
Backup:              etcd snapshots (15 min) + Longhorn RecurringJobs + rancher-backup + Velero, all to off-cluster target
DR:                    Documented runbook, quarterly tested, RTO/RPO per Section 12.1
```
