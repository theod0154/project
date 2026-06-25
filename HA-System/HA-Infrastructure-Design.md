# Production-Grade 2-Node HA Infrastructure Design

**Scope:** 2 physical Ubuntu servers → HA virtualization + Kubernetes + observability + caching
**Design philosophy:** Active-Active where possible, Active-Passive where unavoidable (2-node math), budget-conscious, no unjustified complexity.

---

## 0. Executive Summary / Key Design Decision

With **only 2 physical nodes**, you cannot achieve "textbook" HA for every layer (etcd quorum needs 3, for example). The design below solves this with **one pragmatic trick used industry-wide for 2-node clusters**: a lightweight **third "witness" participant** that does *not* run workloads but provides quorum/tie-breaking. Two options, both included:

- **Option A (recommended):** A small **VM or cheap VPS/Raspberry Pi acting as a witness/arbiter node** for etcd/quorum purposes only (no app workloads).
- **Option B (if no 3rd device allowed):** Use **k3s with embedded SQLite (single-server-HA pair via external DB)** or **k3s in 2-node "datastore on external DB"** mode, accepting a brief manual/automatic promotion step on failure.

We recommend **Option A** — a $0–$50 device (old laptop, Raspberry Pi 4, or a $5/mo VPS) solves 90% of 2-node HA headaches and is the single highest-leverage investment in this design.

**Chosen stack:**
| Layer | Choice | Why |
|---|---|---|
| Hypervisor | **Proxmox VE** (or raw KVM/QEMU + libvirt if you want zero extra licensing/UI) | Built-in clustering, live migration, snapshot/backup, web UI — saves huge ops time vs raw libvirt |
| Container orchestration | **k3s** (HA embedded etcd mode, 2 server nodes + 1 witness) | Lightweight, single binary, far less RAM/CPU overhead than kubeadm full K8s — critical on only 2 physical hosts |
| Container runtime | **containerd** (ships with k3s) + Docker only where devs need it for local builds | Avoid running two container runtimes side by side on the same workloads |
| L4/L7 LB + VIP | **HAProxy + Keepalived** (active-passive VIP) | Mature, minimal resource footprint, proven failover pattern |
| Monitoring (infra) | **Zabbix** | Best for hardware/VM/OS-level monitoring, SNMP, agent-based alerting |
| Monitoring (metrics/dashboards) | **Prometheus + Grafana** | De facto standard for K8s/app metrics |
| Logging | **Loki + Promtail + Grafana** | Far lighter than ELK on 2-node hardware; integrates natively with Grafana |
| Caching | **Redis with Sentinel** (3 sentinels: 2 on physical nodes + 1 on witness) | HA failover without needing Redis Cluster complexity |
| Storage (K8s) | **Longhorn** (replicated block storage across 2 nodes) | Gives PVC replication without a separate SAN/NAS |

---

## 1. Full Architecture Diagram (text-based)

```
                              ┌─────────────────────────┐
                              │        INTERNET /        │
                              │     Corporate Network    │
                              └────────────┬─────────────┘
                                           │
                              ┌────────────▼─────────────┐
                              │   Edge Router / Firewall │
                              └────────────┬─────────────┘
                                           │
                         VIP: 10.0.10.10 (floating, Keepalived)
                       ┌────────────────────┴────────────────────┐
                       │                                          │
             ┌─────────▼─────────┐                     ┌─────────▼─────────┐
             │  HAProxy + Keepa- │   VRRP heartbeat     │  HAProxy + Keepa- │
             │  lived (MASTER)   │◄───────────────────►│  lived (BACKUP)   │
             │  on Node A        │                      │  on Node B        │
             └─────────┬─────────┘                     └─────────┬─────────┘
                       │                                          │
   ┌───────────────────┴──────────────────────────────────────────┴──────────────────┐
   │                                                                                   │
   │   PHYSICAL NODE A (Ubuntu Server)            PHYSICAL NODE B (Ubuntu Server)    │
   │   Proxmox VE / KVM Host                       Proxmox VE / KVM Host             │
   │  ┌─────────────────────────────┐             ┌─────────────────────────────┐    │
   │  │ VM: k3s-server-1 (control+  │  k3s HA     │ VM: k3s-server-2 (control+  │    │
   │  │      agent, embedded etcd)  │◄───────────►│      agent, embedded etcd)  │    │
   │  ├─────────────────────────────┤  cluster    ├─────────────────────────────┤    │
   │  │ Pods (Deployments,          │             │ Pods (Deployments,          │    │
   │  │  StatefulSets, Longhorn)    │◄──Longhorn──►│  StatefulSets, Longhorn)    │    │
   │  ├─────────────────────────────┤  replication├─────────────────────────────┤    │
   │  │ VM: Redis-A (Sentinel)      │◄────────────►│ VM: Redis-B (Sentinel)     │    │
   │  ├─────────────────────────────┤             ├─────────────────────────────┤    │
   │  │ VM: Prometheus/Grafana      │             │ VM: Loki/Promtail (or       │    │
   │  │  (or run as pods in k3s)    │             │  same — see §2)             │    │
   │  ├─────────────────────────────┤             ├─────────────────────────────┤    │
   │  │ VM: Zabbix Server + Web     │  MySQL repl │ VM: Zabbix DB replica /     │    │
   │  │  (active)                   │◄───────────►│  Zabbix Proxy (standby)    │    │
   │  ├─────────────────────────────┤             ├─────────────────────────────┤    │
   │  │ Legacy/special VMs          │             │ Legacy/special VMs          │    │
   │  │ (DB, AD, file server, etc.) │             │ (DB replica, etc.)          │    │
   │  └─────────────────────────────┘             └─────────────────────────────┘    │
   │                                                                                   │
   └───────────────────────────────────────────────────────────────────────────────────┘
                       │                                          │
                       └───────────────────┬──────────────────────┘
                                           │
                              ┌────────────▼─────────────┐
                              │  WITNESS NODE (tiny VM /  │
                              │  Raspberry Pi / cheap VPS)│
                              │  - k3s etcd witness OR    │
                              │    3rd Sentinel instance  │
                              │  - Keepalived 3rd voter   │
                              │    (optional, for split-  │
                              │     brain protection)     │
                              └───────────────────────────┘
```

---

## 2. Component Breakdown

| Component | Where it runs | HA Mechanism |
|---|---|---|
| Hypervisor | Bare metal on both nodes | Proxmox clustering (2-node + optional QDevice for quorum) |
| k3s control plane | VM on each node + witness (3-member etcd) | Embedded etcd Raft consensus across 3 voters |
| k3s workloads (pods) | Both nodes (agents) | K8s scheduler reschedules pods from failed node; PodDisruptionBudgets + anti-affinity |
| HAProxy | VM/container on both nodes | Active-passive via Keepalived VIP |
| Keepalived | Same VM as HAProxy, both nodes | VRRP protocol, sub-second failover |
| Zabbix Server | Primary on Node A | MySQL/PostgreSQL replicated to Node B; manual or scripted promotion (Zabbix server itself has no native multi-master HA — see §4) |
| Prometheus | Runs **inside k3s** as a Deployment with Longhorn-backed PVC, 2 replicas (Thanos optional later) | Pod rescheduled on node failure; data on replicated volume |
| Grafana | Inside k3s, Deployment with PVC | Same as above; stateless if using external DB for dashboards config |
| Loki | Inside k3s, single binary or simple-scalable mode | PVC on Longhorn; or push logs to object storage (MinIO) for durability |
| Redis | VM or k3s pods, **Sentinel topology**: master + replica + 3rd sentinel on witness | Sentinel auto-promotes replica to master on failure |
| Longhorn | Inside k3s, uses node-local disks | Replicates volumes (replica count 2, across both nodes) |

---

## 3. Network Topology Design

```
VLAN 10 - Management        : Proxmox/host mgmt, IPMI/iDRAC          10.0.10.0/24
VLAN 20 - Public/Frontend   : HAProxy VIP, ingress traffic           10.0.20.0/24
VLAN 30 - Kubernetes internal: Pod network (k3s flannel/Cilium)      10.42.0.0/16 (default flannel)
VLAN 40 - Storage/Replication: Longhorn sync, Proxmox migration, DB repl  10.0.40.0/24 (dedicated NIC if possible)
VLAN 50 - Monitoring        : Zabbix agents, Prometheus scrape targets   10.0.50.0/24
```

**Recommendations:**
- Each physical server should have **at least 2 NICs**: one for management/public traffic, one dedicated to storage replication + Proxmox cluster/Corosync heartbeat (latency-sensitive). This avoids storage replication traffic competing with user traffic — a common cause of "split brain" false-positives.
- Keepalived VRRP heartbeat should ride on its own VLAN or at minimum not share saturation-prone links.
- The witness node only needs reachability to VLAN 10/30/40 (control-plane/quorum traffic), not the data plane — keep it lightweight on bandwidth.

---

## 4. HA Strategy Explanation

### Why **Active-Active for workloads, Active-Passive for the LB VIP**
- **Kubernetes workloads:** Active-active across both nodes. Pods run simultaneously on Node A and Node B behind a Service; Kubernetes' own load balancing (kube-proxy/iptables or IPVS) spreads traffic. This maximizes hardware utilization — no idle standby.
- **HAProxy/Keepalived VIP:** Active-passive. Only one node owns the VIP at a time. Running HAProxy active-active with anycast/ECMP is possible but adds real complexity (BGP, multiple uplinks) that is **not justified** at this scale. Keepalived failover is sub-second to a few seconds — well within your <30s target.
- **etcd / control plane quorum:** This is the crux of "2-node HA" being a contradiction in pure form. Raft consensus (used by etcd and k3s) requires `(N/2)+1` votes to elect a leader. With exactly 2 voters, losing 1 = losing quorum = **read-only or fully down cluster**, even though a server is still alive. **This is why the witness node is mandatory, not optional, if you want real HA at the control-plane layer.**
- **Zabbix server:** Zabbix server is NOT natively clusterable (no built-in multi-master). We treat it as active-passive via DB replication + a floating VIP/DNS pointing to whichever instance is promoted (manual runbook or scripted with a tool like `keepalived` + a health check script that starts/stops the zabbix-server service). This is an accepted industry limitation of Zabbix — Zabbix Proxies (lightweight) can run on both nodes feeding the single server, so monitoring **data collection** continues even if the central server briefly fails over.
- **Redis:** Sentinel-based active-passive per shard, automatic failover, no manual step needed.

### Failover targets
| Component | Target RTO | Mechanism |
|---|---|---|
| HAProxy/VIP | < 3 sec | Keepalived VRRP |
| K8s pod rescheduling | 10–40 sec (depends on `--node-monitor-grace-period`, tune down to ~15s default is 40s) | kube-controller-manager node eviction + PDB-respecting reschedule |
| Redis | < 10 sec | Sentinel quorum + promotion |
| Storage (Longhorn) | Immediate read from surviving replica | Volume replica engine switch |
| Zabbix server | Minutes (manual/scripted) | Acceptable since Proxies keep collecting data |

---

## 5. Kubernetes Deployment Strategy for the 2-Node Limitation

**Recommended: k3s, NOT kubeadm.** Reasons:
- Single binary, ~512MB RAM control plane footprint vs 2GB+ for kubeadm's etcd+API+scheduler+controller-manager separately.
- Built-in embedded etcd HA mode (`--cluster-init` + `server --server https://...`) designed exactly for small clusters.
- Built-in support for external DB datastore (MySQL/Postgres/etcd) as an alternative to embedded etcd if you'd rather lean on an existing replicated DB.

**Topology:**
```
k3s-server-1  (Node A, VM)  --cluster-init      → etcd voter #1
k3s-server-2  (Node B, VM)  --server https://A  → etcd voter #2
k3s-server-3  (Witness, VM/Pi) --server https://A → etcd voter #3 (taint: NoSchedule, control-plane only)
```
- Both real servers are **control-plane + worker (agent) combined** (`k3s server` role handles both by default) so you don't waste a whole node on control-plane-only duty — important when you only have 2 boxes.
- The **witness node is tainted `node-role.kubernetes.io/control-plane:NoSchedule`** so it never receives workload pods — it exists purely for Raft quorum. It can be tiny (1 vCPU, 1–2GB RAM).
- Use **PodDisruptionBudgets** and **podAntiAffinity** (`topologyKey: kubernetes.io/hostname`) on all critical Deployments/StatefulSets so K8s never schedules both replicas of the same service on the same physical node.
- Set `replicas: 2` minimum for every Deployment that must survive a node loss.
- Tune `kube-controller-manager`: `--node-monitor-grace-period=15s --node-monitor-period=2s --pod-eviction-timeout=30s` to hit your <30s target (defaults are much longer, ~5 min).

**If you truly cannot add a 3rd device:** fallback is k3s 2-node with an **external MySQL/Postgres datastore** (itself replicated, e.g. Galera/Patroni) instead of embedded etcd — but this just moves the quorum problem to the DB layer, which still needs 3 nodes for proper Galera/Patroni HA. **There is no way to get true automatic quorum-based HA with exactly 2 physical pieces of hardware and nothing else** — this is a hard distributed-systems constraint, not a tooling limitation. The witness can be extremely cheap (even a $35 Raspberry Pi or a free-tier cloud VM), so we strongly recommend it.

---

## 6. Load Balancing Design

**External (north-south) traffic:**
```
Client → DNS (app.company.com) → VIP 10.0.20.10
       → Keepalived-elected HAProxy (Node A or B)
       → HAProxy frontend (TLS termination, optional)
       → backend pool = NodePort or MetalLB-assigned IPs on both k3s nodes
       → kube-proxy → pod
```
- HAProxy backend health-checks both k3s nodes' NodePort (or ingress-controller IP) — if Node A's k3s agent is down, HAProxy stops sending traffic there within its `inter`/`fall` check interval (set 2–3s).
- Alternative/complement: install **MetalLB** in L2 mode inside k3s for `LoadBalancer`-type Services, so HAProxy only needs to target a single MetalLB-announced IP that itself fails over between nodes — gives you two layers of failover (MetalLB + Keepalived) for extra resilience, optional but recommended once you're comfortable with the basics.

**Internal (east-west) traffic:**
- Native Kubernetes Services (ClusterIP) + kube-proxy (iptables or IPVS mode — prefer **IPVS** for better performance at scale) handle pod-to-pod load balancing automatically; no extra tooling needed.
- For non-k8s VM-to-VM traffic (e.g., app VM → Redis), use HAProxy in TCP mode as an internal LB pointing at Sentinel-discovered master, or have apps use a **Redis-aware client with Sentinel support** (recommended — avoids HAProxy needing to track Redis master changes).

**No single point of failure:** both HAProxy/Keepalived instances are identical/interchangeable; VIP can live on either node; config is kept in sync via a simple `rsync`/Ansible playbook or Keepalived `notify` scripts triggering a config push.

---

## 7. Storage Strategy

| Data class | Strategy | Tooling |
|---|---|---|
| K8s persistent app data (PVCs) | **Replicated, 2 copies, one per node** | Longhorn (replica count = 2; engine handles automatic resync after node recovery) |
| VM disks (Proxmox) | **Local with scheduled replication**, OR shared via ZFS replication every N minutes | `pve-zsync` / ZFS send-receive between hosts (Proxmox native), gives near-real-time VM portability without needing a SAN |
| Redis data | In-memory + AOF/RDB persistence to local disk, replicated via Redis replication (not via Longhorn) | Native Redis replication |
| Zabbix/Grafana metadata DB | MySQL/Postgres with **async or semi-sync replication** Node A → Node B | MySQL InnoDB Cluster / native Postgres streaming replication |
| Logs (Loki) | Object storage backend (MinIO, run as a small HA-ish pair or single instance with replicated disk) rather than only local disk — durability over node loss | Loki + MinIO (or S3 if available) |
| Backups | See §9 | Restic / Proxmox Backup Server |

**Local vs shared vs replicated — decision rule:**
- **Local-only** (no replication): acceptable only for ephemeral/cache/scratch data (e.g., a CI build cache) — anything you can afford to lose.
- **Replicated (Longhorn/ZFS/DB replication):** default for everything else — gives you HA without the cost/complexity of a dedicated SAN/NAS box.
- **Shared storage (NFS/iSCSI/Ceph):** not recommended at 2-node scale — Ceph specifically wants ≥3 nodes for sane quorum/replication; adding a NAS adds another SPOF unless that NAS itself is HA (expensive). Revisit this when you scale to 3+ nodes (see §10).

---

## 8. Failure Scenarios and System Behavior

| Scenario | What happens | User impact |
|---|---|---|
| **Node A physical failure** | Keepalived on Node B detects missed VRRP heartbeats (~1–3s) → takes over VIP. k3s loses 1 of 3 etcd voters but retains quorum (2/3) → cluster stays writable. Pods that were on Node A are rescheduled to Node B (after `node-monitor-grace-period`, tuned to ~15-30s). Longhorn serves reads/writes from the surviving replica on Node B, marks volume degraded, resyncs once Node A returns. | Brief (<30s) latency blip for pods that were on Node A; HAProxy/VIP failover near-instant; no data loss for replicated PVCs/Redis. |
| **Node B physical failure** | Symmetric to above. | Same. |
| **Witness node failure** | etcd quorum drops to 2/2 — Raft can still elect a leader since both remaining voters agree (majority of *remaining* voters), but the cluster is now vulnerable: if either Node A or B also fails, you lose quorum entirely. | No immediate impact, but **you are temporarily in a non-HA state** — alert should fire immediately (Zabbix/Prometheus) demanding urgent witness restoration. |
| **Network partition between Node A and Node B (split brain risk)** | The witness's vote breaks the tie — whichever side can still reach the witness retains quorum and keeps serving; the partitioned-off side's k3s agent steps down from any leader role. Keepalived also uses this principle if you give the witness a VRRP-tracking script vote (optional advanced config). | The "winning" side continues serving; the isolated side pauses workloads until partition heals — by design, to prevent data corruption. |
| **HAProxy/Keepalived VM crash on active node** | Keepalived VRRP timeout on the passive node triggers VIP takeover automatically. | <3s blip. |
| **Redis master failure** | Sentinels (quorum of 2 of 3) detect and promote the replica; clients using Sentinel-aware libraries reconnect to new master automatically. | Sub-10s cache unavailability; no data loss if AOF `everysec` or better fsync policy used (some risk of last-second writes lost — acceptable for cache use case; for anything stricter, use `appendfsync always` at a performance cost). |
| **Zabbix server VM failure** | Zabbix Proxies (running on both nodes) continue buffering monitoring data locally. Central server is down until manually/scripted promotion of the DB replica + starting zabbix-server on Node B. | Dashboards/alerting gap until promotion (minutes) — data is not lost (Proxies buffer), just delayed. |
| **Prometheus pod failure** | K8s reschedules pod on the other node; PVC (Longhorn-replicated) reattaches with existing TSDB data. | Few seconds to ~1 min gap in scraped metrics during reschedule. |
| **Total power loss to both servers** | Nothing — this is the one scenario this design cannot survive, by definition of having only 2 physical hosts in one location. | Mitigate with UPS + generator if uptime SLA demands it, or plan a DR site once budget allows. |

---

## 9. Step-by-Step Implementation Plan

**Phase 0 — Prep (1–2 days)**
1. Decide on Proxmox VE vs raw KVM/libvirt. (Recommend Proxmox — free, web UI, built-in clustering/backup/ZFS replication, minimal extra cost.)
2. Install Ubuntu Server 22.04/24.04 LTS on both physical nodes if going raw KVM, or install Proxmox VE directly (Debian-based) if going that route.
3. Acquire/provision the witness device (Raspberry Pi 4/5, old PC, or cheap cloud VM — needs only ~1 vCPU/1-2GB RAM, static IP, reachable on the management VLAN).
4. Configure NICs: separate management vs storage/replication traffic if 2+ NICs available.

**Phase 1 — Virtualization layer**
5. Join both Proxmox hosts into a Proxmox cluster (`pvecm`), add a QDevice (corosync-qdevice) on the witness for Proxmox-level quorum too — same witness device can serve double duty for Proxmox quorum *and* k3s/etcd quorum.
6. Set up ZFS storage pools; configure `pve-zsync` jobs for VM disk replication between nodes for the VMs you decide to keep VM-based (see §below for VM vs container decision).
7. Create base VM templates (Ubuntu cloud-image) for fast provisioning.

**Phase 2 — Kubernetes layer**
8. Provision 2 VMs (one per physical node) sized appropriately (e.g., 4 vCPU/8GB to start) + 1 tiny VM/device for witness.
9. Install k3s:
   - Node A: `curl -sfL https://get.k3s.io | sh -s - server --cluster-init --tls-san <VIP> --node-taint ...` (no taint on A/B, taint on witness)
   - Node B: `... server --server https://<NodeA-IP>:6443 --token <token>`
   - Witness: `... server --server https://<NodeA-IP>:6443 --token <token> --node-taint node-role.kubernetes.io/control-plane=true:NoSchedule`
10. Install MetalLB (L2 mode) and assign an address pool from VLAN 20 for `LoadBalancer` services (optional but recommended).
11. Install Longhorn via Helm; set default replica count = 2.
12. Validate with `kubectl get nodes -o wide` and a test Deployment with anti-affinity + PDB.

**Phase 3 — Load balancing**
13. Stand up HAProxy + Keepalived on both nodes (as VMs or LXC containers — LXC is lighter for this purpose).
14. Configure Keepalived VRRP with unique `virtual_router_id`, priorities (e.g., 150/100), and a health-check script (`track_script`) that checks HAProxy + k3s API reachability before allowing VIP ownership.
15. Configure HAProxy frontends/backends pointing at both k3s nodes' NodePort/MetalLB IP, with TCP/HTTP health checks.

**Phase 4 — Caching**
16. Deploy Redis (as VMs or k3s pods via Bitnami/official Helm chart) — 1 master + 1 replica on the two physical nodes, + Sentinel on all three (Node A, Node B, witness).
17. Configure apps to use Sentinel-aware connection strings (e.g., `redis+sentinel://sentinel1:26379,sentinel2:26379,sentinel3:26379/mymaster`).

**Phase 5 — Observability**
18. Deploy Prometheus + Grafana into k3s via `kube-prometheus-stack` Helm chart, with Longhorn-backed PVCs, `replicas: 2` where the chart supports it (Alertmanager especially).
19. Deploy Loki (`loki-stack` or `loki` + `promtail` DaemonSet) inside k3s; point persistence at MinIO or a Longhorn PVC.
20. Install Zabbix server + frontend + MySQL on Node A's VM; configure MySQL replication to a standby on Node B; install Zabbix Proxy on both nodes' VM layer monitoring hardware (IPMI/SNMP) and pass data up to the server.
21. Configure Alertmanager → email/Slack/Telegram webhook; configure Zabbix actions → same channels.

**Phase 6 — Backup**
22. Configure Proxmox Backup Server (PBS) — can run as a VM on either node, or external — for scheduled VM snapshots/backups.
23. Schedule k3s etcd snapshots: k3s does this automatically by default (`/var/lib/rancher/k3s/server/db/snapshots`), set `--etcd-snapshot-schedule-cron` and `--etcd-snapshot-retention`; also copy snapshots off-box (e.g., to the witness or object storage) regularly.
24. Schedule DB dumps (Zabbix MySQL, anything else) via `mysqldump`/`pg_dump` cron + offsite copy.

**Phase 7 — Validation/chaos testing**
25. Simulate Node A failure (power off) — confirm VIP fails over, pods reschedule, Redis promotes, Longhorn marks degraded and resyncs on recovery.
26. Simulate witness failure — confirm cluster stays up but alerts fire.
27. Document RTO/RPO actually observed vs targets; tune timeouts accordingly.

---

## 10. VM vs Container Decision Guide

| Run in a **VM** when... | Run in a **Container (k3s)** when... |
|---|---|
| Needs a different kernel/OS or kernel modules (e.g., specific Windows workloads, custom kernel tuning) | Stateless or cloud-native app, scales horizontally |
| Legacy/COTS software not container-friendly (e.g., some monitoring appliances, AD/DC, license-bound software tied to MAC/hardware) | Anything you build in-house / has a maintained Docker image |
| Needs strong kernel-level isolation/security boundary beyond container namespaces (e.g., multi-tenant untrusted code) | CI/CD friendly, needs frequent rolling deploys |
| Heavy, monolithic DB engines where you want full OS-level tuning control and live-migration via Proxmox (some teams keep primary DBs in VMs for this reason) | Microservices, APIs, web frontends, batch jobs, anything in this design's "app layer" |
| Infrastructure services tightly coupled to host networking/storage (e.g., the HAProxy/Keepalived pair, for simplest VRRP networking — though LXC also works) | Prometheus, Grafana, Loki, Redis (all containerize well and benefit from k8s scheduling/HA primitives) |

In this design: **k3s itself, Redis, Prometheus, Grafana, Loki run as VMs hosting k3s or as k3s pods**; **Zabbix server + DB, HAProxy/Keepalived, and any legacy apps (AD, file servers, license servers)** are kept as dedicated VMs for simplicity, portability (Proxmox live migration/ZFS replication), and because they don't benefit much from k8s scheduling.

---

## 11. Suggested Improvements When Scaling to 3–5 Servers

1. **Drop the "witness-only" device** — promote it to a real 3rd physical node; now you have genuine N=3 quorum for k3s/etcd, Proxmox, and Redis Sentinel, with real compute capacity instead of a tie-breaker.
2. **Move to Ceph (via Proxmox's built-in Ceph support)** for VM storage instead of ZFS replication — Ceph needs ≥3 nodes to be sane, and now you have them; gives synchronous shared storage and easier live migration.
3. **HAProxy active-active** becomes viable: with 3+ nodes you can run HAProxy on every node and use ECMP/BGP (if your network supports it) or DNS round-robin + health checks, removing the single "active" LB bottleneck entirely.
4. **Kubernetes**: move to full kubeadm or k3s with **3 dedicated control-plane nodes** + separate worker nodes (no longer combining control-plane+worker), improving control-plane resilience and isolating workload noise from etcd performance.
5. **Zabbix HA**: Zabbix 6.4+ added a native **Zabbix Server HA cluster** feature (multiple zabbix-server instances with automatic standby promotion) — adopt this once you have spare nodes to dedicate.
6. **Prometheus**: introduce **Thanos** or **Mimir** for long-term storage, global query view, and true HA Prometheus pairs with deduplication.
7. **Loki**: move from single-binary to **simple-scalable or microservices mode** for higher log ingestion throughput.
8. **Redis**: consider **Redis Cluster mode** (sharding) if data volume/throughput outgrows a single master-replica pair.
9. **Add a secondary site/DR**: once on 5 nodes, consider keeping 3 in primary site, 2 in a secondary location for true site-level disaster recovery (the one failure mode 2-node-single-site can never solve).
10. **GitOps**: introduce **ArgoCD/Flux** for declarative, auditable deployment management as the number of services/nodes grows beyond what manual `kubectl apply` / Ansible comfortably manages.

---

## 12. Budget-Conscious Notes

- Every tool selected (Proxmox, k3s, HAProxy, Keepalived, Zabbix, Prometheus, Grafana, Loki, Redis, Longhorn, MetalLB) is **free and open-source** — no licensing cost.
- The only "new" purchase recommended is the witness device — a Raspberry Pi 4/5 (~$35–80) or repurposed old PC is sufficient; a free-tier cloud VM also works if you're comfortable with a small WAN dependency for quorum traffic (latency-sensitive — test this if you choose the cloud route).
- This avoids the temptation to buy a SAN/NAS or a 3rd full server before you actually need one — the design defers that spend to §11 when you scale.
