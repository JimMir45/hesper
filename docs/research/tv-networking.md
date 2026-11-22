# TV-1: Lab Networking Technical Validation

> Task: plan.md **TV-1** (front-loaded risk task) · Validated live on this machine, 2026-11-21
> Verdict: **lite profile networking fully working** (compose healthchecks green, host↔container↔container all verified). Windows-VM leg resolved to a chosen topology; VM-side verification deferred to M4-1/M4-2 (no VM tooling installed yet — by plan).

## 1. Host facts (measured)

| Fact | Value | Impact |
|---|---|---|
| WSL2 networking mode | **mirrored** (`wslinfo --networking-mode`) | Windows↔WSL share interfaces; loopback bidirectional |
| CPU vendor | GenuineIntel | M4 nested virtualization feasible (§9 preflight still required at M4-0) |
| RAM seen by WSL | 15 GB | lite fits comfortably; **full profile (GOAD ≥20 GB) will need `.wslconfig` raise** — M4 preflight |
| docker / compose | 29.1.3 native / 2.40.3 | `docker compose` (v2 syntax) |
| Docker address space | 172.17–172.31 and many 192.168.x/20 pools **already occupied by other projects on this shared machine** | lab-net pinned to **172.16.0.0/16** (the only free 172.x /16); future profiles must set explicit ipam and re-check |

## 2. Verified paths (all commands run live)

| Path | Result |
|---|---|
| WSL host → container published ports (127.0.0.1) | **200** (DVWA :4280/login.php) · **JSON** (VAmPI :5002/) · **307** (Velociraptor GUI :8889) · **400** (frontend :8000 — alive, expects client protocol) |
| container → container over lab-net (service DNS) | **200** (`hesper-dvwa` → `http://vampi:5000/`) |
| Windows (host) → WSL published ports via `127.0.0.1` | **200** (:4280) · **307** (:8889) — mirrored-mode loopback works |
| Windows (host) → WSL via LAN IP `192.168.3.147` | **timeout (000)** — Hyper-V Firewall blocks the non-loopback self-host path by default |
| compose up --wait healthchecks | all 4 services (vampi, db, dvwa, velociraptor) `running + healthy`; `hesper lab up/status/down` exercised; teardown leaves 0 containers |

## 3. Chosen topology for M4 (Windows-host VM → detection plane)

**Primary: VirtualBox NAT**

```
Windows VM (Vagrant/VBox, NAT)                     WSL2 (mirrored)
  velociraptor client agent ──► 10.0.2.2:18000 ──► Windows loopback ──► mirrored ──► hesper-velociraptor:8000
                                                    (host-side 18000: bare 8000 collides with other
                                                     dev services on this shared machine — M2 finding)
```

- `10.0.2.2` (VBox NAT gateway) maps to the **Windows host loopback**, and Windows-loopback → WSL is the verified path (table §2). No firewall changes needed; NAT guest→host egress is allowed by default.
- Confidence: all links verified separately **except the VBox leg itself** (no VM tooling yet) — verify live at **M4-2**.

**Fallback A: VBox bridged** → Windows LAN IP path is currently firewalled (§2). Requires a Hyper-V Firewall rule for inbound WSL ports (cmdlets `Get/Set-NetFirewallHyperVVMSetting`, `New-NetFirewallHyperVRule` — exact rule to be validated at M4-1). Avoid unless NAT proves insufficient.

**Fallback B (no cross-boundary networking at all):** run the Velociraptor frontend inside the VM, export EVTX, and judge **offline** (chainsaw path, already working — §5). This is the guaranteed-to-work floor.

## 4. Gotchas discovered (each one bit us live)

1. **drvfs (=/mnt/c) bind mounts mount everything 0777.** MariaDB's stock `healthcheck.sh` writes a credentials `.cnf` into the datadir; MariaDB refuses world-writable config files → the default healthcheck can never authenticate on drvfs. Fixed: db healthcheck pings with root credentials from env (`compose.lite.yaml`). Everything else (velociraptor config/datastore, dvwa-db data) works on drvfs. For heavy IO, `HESPER_LAB_STATE` env can relocate state to an ext4 path.
2. **The WSL shell exports `http_proxy=127.0.0.1:17897`** and its `no_proxy` (`127.*` wildcard form) is **not honored by curl** → every host-side probe must pass `--noproxy '*'` or it gets 502 artifacts from the local proxy. (Already covered as a project memory quirk; now also a TV-1 fact.)
3. **Docker address pools are exhausted on this shared machine** → any new compose project without an explicit pinned subnet fails with "all predefined address pools fully subnetted". lite pins 172.16.0.0/16; zero-vm uses `network_mode: none` (offline scanner needs no network at all).
4. **`wsl -e bash -c "…$VAR…"` from Git Bash**: `$` gets expanded locally / paths get rewritten unless the whole command is quoted — known project quirk, applied throughout.

## 5. Image inventory (corrections vs the selection research)

| Image | Resolution |
|---|---|
| Velociraptor server | `ghcr.io/velocidex/velociraptor-server:latest` — first start **auto-generates** `server.config.yaml` + admin user (env: `VELOCIRAPTOR_INITIAL_ADMIN_PASSWORD`, `VELOCIRAPTOR_NO_INITIALIZE=TRUE` skips MSI builds). Generated binds: GUI `0.0.0.0:8889`, frontend `0.0.0.0:8000` (both inside container ✓). GUI on the host stays loopback-only by publish rule. |
| DVWA | `ghcr.io/digininja/dvwa:latest` + `mariadb:10` sidecar (official compose envs: `MYSQL_*` on db, `DB_SERVER=db` on dvwa). curl present in image → healthcheck `curl -sf /login.php`. |
| VAmPI | `erev0s/vampi:latest`, `vulnerable=1`, internal :5000 → host 127.0.0.1:5002. No curl/wget in image; healthcheck via python urllib. |
| chainsaw | **No official image exists** (ghcr + Docker Hub both denied/absent; README has no Docker section). Repo moved `WithSecureLabs` → **`WithSecureOpenSource/chainsaw`**; v2.18+ ships **no musl build**. Resolution: fetch the `x86_64-unknown-linux-gnu` release binary (`scripts/fetch-zero-vm-data.sh`) into a `debian:bookworm-slim` container. Working live: 316 EVTX samples × full Sigma → 2.7 MB `findings.json` (first hit: T1098 DSRM, ATT&CK-tagged — the join-key evidence shape we designed for). |

## 6. Deferred to M4 (honest gaps)

- VM leg of the primary topology (VBox NAT `10.0.2.2:8000`) — needs M4-1 VM provisioning first.
- Nested-virtualization actual launch test (CPU is Intel ✓, but M4-0 preflight still runs the real check).
- Hyper-V Firewall rule details for Fallback A.
- `.wslconfig` memory raise for the full profile (GOAD ≥20 GB).

## 7. devbox topology (2026-11-24, post-migration)

The original host's VBox-under-Hyper-V path proved unusable for Windows guests
(NEM software emulation — see the M4 live-checklist BLOCKER). The VM leg moved
to **devbox** (Win10 Pro, i5-9400F, 16GB; Hyper-V role enabled 2026-11-24,
WSL capped at 6GB/4CPU via .wslconfig).

| Element | devbox reality |
|---|---|
| VM provider | **Hyper-V native** (root hypervisor — real VT-x, no NEM trap); vagrant 2.4.9 hyperv provider, `Default Switch` (no second switch created; VM↔VM and VM↔host both ride it) |
| Box pin | StefanScherer/windows_2019 **@2020.02.12** — newest version with a `hyperv` provider (2021.05.15 ships virtualbox/vmware only; Vagrant Cloud API verified). windows_10 hyperv caps at 2020.04.15 (wkst, later). |
| WSL networking mode | **NAT** (not mirrored) → host cannot reach WSL via loopback transparently; **`netsh interface portproxy`** on the Windows host forwards host:48999 (deps) and host:8889/18000 (Velo) to the WSL IP |
| Dep server | WSL `python3 -m http.server 48999` on `~/provision-files` (binds 0.0.0.0), reached from VM via gateway IP (Default Switch host vNIC) → portproxy → WSL. Provision scripts compute the gateway dynamically (`Get-NetRoute 0.0.0.0/0`) — same code works on the original VBox NAT path. |
| VM → Velo | VM → gateway:8889 → portproxy → WSL docker lab-net velociraptor (published 0.0.0.0:8889 inside WSL) |
| Deps source | fetched on the original host (proxy needed for github there), scp'd to devbox (3.4MB) — nothing binary in-repo unchanged |

Gotchas so far: winget source broken on devbox (0x8a15000f) → vagrant installed
via direct HashiCorp MSI; Tailscale did not come back unattended after the
Hyper-V reboot (needed one physical login — ops note, not a topology issue).
