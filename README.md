# eBPF/XDP Real-Time DDoS Detection and Mitigation
An eBPF/XDP testbed for detecting and dropping UDP and TCP SYN floods at the
network driver, before packets reach the normal Linux networking stack. The
project reproduces the UDP mitigation approach from Tolay (2025) and extends it
with SYN flood protection, a combined filter, a Python controller, and a live
web dashboard.

## Live demo

**https://ejajaka.github.io/computer-networks-project/**

The hosted page is an interactive browser model of the rate limiter and
dashboard. It does **not** execute eBPF or generate packets. The real
kernel/XDP implementation runs locally with the testbed commands below.

## Highlights

| Capability | Implementation |
|---|---|
| UDP flood protection | Per-source-IP packet rate, limit 800 packets/s |
| SYN flood protection | Per-source-IP SYN rate, limit 200 attempts/s |
| Combined defense | One XDP program handles both protocols |
| Early dropping | Native XDP before `sk_buff` allocation |
| Kernel-to-user alerts | `bpf_printk` to `trace_pipe` |
| Persistent blocking | Controller adds an `iptables` DROP rule |
| Live dashboard | Python backend, browser UI, packet-rate chart, resource model |
| CLI validation | Combined UDP + SYN tests and with/without-filter reports |

## Measured results

| Test | Result |
|---|---|
| UDP flood dropped | 99.6-99.8% |
| SYN flood dropped | 99.8-99.9% |
| Combined UDP + SYN dropped | ~99.7% |
| Legitimate UDP traffic | 0% dropped |
| Detection-to-block response | Under 2 seconds |

Measurements were taken in the local Docker testbed with `hping3` floods and
`iperf3` legitimate traffic.

## Architecture

```text
              +-----------------------------+
              | Attacker                    |
              | 172.30.0.20                 |
              +--------------+--------------+
                             |
                       UDP / SYN flood
                             v
              +-----------------------------+
              | Victim NIC (eth0)           |
              | 172.30.0.10                 |
              +--------------+--------------+
                             |
                             v
              +---------------------------------+
              | XDP filter                      |
              | engine/ddos_filter_kern.o       |
              |                                 |
              | parse IPv4 -> UDP / TCP SYN     |
              | per-source IP, 1 second window  |
              | UDP limit: 800 packets/s        |
              | SYN limit: 200 SYNs/s           |
              +------+--------------------+-----+
                     |                    |
                below limit          above limit
                     |                    |
                     v                    v
          +--------------------+ +------------------+
          | XDP_PASS           | | XDP_DROP         |
          +----------+---------+ +--------+---------+
                     |                    |
                     v                    v
        +------------------------+     packet discarded
        | Linux stack + iperf3   |    at the network card
        +------------------------+


## Repository layout

```text
engine/
  ddos_filter_kern.c      combined UDP + SYN XDP filter
  udp_filter_kern.c       UDP-only filter (paper reproduction)
  syn_filter_kern.c       SYN-only filter
  Makefile                compiles C sources to eBPF objects

sim/
  start_ui.sh             starts the local web simulator
  ui_server.py            backend, HTTP API, dashboard, resource model

site/
  index.html              hosted GitHub Pages demo
  style.css
  app.js                  browser-side model of the rate limiter

testbed/
  setup_testbed.sh        creates the Docker victim/attacker/benign network
  demo.sh                 one-command UDP + SYN + combined CLI demo
  report.sh               formal with/without-filter report
  bench_run.sh            CPU benchmark
  ctl_udp.sh              attach/detach the UDP filter
  start_controller.sh     starts the alert controller

controller/
  controller.py           reads kernel alerts, blocks the attacker IP, logs events

results/
  UDP_results.md          recorded measurements
  alerts.log              controller event log

docs/
  references/             paper PDF and extracted paper text

flowchart.txt             architecture, packet path, and control paths
COMMANDS.txt              web and CLI command reference
```

## Getting started

### Prerequisites

- Linux with Docker
- `clang`, `llvm`, `libbpf-dev`, `libelf-dev`, `pahole`
- `linux-tools-common`, `linux-tools-generic`
- `hping3`, `iperf3`

```bash
sudo apt update
sudo apt install -y docker.io clang llvm libbpf-dev libelf-dev pahole \
  linux-tools-common linux-tools-generic hping3 iperf3
sudo usermod -aG docker "$USER"
```

Log out and back in after adding the Docker group, or run the scripts with
`sudo`.

### Build the eBPF filters

```bash
make -C engine
```

This produces `engine/udp_filter_kern.o`, `engine/syn_filter_kern.o`, and
`engine/ddos_filter_kern.o`.

### Create the testbed

```bash
sudo bash testbed/setup_testbed.sh
```

The testbed creates three containers on `172.30.0.0/24`:

| Container | IP | Role |
|---|---|---|
| `victim` | 172.30.0.10 | Target, XDP attach point, `iperf3` server |
| `attacker` | 172.30.0.20 | Generates UDP/SYN floods |
| `benign` | 172.30.0.30 | Generates legitimate traffic |

### Run the local web simulator

```bash
bash sim/start_ui.sh
```

Open **http://localhost:8090**. Use the UDP, SYN, or combined flood buttons,
then toggle the XDP filter and watch the traffic, verdicts, and resource cards.

### Run the CLI demo

```bash
sudo bash testbed/demo.sh
```

Runs UDP, SYN, and combined floods, then verifies that legitimate traffic is
not dropped.

### Generate the formal report

```bash
sudo bash testbed/report.sh
```

Runs each scenario with the filter off and on, prints drop rates, host CPU,
victim CPU/memory model values, and optional GPU utilization. A shorter run can
be requested with:

```bash
DURATION=8 bash testbed/report.sh
```

## How the filter works

The combined filter uses two hash maps and one statistics map:

```text
rate_map   -> per-source UDP count + last timestamp
syn_map    -> per-source SYN count + last timestamp
stats_map  -> UDP/SYN total, dropped, and alert counters
```

For each protected packet:

```text
first packet from IP      -> create window with count = 1, XDP_PASS
window older than 1 s     -> reset count = 1, XDP_PASS
otherwise                 -> count += 1
count above limit         -> XDP_DROP
count at or below limit   -> XDP_PASS
```

Limits:

```text
UDP: 800 packets per second per source IP
SYN: 200 SYN packets per second per source IP
```

The filter only handles IPv4 UDP and TCP SYN. Other traffic is allowed through
to the normal Linux stack.

## Dashboard and controller

The local Python backend (`sim/ui_server.py`):

- Starts and stops UDP/SYN/combined floods.
- Loads, pins, attaches, and detaches the XDP program.
- Reads NIC counters, application counters, and `stats_map`.
- Computes per-second rates and PASS/DROP verdicts.
- Displays optional GPU usage when `nvidia-smi` is available.
- Models victim CPU and memory pressure from packets reaching the application.

The controller (`controller/controller.py`) reads alert messages from
`/sys/kernel/tracing/trace_pipe`, adds an `iptables` DROP rule for the attacker
IP inside the victim, and appends the event to `results/alerts.log`.

## Verification

The repository has been checked with:

- eBPF compilation via `make -C engine`.
- Python syntax checks for the backend and controller.
- Bash syntax checks for all testbed scripts.
- Live UDP, SYN, and combined flood tests.
- Web API and dashboard checks.
- No leftover flood workers after stopping.
- XDP detached after test completion.

## Limitations

- Thresholds are fixed; legitimate senders above the limit can be blocked.
- IPv4 UDP and TCP SYN only; IPv6 and other protocols pass through.
- No protection against source-IP spoofing.
- Rate-based detection does not catch low-and-slow application-layer attacks.
- CPU and memory resource cards are model estimates, not cgroup measurements.
- The Docker testbed is an emulation, not a hardware IoT deployment.
- GitHub Pages hosts a browser model only; the real eBPF/XDP path requires a
  local Linux kernel and Docker.

## References

- A. Tolay, *eBPF-Based Real-Time DDoS Mitigation for IoT Edge Devices*,
  arXiv:2508.00851, 2025. https://arxiv.org/abs/2508.00851
- T. Høiland-Jørgensen et al., *The eXpress Data Path: Fast Programmable Packet
  Processing in the Operating System Kernel*, CoNEXT 2018.
- Local copy: `docs/references/`
