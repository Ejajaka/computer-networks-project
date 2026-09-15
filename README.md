# eBPF/XDP Real-Time DDoS Detection & Mitigation

This project is a **copy and improvement** of the paper
**"eBPF-Based Real-Time DDoS Mitigation for IoT Edge Devices"**
(A. Tolay, Istinye University, July 2025) — arXiv:2508.00851.

- **Reproduced:** the paper's Docker-based **UDP flood** protection (spot a sender that
  is sending too fast, and throw its packets away at the network card).
- **Extended:** added **SYN flood** protection (spot a sender that is trying to start too
  many new connections at once), and combined **both** into one program.

> **▶ How to run it yourself:** see **[HOW_TO_RUN.md](HOW_TO_RUN.md)** — a step-by-step
> guide with the commands, what to expect, how it was built, and simple explanations.

> **🌐 Complete project explanation (website):** open
> **[`website/index.html`](website/index.html)** in any browser (or visit the repo's
> **GitHub Pages**). It explains the paper, our added SYN-flood + combined features,
> every line of code, the testbed, the results, and how to run it — in simple words
> with diagrams and an interactive demo.

---

## 1. What the results were

| Test | Paper | Our result |
|---|---|---|
| UDP flood dropped | ~99% | **99.7%** |
| SYN flood dropped | (not covered) | **99.9%** |
| Combined UDP + SYN dropped | — | **99.8%** |
| Normal traffic preserved | Yes | Yes (0% dropped below the limit) |
| Time from detection to blocking | < 2 s | < 2 s |

---

## 2. How it is put together

```
 attacker  --UDP/SYN flood-->  victim
  (172.30.0.20)                  |
                                 v
                         victim's network card
                                 |  (XDP: the very first stop)
                                 v
                     ddos_filter_kern.o
                     - UDP: drop a sender above 800 packets/s
                     - SYN: drop a sender above 200 new-connections/s
                                 |  leaves a note (bpf_printk)
                                 v
                   trace_pipe  -->  controller.py (helper program)
                                 |  firewall rule: block the attacker's IP
                                 v
                        alerts.log  (a record of events)
```

- **In the kernel (the filter):** bad packets are thrown away at the very first stop on
  the network card, before the computer spends memory and time on them. This is the fast
  part.
- **Outside the kernel (the controller):** a normal helper program reads the notes the
  filter leaves, blocks the attacker's IP with a firewall rule, and keeps a log. This is
  the flexible part.

---

## 3. The files

```
ebpf/
  hello_xdp.c          # quick test program (proves XDP works)
  udp_filter_kern.c    # UDP flood filter (reproduces the paper)
  syn_filter_kern.c    # SYN flood filter (our extension)
  ddos_filter_kern.c   # COMBINED UDP + SYN filter (our main program)
  Makefile             # build script (clang -> eBPF)
testbed/
  setup_testbed.sh     # creates the fake network + victim/attacker/benign
  ctl_udp.sh           # turn the filter on/off inside the victim
  bench_run.sh         # measures CPU and response time
  start_controller.sh  # starts the controller program
controller/
  controller.py        # reads notes, blocks attacker IP, logs events
results/
  UDP_results.md       # the measured results in detail
  alerts.log           # event log from the runs
```

---

## 4. Quick way to run it

**Easiest — one command does everything:**
```bash
make -C ebpf                     # build the filters (first time only)
sudo bash testbed/demo.sh        # builds network, attaches filter, runs attacks, prints results
```

**Manual, step by step:**
```bash
# 1. build the filters
cd ~/Desktop/CN/ebpf && make

# 2. build the fake network
cd ~/Desktop/CN/testbed && sudo bash setup_testbed.sh

# 3. put the combined filter on the victim
sudo docker cp ~/Desktop/CN/ebpf/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o
sudo docker exec victim bash -c '
  BPF=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp'

# 4. start the controller
cd ~/Desktop/CN/testbed && sudo bash start_controller.sh

# 5. launch a UDP flood (attack)
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10; done

# 6. read the drop counters
sudo docker exec victim bash -c '$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1) map dump name stats_map'
```

---

## 5. Things to keep in mind

- The filter works in **native XDP** mode on the victim's fake network card.
- On this 16-core computer, a ~100 Mbps flood doesn't fully use one core, so the CPU
  number doesn't change much with the filter on/off. The big CPU saving the paper shows
  appears on small devices (like a Raspberry Pi). The main result — the **~99% drop
  rate** — reproduces perfectly here.
- The limits (800 packets/s for UDP, 200 connections/s for SYN) are **fixed numbers**.
  If a normal user sends faster than the limit, they would be wrongly blocked too. This
  is a known weakness of the paper's simple design (see paper section 6.3).
