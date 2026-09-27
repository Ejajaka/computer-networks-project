# How to Run, Verify & Understand the DDoS Simulation
*(written in simple words)*

This guide shows you:
1. **How to run the simulation** (the commands, in order).
2. **How to check it worked** (what output to expect).
3. **How the project was built** (every command used).
4. **What is happening** at each step (a simple explanation).

Everything runs on **one** Linux computer (this one). The attack stays inside a
**private fake network** on your computer — it never touches your real internet.

---

## 0. Prerequisites (what you must install first)

You need administrator rights (sudo). Install these:

```bash
# update the list of available software
sudo apt update

# Docker + the tools to build eBPF programs + the attack tools
sudo apt install -y docker.io docker-compose-v2 \
  clang llvm libbpf-dev libelf-dev pahole \
  linux-tools-common linux-tools-generic \
  hping3 iperf3 tcpdump python3-requests

# let your username use docker (then log out/in, or run: newgrp docker)
sudo usermod -aG docker $USER
```

**Check it worked:**
```bash
docker run --rm hello-world     # should print "Hello from Docker!"
clang --version                 # should show a version number
```

> **Why these?** `docker` makes the private fake network. `clang`/`libbpf-dev` build
> the special kernel code. `bpftool` loads that code. `hping3` makes the attacks.
> `iperf3` makes normal (good) traffic.

---

## 1. THE EASY WAY — run the whole simulation with one command

A script called `demo.sh` does EVERYTHING for you: builds the network, attaches the
filter, starts the controller, runs both attacks, measures the drop rate, and checks
that normal traffic is preserved.

```bash
cd ~/Desktop/CN
make -C engine            # build the filter programs (first time only)
sudo bash testbed/demo.sh
```

**What you will see** (the important numbers):
```
==> Step 4: UDP flood test
    UDP: seen=1673607 dropped=1666407  drop_rate=99.6%
==> Step 5: SYN flood test
    SYN: seen=2126412 dropped=2124612  drop_rate=99.9%
==> Step 6: legitimate traffic test
    benign UDP extra drops: 0  (expected: 0)
==> Step 7: controller log
    UDP FLOOD detected from 172.30.0.20 -- blocking via iptables
    BLOCKED 172.30.0.20 (iptables rule added in victim)
```

That is the whole simulation. The drop rate should be **~99%** for UDP and SYN floods,
and **0** extra drops for normal traffic. This proves the problem is solved.

---

## 2. The MANUAL way — step by step (if you want to see it yourself)

Same as above but done command-by-command so you can watch each part.

### Step A — build the filter programs
```bash
cd ~/Desktop/CN/engine
make
```
Creates `.o` files: `udp_filter_kern.o`, `syn_filter_kern.o`, `ddos_filter_kern.o`.
(No errors = the kernel's safety check will accept them.)

### Step B — build the fake test network
```bash
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh
```
Creates the private network (172.30.0.0/24) and three containers:

| Container | IP | Role |
|---|---|---|
| `victim` | 172.30.0.10 | The target; runs a server; gets the filter |
| `attacker` | 172.30.0.20 | Launches the floods |
| `benign` | 172.30.0.30 | Sends normal traffic |

Check: `docker ps` → all three show **Up**.

### Step C — attach the combined filter to the victim
```bash
sudo docker cp ~/Desktop/CN/engine/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o
sudo docker exec victim bash -c '
  BPF=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp
  ip link show dev eth0'
```
The last line should show `xdp` and `xdp_ddos_filter` — the filter is now live at the
earliest point on the victim's network card.

### Step D — start the controller (the "observer")
```bash
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh
```
It reads the kernel's message board, blocks attackers with a firewall rule, and logs.

### Step E — launch a UDP flood and check
```bash
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10; done
sleep 8
sudo docker exec attacker pkill -9 hping3
```
Check the drop counters (reads `udp_total` and `udp_dropped`):
```bash
sudo docker exec victim bash -c '
  BPF=$(ls /usr/lib/linux-tools/*/bpftool 2>/dev/null | head -1)
  $BPF map dump name stats_map'
```
Expected: `udp_dropped` ≈ **99%** of `udp_total`. Controller log shows the alert + block.

### Step F — launch a SYN flood and check
```bash
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -S -p 5201 --flood 172.30.0.10; done
sleep 8
sudo docker exec attacker pkill -9 hping3
```
Same check → `syn_dropped` ≈ **99%** of `syn_total`.

### Step G — prove normal traffic is NOT blocked
```bash
sudo docker exec benign iperf3 -c 172.30.0.10 -p 5201 -u -b 3M -t 5
```
Re-read the counters — `udp_dropped` should **NOT** have increased.

### Step H — clean up when done
```bash
sudo docker exec victim ip link set dev eth0 xdp off
sudo pkill -f controller.py
sudo docker rm -f victim attacker benign
sudo docker network rm ddos-net
```

---

## 3. The results we measured

| Test | Result |
|---|---|
| UDP flood dropped (filter ON) | **99.6–99.8%** |
| SYN flood dropped (filter ON) | **99.8–99.9%** |
| Combined UDP + SYN dropped | **~99.8%** |
| Normal UDP (slow rate) preserved | **0% dropped** |
| Normal TCP connection preserved | **0 dropped** |
| Time from detection to blocking | **< 2 seconds** |

These match the paper (arXiv 2508.00851), which reported ~99% for UDP floods.

---

## 4. What is actually happening (the simple explanation)

**The problem:** normal firewalls sit INSIDE the network stack. By the time they see a
packet, the kernel has already spent memory and CPU on it. Under a flood, the kernel
runs out of resources before the firewall can drop anything.

**The solution (this project):**
- **XDP** = the very FIRST stop on the network card. We look at every packet here,
  BEFORE the kernel reserves any memory for it.
- **eBPF** = a safe way to run our own small code at that XDP spot. The kernel's safety
  check ("verifier") guarantees the code cannot crash or hang the system.
- Our code keeps a list of how many packets / how many new connections each sender has
  sent in the last 1 second. If a sender goes over the limit (800 packets/s for UDP,
  200 connections/s for SYN), we throw that sender's packets away instantly.
- Normal users send far below the limit, so they pass through untouched.
- When an attack is caught, the code leaves a note; the controller reads the note,
  blocks the attacker's IP with a firewall rule, and logs the event.

**Result:** attacks are stopped at the front door, before they use any resources, while
normal users keep working.

---

## 5. Common problems and fixes

| Problem | Fix |
|---|---|
| `container ... is not running` | The machine rebooted. Run `sudo docker start victim attacker benign` |
| `bpftool: No such file or directory` | The victim was recreated. Run `demo.sh` — it installs bpftool automatically |
| `iptables: not found` | Run `demo.sh` — it installs iptables in the victim automatically |
| `sudo: password for sanjeev` | Type your password and press Enter |
| Drop rate slightly below 99% | Normal variance; still a success (paper reports ~99%) |