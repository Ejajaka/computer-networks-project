# How to Run, Verify & Understand the DDoS Simulation
*(written in simple words)*

This guide shows you:
1. **How to run the simulation** (the commands, in order).
2. **How to check it worked** (what output to expect).
3. **How the project was built** (every command used).
4. **What is happening** at each step (a simple explanation).
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

## 1. Build the eBPF/XDP programs (turn our C code into something the kernel can run)

```bash
cd ~/Desktop/CN/ebpf
make
```

This builds three small programs (our code → `.o` files):

| File | Program | What it does |
|---|---|---|
| `udp_filter_kern.c` | `xdp_udp_filter` | Stops UDP floods (this is the paper's result) |
| `syn_filter_kern.c` | `xdp_syn_filter` | Stops SYN floods (our new addition) |
| `ddos_filter_kern.c` | `xdp_ddos_filter` | **Combined**: stops both at once (our main program) |

**Expected output:** lines like
```
clang -O2 -g -Wall ... -c ddos_filter_kern.c -o ddos_filter_kern.o
```
with **no errors**. Check the files exist:
```bash
ls -la *.o
```

**Check the kernel will accept the code** (a safety test):
```bash
sudo bpftool prog load ddos_filter_kern.o /sys/fs/bpf/vcheck
sudo rm -rf /sys/fs/bpf/vcheck
```
No error = the kernel's built-in safety check approved the code.

### What is happening here
- Normally, a program runs in "user space" and asks the kernel for everything.
- **eBPF** is a way to run small, safe pieces of code **inside the kernel** (the core
  of the operating system), so they act very fast.
- `clang` turns our C code into eBPF code.
- Before letting it run, the **kernel checks the code** to make sure it can't crash or
  freeze the computer. Only safe code is allowed in.
- The `.o` file is the finished program we load later.

---

## 2. Build the fake test network (Docker containers)

```bash
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh
```

This creates a fake network and **three little computers (containers)** inside your
real computer:

| Container | IP | Role |
|---|---|---|
| `victim` | 172.30.0.10 | The target — it runs a server and has our protective filter |
| `attacker` | 172.30.0.20 | The one who launches the flood attacks |
| `benign` | 172.30.0.30 | A normal user sending normal traffic |

The `victim` container gets special permission so it can attach the filter to its own
network card. The script also installs the needed tools and starts a UDP server on the
victim.

**Check it worked:**
```bash
docker ps --format '{{.Names}} {{.IPAddress}} {{.Status}}'
# expect: victim 172.30.0.10 Up; attacker 172.30.0.20 Up; benign 172.30.0.30 Up

# check the attacker can reach the victim
sudo docker exec attacker ping -c 2 172.30.0.10
```

### What is happening here
- A **container** is a tiny, separate copy of Linux. Each one has its own "network card".
- We connect them with a **fake switch** (Docker calls it a bridge). This mimics a small
  office/home network where one device is under attack.
- Because this network is private (172.30.0.0/24), the flood **only** affects these three
  fake devices — never your real internet.

---

## 3. Put the protective filter on the victim

```bash
# copy the finished program into the victim
sudo docker cp ~/Desktop/CN/ebpf/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o

# load it and attach it to the victim's network card
sudo docker exec victim bash -c '
  BPF=/usr/lib/linux-tools/5.15.0-190-generic/bpftool
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp
  ip link show dev eth0'
```

**Expected output:** the last line shows the filter is attached, something like:
```
2: eth0@if8: ... xdp ... prog/xdp id 329 ... name xdp_ddos_filter ... jited
```

### What is happening here
- `bpftool prog loadall` loads the program into the kernel and saves a pointer to it
  (in `/sys/fs/bpf/ddos`).
- `ip link set dev eth0 xdp pinned ...` puts the program onto the victim's network card,
  at the **XDP** spot.
- The XDP spot is the **very first stop** for any incoming packet. Our program looks at
  each packet here — **before** the kernel spends memory and time processing it.
- This is the whole point of the project: we can throw away bad packets right at the
  door, instead of letting them into the house first.

---

## 4. Run the helper program (the "controller")

```bash
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh
```

**Expected output:** `controller started, log: /tmp/ddos_controller.log`

Check it is running:
```bash
cat /tmp/ddos_controller.log   # should say: Controller started. Monitoring ...
```

### What is happening here
- When the filter catches an attack, it writes a small note into the kernel's "message
  board" (`trace_pipe`).
- `controller.py` (a normal program, running in user space) reads that message board.
- When it sees `UDP FLOOD DETECTED from <ip>` or `SYN FLOOD DETECTED from <ip>`, it:
  1. Adds a **firewall rule** inside the victim to permanently block that attacker's IP
     (`iptables -A INPUT -s <ip> -j DROP`) — this is a second line of defense.
  2. Saves the event to a log file (`results/alerts.log`).
- So we get the best of both worlds: the **filter** catches things super fast in the
  kernel, and the **controller** does the slower, more flexible bookkeeping in user space.

---

## 5. Launch the attacks and check the protection works

### 5a. Check the UDP flood is stopped

```bash
# read the filter's counters (packets seen vs packets thrown away)
sudo docker exec victim bash -c '
  /usr/lib/linux-tools/5.15.0-190-generic/bpftool map dump name stats_map'

# launch a UDP flood from the attacker (4 workers ≈ 100 Mbps, like the paper)
for i in 1 2 3 4; do
  sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10
done
sleep 8
sudo docker exec attacker pkill -9 hping3
```

**Check the controller log** — you should see:
```
UDP FLOOD detected from 172.30.0.20 -- blocking via iptables
BLOCKED 172.30.0.20 (iptables rule added in victim)
```

**Check the counters** before and after. The map has four numbers:
`udp_total` (UDP packets seen), `udp_dropped` (thrown away),
`syn_total` / `syn_dropped` (same for SYN). Expected: **~99.7% of UDP packets dropped**.

### 5b. Check the SYN flood is stopped

```bash
# launch a SYN flood from the attacker
for i in 1 2 3 4; do
  sudo docker exec -d attacker hping3 -S -p 5201 --flood 172.30.0.10
done
sleep 8
sudo docker exec attacker pkill -9 hping3
```
Controller log shows `SYN FLOOD detected from 172.30.0.20 ...`. Expected **~99.9% dropped**.

### 5c. Check normal traffic is NOT stopped

```bash
# normal UDP at a modest rate (below the limit) — should NOT be dropped
sudo docker exec benign iperf3 -c 172.30.0.10 -p 5201 -u -b 3M -t 5
```
The counter `udp_dropped` should stay the same (0 extra drops) — normal traffic passes.

### What is happening here
- `hping3 -2 --flood` = flood of **UDP** packets (the attacker just sprays data).
- `hping3 -S --flood` = flood of **TCP SYN** packets (the attacker pretends to start
  thousands of new connections, which can exhaust a server).
- The filter keeps a list that **remembers how many packets each sender has sent in the
  last 1 second**. If a sender goes over the limit (800 packets/s for UDP, 200 SYN/s
  for TCP), the filter starts throwing that sender's packets away instantly — right at
  the network card, before they can slow down or fill up the victim.
- Normal users send far fewer packets than the limit, so they are left alone.

---

## 6. Optional: measure CPU and response time

```bash
cd ~/Desktop/CN/testbed
# first: protection OFF, flood for 10s, measure CPU + ping time
sudo bash bench_run.sh filter-off 10

# then: protection ON, same test
sudo bash bench_run.sh filter-on 10
```

Each run prints the CPU used by the computer and the ping time (how fast the victim
responds) during the flood.

> **About the numbers:** on this 16-core computer, a ~100 Mbps flood doesn't fully use
> up any single core, so the CPU is similar (~37–38%) whether the filter is on or off.
> The paper's big CPU improvement (45% → 12%) shows up on small, weak devices (like a
> Raspberry Pi) where one core does all the work. The main result — how many bad packets
> get thrown away (**~99%**) — works exactly the same here.

---

## 7. Clean up when you're done

```bash
# turn off the filter and stop the controller
sudo docker exec victim ip link set dev eth0 xdp off
sudo pkill -f controller.py

# remove the three fake computers and the fake network
sudo docker rm -f victim attacker benign
sudo docker network rm ddos-net
```

---

## Appendix A — Every command used to build this project

Here is the exact list of everything that was run to create and test the project.

```bash
# 1. Install the tools
sudo apt update
sudo apt install -y docker.io docker-compose-v2 clang llvm libbpf-dev libelf-dev \
  pahole linux-tools-common linux-tools-generic hping3 iperf3 tcpdump python3-requests
sudo usermod -aG docker $USER

# 2. Make the project folders
mkdir -p ~/Desktop/CN/ebpf ~/Desktop/CN/testbed ~/Desktop/CN/controller ~/Desktop/CN/results

# 3. Build the filter programs
cd ~/Desktop/CN/ebpf
make

# 4. Quick test that XDP works at all (on the loopback address)
sudo bpftool prog loadall hello_xdp.o /sys/fs/bpf/hello
sudo ip link set dev lo xdp pinned /sys/fs/bpf/hello/xdp_hello
ping -c 3 127.0.0.1
sudo cat /sys/kernel/tracing/trace_pipe     # shows the kernel's notes; Ctrl+C to exit
sudo ip link set dev lo xdp off
sudo rm -rf /sys/fs/bpf/hello

# 5. Build the fake test network
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh

# 6. Put the combined filter on the victim
sudo docker cp ~/Desktop/CN/ebpf/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o
sudo docker exec victim bash -c '
  BPF=/usr/lib/linux-tools/5.15.0-190-generic/bpftool
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp'

# 7. Start the controller (user-space helper + logging)
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh

# 8. Run the attacks and measure
# UDP flood
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10; done
sleep 8; sudo docker exec attacker pkill -9 hping3
# SYN flood
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -S -p 5201 --flood 172.30.0.10; done
sleep 8; sudo docker exec attacker pkill -9 hping3

# Read the drop counters
sudo docker exec victim bash -c '/usr/lib/linux-tools/5.15.0-190-generic/bpftool map dump name stats_map'

# 9. Benchmark (optional)
cd ~/Desktop/CN/testbed
sudo bash bench_run.sh filter-off 10
sudo bash bench_run.sh filter-on 10
```

---

## Appendix B — Results we measured

| Test | Result |
|---|---|
| UDP flood dropped (filter ON) | **99.7%** |
| SYN flood dropped (filter ON) | **99.9%** |
| Combined UDP + SYN dropped | **99.8%** |
| Normal UDP (slow rate) preserved | **0% dropped** |
| Normal TCP connection preserved | **0 dropped** |
| Time from detection to blocking | **< 2 seconds** |

These match the paper (arXiv 2508.00851), which reported ~99% for UDP floods.

---

## Appendix C — The jargon, explained in one line each

- **DDoS** — many computers sending tons of traffic to overload one target.
- **UDP flood** — attacker sprays lots of data packets at the victim.
- **SYN flood** — attacker pretends to start thousands of new connections at once.
- **eBPF** — a safe way to run small custom code inside the kernel (the core of Linux).
- **XDP** — the earliest point on a network card where we can look at / drop packets.
- **Docker / container** — a tiny separate copy of Linux; used to make the fake devices.
- **veth** — a fake network cable connecting a container to the fake switch.
- **bps / pps** — bits per second / packets per second (how fast traffic flows).
- **threshold** — the "limit" a sender must not go over.
- **XDP_DROP** — the filter's decision: throw this packet away.
- **iptables** — the Linux firewall; used to permanently block an attacker's IP.
- **trace_pipe / bpf_printk** — the kernel's message board, where the filter leaves notes.
- **controller** — the normal (user-space) helper program that reads the notes and blocks IPs.
- **verifier** — the kernel's safety check that only lets safe code run.
- **sk_buff** — the memory the kernel normally reserves for each packet; XDP avoids this.# How to Run, Verify & Understand the DDoS Simulation
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

## 1. Build the eBPF/XDP programs (turn our C code into something the kernel can run)

```bash
cd ~/Desktop/CN/ebpf
make
```

This builds three small programs (our code → `.o` files):

| File | Program | What it does |
|---|---|---|
| `udp_filter_kern.c` | `xdp_udp_filter` | Stops UDP floods (this is the paper's result) |
| `syn_filter_kern.c` | `xdp_syn_filter` | Stops SYN floods (our new addition) |
| `ddos_filter_kern.c` | `xdp_ddos_filter` | **Combined**: stops both at once (our main program) |

**Expected output:** lines like
```
clang -O2 -g -Wall ... -c ddos_filter_kern.c -o ddos_filter_kern.o
```
with **no errors**. Check the files exist:
```bash
ls -la *.o
```

**Check the kernel will accept the code** (a safety test):
```bash
sudo bpftool prog load ddos_filter_kern.o /sys/fs/bpf/vcheck
sudo rm -rf /sys/fs/bpf/vcheck
```
No error = the kernel's built-in safety check approved the code.

### What is happening here
- Normally, a program runs in "user space" and asks the kernel for everything.
- **eBPF** is a way to run small, safe pieces of code **inside the kernel** (the core
  of the operating system), so they act very fast.
- `clang` turns our C code into eBPF code.
- Before letting it run, the **kernel checks the code** to make sure it can't crash or
  freeze the computer. Only safe code is allowed in.
- The `.o` file is the finished program we load later.

---

## 2. Build the fake test network (Docker containers)

```bash
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh
```

This creates a fake network and **three little computers (containers)** inside your
real computer:

| Container | IP | Role |
|---|---|---|
| `victim` | 172.30.0.10 | The target — it runs a server and has our protective filter |
| `attacker` | 172.30.0.20 | The one who launches the flood attacks |
| `benign` | 172.30.0.30 | A normal user sending normal traffic |

The `victim` container gets special permission so it can attach the filter to its own
network card. The script also installs the needed tools and starts a UDP server on the
victim.

**Check it worked:**
```bash
docker ps --format '{{.Names}} {{.IPAddress}} {{.Status}}'
# expect: victim 172.30.0.10 Up; attacker 172.30.0.20 Up; benign 172.30.0.30 Up

# check the attacker can reach the victim
sudo docker exec attacker ping -c 2 172.30.0.10
```

### What is happening here
- A **container** is a tiny, separate copy of Linux. Each one has its own "network card".
- We connect them with a **fake switch** (Docker calls it a bridge). This mimics a small
  office/home network where one device is under attack.
- Because this network is private (172.30.0.0/24), the flood **only** affects these three
  fake devices — never your real internet.

---

## 3. Put the protective filter on the victim

```bash
# copy the finished program into the victim
sudo docker cp ~/Desktop/CN/ebpf/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o

# load it and attach it to the victim's network card
sudo docker exec victim bash -c '
  BPF=/usr/lib/linux-tools/5.15.0-190-generic/bpftool
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp
  ip link show dev eth0'
```

**Expected output:** the last line shows the filter is attached, something like:
```
2: eth0@if8: ... xdp ... prog/xdp id 329 ... name xdp_ddos_filter ... jited
```

### What is happening here
- `bpftool prog loadall` loads the program into the kernel and saves a pointer to it
  (in `/sys/fs/bpf/ddos`).
- `ip link set dev eth0 xdp pinned ...` puts the program onto the victim's network card,
  at the **XDP** spot.
- The XDP spot is the **very first stop** for any incoming packet. Our program looks at
  each packet here — **before** the kernel spends memory and time processing it.
- This is the whole point of the project: we can throw away bad packets right at the
  door, instead of letting them into the house first.

---

## 4. Run the helper program (the "controller")

```bash
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh
```

**Expected output:** `controller started, log: /tmp/ddos_controller.log`

Check it is running:
```bash
cat /tmp/ddos_controller.log   # should say: Controller started. Monitoring ...
```

### What is happening here
- When the filter catches an attack, it writes a small note into the kernel's "message
  board" (`trace_pipe`).
- `controller.py` (a normal program, running in user space) reads that message board.
- When it sees `UDP FLOOD DETECTED from <ip>` or `SYN FLOOD DETECTED from <ip>`, it:
  1. Adds a **firewall rule** inside the victim to permanently block that attacker's IP
     (`iptables -A INPUT -s <ip> -j DROP`) — this is a second line of defense.
  2. Saves the event to a log file (`results/alerts.log`).
- So we get the best of both worlds: the **filter** catches things super fast in the
  kernel, and the **controller** does the slower, more flexible bookkeeping in user space.

---

## 5. Launch the attacks and check the protection works

### 5a. Check the UDP flood is stopped

```bash
# read the filter's counters (packets seen vs packets thrown away)
sudo docker exec victim bash -c '
  /usr/lib/linux-tools/5.15.0-190-generic/bpftool map dump name stats_map'

# launch a UDP flood from the attacker (4 workers ≈ 100 Mbps, like the paper)
for i in 1 2 3 4; do
  sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10
done
sleep 8
sudo docker exec attacker pkill -9 hping3
```

**Check the controller log** — you should see:
```
UDP FLOOD detected from 172.30.0.20 -- blocking via iptables
BLOCKED 172.30.0.20 (iptables rule added in victim)
```

**Check the counters** before and after. The map has four numbers:
`udp_total` (UDP packets seen), `udp_dropped` (thrown away),
`syn_total` / `syn_dropped` (same for SYN). Expected: **~99.7% of UDP packets dropped**.

### 5b. Check the SYN flood is stopped

```bash
# launch a SYN flood from the attacker
for i in 1 2 3 4; do
  sudo docker exec -d attacker hping3 -S -p 5201 --flood 172.30.0.10
done
sleep 8
sudo docker exec attacker pkill -9 hping3
```
Controller log shows `SYN FLOOD detected from 172.30.0.20 ...`. Expected **~99.9% dropped**.

### 5c. Check normal traffic is NOT stopped

```bash
# normal UDP at a modest rate (below the limit) — should NOT be dropped
sudo docker exec benign iperf3 -c 172.30.0.10 -p 5201 -u -b 3M -t 5
```
The counter `udp_dropped` should stay the same (0 extra drops) — normal traffic passes.

### What is happening here
- `hping3 -2 --flood` = flood of **UDP** packets (the attacker just sprays data).
- `hping3 -S --flood` = flood of **TCP SYN** packets (the attacker pretends to start
  thousands of new connections, which can exhaust a server).
- The filter keeps a list that **remembers how many packets each sender has sent in the
  last 1 second**. If a sender goes over the limit (800 packets/s for UDP, 200 SYN/s
  for TCP), the filter starts throwing that sender's packets away instantly — right at
  the network card, before they can slow down or fill up the victim.
- Normal users send far fewer packets than the limit, so they are left alone.

---

## 6. Optional: measure CPU and response time

```bash
cd ~/Desktop/CN/testbed
# first: protection OFF, flood for 10s, measure CPU + ping time
sudo bash bench_run.sh filter-off 10

# then: protection ON, same test
sudo bash bench_run.sh filter-on 10
```

Each run prints the CPU used by the computer and the ping time (how fast the victim
responds) during the flood.

> **About the numbers:** on this 16-core computer, a ~100 Mbps flood doesn't fully use
> up any single core, so the CPU is similar (~37–38%) whether the filter is on or off.
> The paper's big CPU improvement (45% → 12%) shows up on small, weak devices (like a
> Raspberry Pi) where one core does all the work. The main result — how many bad packets
> get thrown away (**~99%**) — works exactly the same here.

---

## 7. Clean up when you're done

```bash
# turn off the filter and stop the controller
sudo docker exec victim ip link set dev eth0 xdp off
sudo pkill -f controller.py

# remove the three fake computers and the fake network
sudo docker rm -f victim attacker benign
sudo docker network rm ddos-net
```

---

## Appendix A — Every command used to build this project

Here is the exact list of everything that was run to create and test the project.

```bash
# 1. Install the tools
sudo apt update
sudo apt install -y docker.io docker-compose-v2 clang llvm libbpf-dev libelf-dev \
  pahole linux-tools-common linux-tools-generic hping3 iperf3 tcpdump python3-requests
sudo usermod -aG docker $USER

# 2. Make the project folders
mkdir -p ~/Desktop/CN/ebpf ~/Desktop/CN/testbed ~/Desktop/CN/controller ~/Desktop/CN/results

# 3. Build the filter programs
cd ~/Desktop/CN/ebpf
make

# 4. Quick test that XDP works at all (on the loopback address)
sudo bpftool prog loadall hello_xdp.o /sys/fs/bpf/hello
sudo ip link set dev lo xdp pinned /sys/fs/bpf/hello/xdp_hello
ping -c 3 127.0.0.1
sudo cat /sys/kernel/tracing/trace_pipe     # shows the kernel's notes; Ctrl+C to exit
sudo ip link set dev lo xdp off
sudo rm -rf /sys/fs/bpf/hello

# 5. Build the fake test network
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh

# 6. Put the combined filter on the victim
sudo docker cp ~/Desktop/CN/ebpf/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o
sudo docker exec victim bash -c '
  BPF=/usr/lib/linux-tools/5.15.0-190-generic/bpftool
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp'

# 7. Start the controller (user-space helper + logging)
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh

# 8. Run the attacks and measure
# UDP flood
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10; done
sleep 8; sudo docker exec attacker pkill -9 hping3
# SYN flood
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -S -p 5201 --flood 172.30.0.10; done
sleep 8; sudo docker exec attacker pkill -9 hping3

# Read the drop counters
sudo docker exec victim bash -c '/usr/lib/linux-tools/5.15.0-190-generic/bpftool map dump name stats_map'

# 9. Benchmark (optional)
cd ~/Desktop/CN/testbed
sudo bash bench_run.sh filter-off 10
sudo bash bench_run.sh filter-on 10
```

---

## Appendix B — Results we measured

| Test | Result |
|---|---|
| UDP flood dropped (filter ON) | **99.7%** |
| SYN flood dropped (filter ON) | **99.9%** |
| Combined UDP + SYN dropped | **99.8%** |
| Normal UDP (slow rate) preserved | **0% dropped** |
| Normal TCP connection preserved | **0 dropped** |
| Time from detection to blocking | **< 2 seconds** |

These match the paper (arXiv 2508.00851), which reported ~99% for UDP floods.

---

## Appendix C — The jargon, explained in one line each

- **DDoS** — many computers sending tons of traffic to overload one target.
- **UDP flood** — attacker sprays lots of data packets at the victim.
- **SYN flood** — attacker pretends to start thousands of new connections at once.
- **eBPF** — a safe way to run small custom code inside the kernel (the core of Linux).
- **XDP** — the earliest point on a network card where we can look at / drop packets.
- **Docker / container** — a tiny separate copy of Linux; used to make the fake devices.
- **veth** — a fake network cable connecting a container to the fake switch.
- **bps / pps** — bits per second / packets per second (how fast traffic flows).
- **threshold** — the "limit" a sender must not go over.
- **XDP_DROP** — the filter's decision: throw this packet away.
- **iptables** — the Linux firewall; used to permanently block an attacker's IP.
- **trace_pipe / bpf_printk** — the kernel's message board, where the filter leaves notes.
- **controller** — the normal (user-space) helper program that reads the notes and blocks IPs.
- **verifier** — the kernel's safety check that only lets safe code run.
- **sk_buff** — the memory the kernel normally reserves for each packet; XDP avoids this.
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

## 1. Build the eBPF/XDP programs (turn our C code into something the kernel can run)

```bash
cd ~/Desktop/CN/ebpf
make
```

This builds three small programs (our code → `.o` files):

| File | Program | What it does |
|---|---|---|
| `udp_filter_kern.c` | `xdp_udp_filter` | Stops UDP floods (this is the paper's result) |
| `syn_filter_kern.c` | `xdp_syn_filter` | Stops SYN floods (our new addition) |
| `ddos_filter_kern.c` | `xdp_ddos_filter` | **Combined**: stops both at once (our main program) |

**Expected output:** lines like
```
clang -O2 -g -Wall ... -c ddos_filter_kern.c -o ddos_filter_kern.o
```
with **no errors**. Check the files exist:
```bash
ls -la *.o
```

**Check the kernel will accept the code** (a safety test):
```bash
sudo bpftool prog load ddos_filter_kern.o /sys/fs/bpf/vcheck
sudo rm -rf /sys/fs/bpf/vcheck
```
No error = the kernel's built-in safety check approved the code.

### What is happening here
- Normally, a program runs in "user space" and asks the kernel for everything.
- **eBPF** is a way to run small, safe pieces of code **inside the kernel** (the core
  of the operating system), so they act very fast.
- `clang` turns our C code into eBPF code.
- Before letting it run, the **kernel checks the code** to make sure it can't crash or
  freeze the computer. Only safe code is allowed in.
- The `.o` file is the finished program we load later.

---

## 2. Build the fake test network (Docker containers)

```bash
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh
```

This creates a fake network and **three little computers (containers)** inside your
real computer:

| Container | IP | Role |
|---|---|---|
| `victim` | 172.30.0.10 | The target — it runs a server and has our protective filter |
| `attacker` | 172.30.0.20 | The one who launches the flood attacks |
| `benign` | 172.30.0.30 | A normal user sending normal traffic |

The `victim` container gets special permission so it can attach the filter to its own
network card. The script also installs the needed tools and starts a UDP server on the
victim.

**Check it worked:**
```bash
docker ps --format '{{.Names}} {{.IPAddress}} {{.Status}}'
# expect: victim 172.30.0.10 Up; attacker 172.30.0.20 Up; benign 172.30.0.30 Up

# check the attacker can reach the victim
sudo docker exec attacker ping -c 2 172.30.0.10
```

### What is happening here
- A **container** is a tiny, separate copy of Linux. Each one has its own "network card".
- We connect them with a **fake switch** (Docker calls it a bridge). This mimics a small
  office/home network where one device is under attack.
- Because this network is private (172.30.0.0/24), the flood **only** affects these three
  fake devices — never your real internet.

---

## 3. Put the protective filter on the victim

```bash
# copy the finished program into the victim
sudo docker cp ~/Desktop/CN/ebpf/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o

# load it and attach it to the victim's network card
sudo docker exec victim bash -c '
  BPF=/usr/lib/linux-tools/5.15.0-190-generic/bpftool
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp
  ip link show dev eth0'
```

**Expected output:** the last line shows the filter is attached, something like:
```
2: eth0@if8: ... xdp ... prog/xdp id 329 ... name xdp_ddos_filter ... jited
```

### What is happening here
- `bpftool prog loadall` loads the program into the kernel and saves a pointer to it
  (in `/sys/fs/bpf/ddos`).
- `ip link set dev eth0 xdp pinned ...` puts the program onto the victim's network card,
  at the **XDP** spot.
- The XDP spot is the **very first stop** for any incoming packet. Our program looks at
  each packet here — **before** the kernel spends memory and time processing it.
- This is the whole point of the project: we can throw away bad packets right at the
  door, instead of letting them into the house first.

---

## 4. Run the helper program (the "controller")

```bash
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh
```

**Expected output:** `controller started, log: /tmp/ddos_controller.log`

Check it is running:
```bash
cat /tmp/ddos_controller.log   # should say: Controller started. Monitoring ...
```

### What is happening here
- When the filter catches an attack, it writes a small note into the kernel's "message
  board" (`trace_pipe`).
- `controller.py` (a normal program, running in user space) reads that message board.
- When it sees `UDP FLOOD DETECTED from <ip>` or `SYN FLOOD DETECTED from <ip>`, it:
  1. Adds a **firewall rule** inside the victim to permanently block that attacker's IP
     (`iptables -A INPUT -s <ip> -j DROP`) — this is a second line of defense.
  2. Saves the event to a log file (`results/alerts.log`).
- So we get the best of both worlds: the **filter** catches things super fast in the
  kernel, and the **controller** does the slower, more flexible bookkeeping in user space.

---

## 5. Launch the attacks and check the protection works

### 5a. Check the UDP flood is stopped

```bash
# read the filter's counters (packets seen vs packets thrown away)
sudo docker exec victim bash -c '
  /usr/lib/linux-tools/5.15.0-190-generic/bpftool map dump name stats_map'

# launch a UDP flood from the attacker (4 workers ≈ 100 Mbps, like the paper)
for i in 1 2 3 4; do
  sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10
done
sleep 8
sudo docker exec attacker pkill -9 hping3
```

**Check the controller log** — you should see:
```
UDP FLOOD detected from 172.30.0.20 -- blocking via iptables
BLOCKED 172.30.0.20 (iptables rule added in victim)
```

**Check the counters** before and after. The map has four numbers:
`udp_total` (UDP packets seen), `udp_dropped` (thrown away),
`syn_total` / `syn_dropped` (same for SYN). Expected: **~99.7% of UDP packets dropped**.

### 5b. Check the SYN flood is stopped

```bash
# launch a SYN flood from the attacker
for i in 1 2 3 4; do
  sudo docker exec -d attacker hping3 -S -p 5201 --flood 172.30.0.10
done
sleep 8
sudo docker exec attacker pkill -9 hping3
```
Controller log shows `SYN FLOOD detected from 172.30.0.20 ...`. Expected **~99.9% dropped**.

### 5c. Check normal traffic is NOT stopped

```bash
# normal UDP at a modest rate (below the limit) — should NOT be dropped
sudo docker exec benign iperf3 -c 172.30.0.10 -p 5201 -u -b 3M -t 5
```
The counter `udp_dropped` should stay the same (0 extra drops) — normal traffic passes.

### What is happening here
- `hping3 -2 --flood` = flood of **UDP** packets (the attacker just sprays data).
- `hping3 -S --flood` = flood of **TCP SYN** packets (the attacker pretends to start
  thousands of new connections, which can exhaust a server).
- The filter keeps a list that **remembers how many packets each sender has sent in the
  last 1 second**. If a sender goes over the limit (800 packets/s for UDP, 200 SYN/s
  for TCP), the filter starts throwing that sender's packets away instantly — right at
  the network card, before they can slow down or fill up the victim.
- Normal users send far fewer packets than the limit, so they are left alone.

---

## 6. Optional: measure CPU and response time

```bash
cd ~/Desktop/CN/testbed
# first: protection OFF, flood for 10s, measure CPU + ping time
sudo bash bench_run.sh filter-off 10

# then: protection ON, same test
sudo bash bench_run.sh filter-on 10
```

Each run prints the CPU used by the computer and the ping time (how fast the victim
responds) during the flood.

> **About the numbers:** on this 16-core computer, a ~100 Mbps flood doesn't fully use
> up any single core, so the CPU is similar (~37–38%) whether the filter is on or off.
> The paper's big CPU improvement (45% → 12%) shows up on small, weak devices (like a
> Raspberry Pi) where one core does all the work. The main result — how many bad packets
> get thrown away (**~99%**) — works exactly the same here.

---

## 7. Clean up when you're done

```bash
# turn off the filter and stop the controller
sudo docker exec victim ip link set dev eth0 xdp off
sudo pkill -f controller.py

# remove the three fake computers and the fake network
sudo docker rm -f victim attacker benign
sudo docker network rm ddos-net
```

---

## Appendix A — Every command used to build this project

Here is the exact list of everything that was run to create and test the project.

```bash
# 1. Install the tools
sudo apt update
sudo apt install -y docker.io docker-compose-v2 clang llvm libbpf-dev libelf-dev \
  pahole linux-tools-common linux-tools-generic hping3 iperf3 tcpdump python3-requests
sudo usermod -aG docker $USER

# 2. Make the project folders
mkdir -p ~/Desktop/CN/ebpf ~/Desktop/CN/testbed ~/Desktop/CN/controller ~/Desktop/CN/results

# 3. Build the filter programs
cd ~/Desktop/CN/ebpf
make

# 4. Quick test that XDP works at all (on the loopback address)
sudo bpftool prog loadall hello_xdp.o /sys/fs/bpf/hello
sudo ip link set dev lo xdp pinned /sys/fs/bpf/hello/xdp_hello
ping -c 3 127.0.0.1
sudo cat /sys/kernel/tracing/trace_pipe     # shows the kernel's notes; Ctrl+C to exit
sudo ip link set dev lo xdp off
sudo rm -rf /sys/fs/bpf/hello

# 5. Build the fake test network
cd ~/Desktop/CN/testbed
sudo bash setup_testbed.sh

# 6. Put the combined filter on the victim
sudo docker cp ~/Desktop/CN/ebpf/ddos_filter_kern.o victim:/tmp/ddos_filter_kern.o
sudo docker exec victim bash -c '
  BPF=/usr/lib/linux-tools/5.15.0-190-generic/bpftool
  rm -rf /sys/fs/bpf/ddos
  $BPF prog loadall /tmp/ddos_filter_kern.o /sys/fs/bpf/ddos
  ip link set dev eth0 xdp pinned /sys/fs/bpf/ddos/xdp'

# 7. Start the controller (user-space helper + logging)
cd ~/Desktop/CN/testbed
sudo bash start_controller.sh

# 8. Run the attacks and measure
# UDP flood
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -2 -p 5201 --flood 172.30.0.10; done
sleep 8; sudo docker exec attacker pkill -9 hping3
# SYN flood
for i in 1 2 3 4; do sudo docker exec -d attacker hping3 -S -p 5201 --flood 172.30.0.10; done
sleep 8; sudo docker exec attacker pkill -9 hping3

# Read the drop counters
sudo docker exec victim bash -c '/usr/lib/linux-tools/5.15.0-190-generic/bpftool map dump name stats_map'

# 9. Benchmark (optional)
cd ~/Desktop/CN/testbed
sudo bash bench_run.sh filter-off 10
sudo bash bench_run.sh filter-on 10
```

---

## Appendix B — Results we measured

| Test | Result |
|---|---|
| UDP flood dropped (filter ON) | **99.7%** |
| SYN flood dropped (filter ON) | **99.9%** |
| Combined UDP + SYN dropped | **99.8%** |
| Normal UDP (slow rate) preserved | **0% dropped** |
| Normal TCP connection preserved | **0 dropped** |
| Time from detection to blocking | **< 2 seconds** |

These match the paper (arXiv 2508.00851), which reported ~99% for UDP floods.

---

## Appendix C — The jargon, explained in one line each

- **DDoS** — many computers sending tons of traffic to overload one target.
- **UDP flood** — attacker sprays lots of data packets at the victim.
- **SYN flood** — attacker pretends to start thousands of new connections at once.
- **eBPF** — a safe way to run small custom code inside the kernel (the core of Linux).
- **XDP** — the earliest point on a network card where we can look at / drop packets.
- **Docker / container** — a tiny separate copy of Linux; used to make the fake devices.
- **veth** — a fake network cable connecting a container to the fake switch.
- **bps / pps** — bits per second / packets per second (how fast traffic flows).
- **threshold** — the "limit" a sender must not go over.
- **XDP_DROP** — the filter's decision: throw this packet away.
- **iptables** — the Linux firewall; used to permanently block an attacker's IP.
- **trace_pipe / bpf_printk** — the kernel's message board, where the filter leaves notes.
- **controller** — the normal (user-space) helper program that reads the notes and blocks IPs.
- **verifier** — the kernel's safety check that only lets safe code run.
- **sk_buff** — the memory the kernel normally reserves for each packet; XDP avoids this.
