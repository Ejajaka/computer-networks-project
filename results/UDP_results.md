# Measured Results (in simple words)

All numbers below are real measurements from running the simulation on this computer.
Paper: arXiv 2508.00851.

**Where we ran it:** one computer (Linux Mint, kernel 6.8, 16 cores, 13 GB RAM).
**The fake network:** attacker (172.30.0.20) → fake switch → victim (172.30.0.10) → normal user (172.30.0.30).
**The filter:** attached inside the victim, on its network card (this is XDP — the earliest spot).

---

## 1. UDP flood protection (this reproduces the paper)

**How fast the attack was:** 4 flood programs at once → about 100 Mbps (the same speed
the paper used).

**The main result — how many bad packets were thrown away:**

| | Packets |
|---|---|
| Packets the filter saw | 3,430,479 |
| Packets thrown away (bad) | 3,421,663 |
| **Drop rate** | **99.7%** |

(The paper reported ~99% in Docker, >97% on a Raspberry Pi.)

**CPU used by the computer during the flood:**
- Filter OFF: about 37.8% of the computer's CPU
- Filter ON: about 37.7%

> Because this computer has 16 cores, the flood doesn't fully use any one core, so the
> CPU number doesn't change much. The paper's big CPU improvement (45% → 12%) shows up
> on small devices like a Raspberry Pi. The **drop rate** result works perfectly here.

**How fast the victim responded (ping) during the flood:**
- Filter OFF: about 0.066 ms (min 0.038, max 0.113)
- Filter ON: about 0.078 ms (min 0.046, max 0.134)

Both are stable — the flood didn't slow the victim down on this computer.

**Normal traffic is left alone (filter ON):**
- Normal UDP at 3 Mbps (about 250 packets/s, below the 800 limit): **0% dropped**
- Normal UDP at 10 Mbps (about 850 packets/s, above the 800 limit): 5.9% dropped

> This shows the "limit" number matters. The paper tested with ping (very slow), so its
> normal traffic was never affected. We used 3 Mbps to stay safely below the limit.

**How it decides to drop:**
- The filter keeps a list that remembers how many packets each sender has sent in the
  last 1 second.
- If a sender goes over **800 packets in 1 second**, that sender's packets start being
  thrown away.
- When it catches one, it leaves a note (`bpf_printk`) that the controller reads.

---

## 2. SYN flood protection (our new addition)

**How fast the attack was:** 4 SYN flood programs at once, to the victim.

**The main result:**

| | SYN packets |
|---|---|
| SYN packets the filter saw | 2,248,518 |
| SYN packets thrown away | 2,246,718 |
| **Drop rate** | **99.9%** |

**Normal traffic is left alone:**
- A normal TCP connection (one handshake) sends only 2 SYN packets — both passed,
  **0 dropped**.
- (A normal connection's 2 SYNs is way below the 200-connections-per-second limit.)

**How it decides to drop:**
- It looks at each TCP packet's flag to see if it is a "new connection" packet (SYN).
- It keeps a list of how many new-connection packets each sender has sent in the last
  1 second.
- If a sender goes over **200 per second**, that sender's SYN packets start being thrown
  away.

---

## 3. Combined UDP + SYN (one program stops both — our main result)

We put both protections into **one** program, and attacked with both floods at the same
time:

| Attack | Packets seen | Packets dropped | Drop rate |
|---|---|---|---|
| UDP flood | 2,535,743 | 2,528,543 | **99.7%** |
| SYN flood | 2,378,602 | 2,376,802 | **99.9%** |
| **Combined** | 4,914,345 | 4,905,345 | **99.8%** |

**End-to-end (filter + controller working together):**
- The controller read the note "SYN FLOOD detected from 172.30.0.20".
- It added a firewall rule inside the victim to block 172.30.0.20.
- It saved the event to `alerts.log`.
- Both kinds of attack were stopped by the single program, and normal TCP connections
  and slow UDP traffic passed through untouched.

---

## 4. What we changed vs. the paper

| | Paper | This project |
|---|---|---|
| UDP flood | ✓ | ✓ (reproduced, 99.7%) |
| SYN flood | not covered | ✓ (added, 99.9%) |
| Both in one program | no | ✓ (combined, 99.8%) |
| Kernel + controller design | ✓ | ✓ (same hybrid design) |
