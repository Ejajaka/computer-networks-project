# Live DDoS Mitigation Simulator UI

An interactive browser UI where the attacker floods the victim for **2 minutes**, and
you can **toggle the eBPF/XDP filter ON/OFF live** to see the difference in real time.

## What it shows (updating every second)

| Metric | Meaning |
|---|---|
| **Packets hitting NIC** | packets arriving at the victim's network card (before XDP) |
| **Packets reaching app** | packets delivered to the IP stack **after** XDP — this crashes to near zero when the filter is ON |
| **Drop rate** | % of packets the filter threw away at the NIC |

## How to run

```bash
bash ~/Desktop/CN/sim/start_ui.sh
```

Then open **http://localhost:8090** in your browser.

To stop:
```bash
pkill -f sim/ui_server.py
```

## How to use it

1. Click **Start 2-minute Flood** — the attacker begins flooding continuously.
2. Watch the numbers. With the filter **OFF**, "packets reaching app" is high (the
   flood reaches the victim).
3. Click the **Filter** button to turn it **ON** — "packets reaching app" drops to
   near zero and the drop rate shows ~99.8%.
4. Toggle it **OFF** and **ON** again to compare live.
5. The chart shows two lines (NIC vs App) — when the filter turns on, the "App" line
   falls to the bottom.

## What you should see

| Filter | Packets hitting NIC | Packets reaching app | Drop rate |
|---|---|---|---|
| OFF | ~350,000 /s | ~350,000 /s | 0% |
| ON | ~400,000 /s | ~700 /s | ~99.8% |

This is the visual proof: the flood still hits the network card, but with the filter ON,
almost nothing reaches the application.

## Notes
- No `sudo` needed — it uses Docker (your user is in the `docker` group).
- The server auto-starts the containers, copies the program, and starts the victim's
  service when you launch it.
- The flood runs for exactly 120 seconds, then stops by itself (or press Stop).
