# Wi-Fi Scanner

A Kismet/Flipper-style Wi-Fi reconnaissance and pentesting tool for the Romhack Camp Badge 2026,
built on the ESP32-S3's native Wi-Fi radio. It replaces the stock Tactility Wi-Fi scanner app
while keeping the same app slot (music player is untouched).

> ⚠️ **Use only on networks and devices you own or are explicitly authorized to test.**
> Passive capture (promiscuous sniffing, handshake/PMKID collection) is generally legal to
> observe on your own network; actively attacking a network you don't own or lack written
> authorization for is illegal in most jurisdictions. This firmware does not perform any
> action for you - it's a tool, and you are responsible for how you use it.

## Hardware notes

- The badge's Wi-Fi antenna is a **PCB trace integrated into the ESP32-S3 module** - there is
  no u.FL connector for it (the two u.FL connectors on the board are for the 13.56 MHz RFID/NFC
  front-end). **No external Wi-Fi antenna or USB Wi-Fi adapter (e.g. Alfa Networks) is possible.**
- The USB-C port goes **directly to the ESP32-S3's native USB-OTG pins** (no CP2102/CH340
  bridge chip). This is what makes USB mass-storage mode (below) possible without extra hardware.

## Modes

The toolbar on the graph page has three buttons:

| Button | Mode | What it does |
| --- | --- | --- |
| Scan | `ActiveScan` | Regular IDF Wi-Fi scan (same behaviour as the original Tactility app) |
| CH   | `Capture`    | Promiscuous passive capture with channel hopping (see below) |
| Stop | `Stopped`    | Freezes the radio and the UI on the last known data |

Each mode drives a different LED pattern on the badge's RGB strip (green sonar while scanning,
red sonar while capturing, and the previous LED configuration is restored on Stop).

## Passive capture & channel hopping

In `Capture` mode the radio goes into promiscuous mode and hops across channels, weighted
Kismet-style so the three non-overlapping 2.4 GHz channels (1/6/11), where most APs live, get
visited twice per hop cycle:

```
Sequence : 1, 6, 11, 3, 8, 13, 2, 7, 1, 6, 11, 4, 9, 5, 10, 12
Dwell    : 300 ms per channel
```

This captures beacons, probe requests/responses and data frames to build:
- the **networks graph/list** (per-channel signal "bells", security type color-coded, total
  beacon count),
- an in-memory **archive of associated/probing clients** (its own page, with signal, TX/RX
  packet counts),
- an **EAPOL 4-way handshake / PMKID capture engine** (below).

Entries not re-heard for `20 s` age out of the list automatically.

## Targeted capture (channel lock)

Channel hopping means the radio is only on any given channel ~300 ms out of every ~5 seconds
(16-channel cycle), which makes catching a full WPA handshake (a burst of 4 frames inside a few
tens of milliseconds) unreliable. Opening a network's **detail page** shows a **"Cattura
mirata" / targeted capture** button: it parks the radio on that network's channel instead of
hopping (starting capture automatically if it wasn't already running). Press again to release
the lock and resume hopping. Stopping the capture (Stop button) always releases the lock.

Use the lock, then force a client to (re)connect (toggle its Wi-Fi off/on) to reliably capture
a fresh handshake.

The channel to release is the one cached when you opened the detail page, not a live lookup -
so the lock always releases even if that network hasn't been re-heard in the last 20 s (and so
dropped out of the list/graph) while you had it parked. If the radio ever seems stuck on one
channel with no obvious way back, Stop always force-releases the lock too.

## Handshake / PMKID capture

While capturing, every EAPOL-Key frame (the WPA/WPA2 4-way handshake) is parsed and buffered per
access point, along with a PMKID check on message 1 (`00:0F:AC:04` KDE). A network's detail page
shows a live status line:

```
Handshake: M1 M2 M3 M4 +PMKID -> salvato su SD
```

As soon as a crackable set is available (M1+M2, or a PMKID), it's written to disk as a
`.pcap` (`LINKTYPE_IEEE802_11`, including the AP's beacon frame for context):

```
/sdcard/wifi-scanner/handshakes/<SSID>_<BSSID>.pcap
```

### Getting the files off the badge

The badge can present its SD card as a plain USB mass-storage device: open the **USB** app
from the launcher and choose **"Reboot as USB storage (SD)"**. It reboots into that mode and
the SD card (including `wifi-scanner/handshakes/`) shows up as a normal USB drive on your
computer. Use the **"Return to OS"** button on the boot screen (or eject the volume from
Linux/macOS) to reboot back into the normal firmware.

### Verifying a capture

```bash
# Convert and check: non-empty output means the capture is structurally valid
hcxpcapngtool capture.pcap -o hash.22000

# Or, a quick visual check
aircrack-ng capture.pcap
# look for "WPA (1 handshake)" next to the target network
```

### Cracking

```bash
# hashcat (GPU, fastest) - handles both full 4-way handshakes and PMKID-only captures
hcxpcapngtool capture.pcap -o hash.22000
hashcat -m 22000 hash.22000 wordlist.txt

# aircrack-ng (CPU, no conversion needed)
aircrack-ng -w wordlist.txt capture.pcap
```

### Audio notification

As soon as a handshake becomes crackable (M1+M2, or a PMKID) a short 8-bit-style beep plays, so
you know something was captured without having to watch the screen. If music is currently
playing on the badge, it fades out, pauses, plays the beep at normal volume, then resumes from
exactly where it paused and fades back in. The beep is a one-shot notification asset bundled
with the firmware (`Data/data/wifiscanner/eapol_beep.mp3` in this repo, played from the
internal `/data` partition) - it doesn't touch the SD card and never shows up in the Music
app's own library.

## Deauthentication

A network's detail page has a red **"Deauth"** button. It always asks for confirmation first
(the dialog names the SSID) before sending anything. Once confirmed, it:

1. starts capture and locks the radio onto that network's channel if it wasn't already
   (same mechanism as targeted capture, for the same reason - off-channel frames go nowhere),
2. sends a short, bounded burst (12 frames, ~25 ms apart - not a continuous flood) of spoofed
   802.11 deauthentication frames (reason code 7, the same one `aireplay-ng` uses) addressed to
   the broadcast address, so every client currently on that AP disconnects and reconnects.

The channel stays locked afterward, so capture keeps running on that network and a resulting
handshake (from the forced reconnect) is caught the same way as in **Handshake / PMKID
capture** above - this is the main reason to use it: force a handshake instead of waiting for
one. The detail page also shows a running count of bursts sent this session.

This is a real, disruptive action (it briefly kicks every connected client off the network),
unlike every other feature in this app which is purely passive/receive-only.

## Status

| Attack | Status |
| --- | --- |
| Handshake / PMKID capture | ✅ Implemented |
| Deauthentication (broadcast, per-network) | ✅ Implemented |
| Deauthentication (single targeted client) | 🚧 Planned |
| Beacon spam / evil twin | 🚧 Planned |

## Restore point

A known-good snapshot of this app (pre-attack features, scanner/list/graph/clients only) is
kept as `backups/scanner-stabile/WifiScanner.cpp` in the maintainer's working tree, so changes
made while implementing attacks can always be rolled back.
