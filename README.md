# A2 HCR - Aion 2 Hidden Cube Radar Overlay

A lightweight, high-performance 2D radar overlay designed to passively detect, locate, and navigate to Hidden Cubes in Aion 2 in real time.

---

## Overview

A2 HCR (Aion 2 Hidden Cube Radar) is an external HUD overlay that provides real-time situational awareness for Hidden Cubes. It runs as an independent borderless top-level window over your game screen and tracks hidden cube spawns by analyzing game network traffic completely passively.

### Safety and Anti-Cheat Compliance

* **100% Passive Network Inspection**: The application operates strictly as a network packet reader using Npcap and Scapy on local game TCP traffic (ports 13328 and 13320).
* **Zero Memory Hooks**: Does not call `OpenProcess`, `ReadProcessMemory`, or `WriteProcessMemory`.
* **Zero Injections**: No DLL injection, API hooking, or thread manipulation.
* **Zero Game File Modifications**: Does not alter game binaries, pak files, or configuration files.
* **Safe from Anti-Cheat**: Because it does not interact with the game process or memory space, it is fundamentally invisible to anti-cheat scanners.

---

## How It Works

### 1. Packet Stream Processing
Aion 2 communicates via TCP with variable-length framed packets compressed with LZ4. A2 HCR passively reconstructs the TCP stream, decompresses LZ4 blocks, and extracts packet frames using unsigned variable-length integer (varint) decoding across both active server ports (13328 and 13320).

### 2. Accurate Cube Filtering
The radar monitors entity spawn and update opcodes (`0x3634`, `0x3635`, `0x3638`, `0x363A`). Detected object models and category identifiers are matched against an internal database of valid Hidden Cube textures (`HiddenCube_01`, `HiddenCube_02`, V01 through V05). False positives such as God Fragments, quest containers, and ordinary loot boxes are strictly excluded.

### 3. Real-Time Movement Synchronization
Player position and movement are synchronized using server-to-client position updates (walking `0x382B`, dashing `0x382A`, flight/wings `0x382C`, and coordinate sync `0x3710-0x3750`) combined with client-to-server movement frames and dead-reckoning extrapolation. This eliminates delay and delivers immediate visual feedback on every step.

### 4. Target-Lock Coordinate System
Traditional rotating radars can be disorienting when navigating terrain. A2 HCR uses an anchored target-lock design:
* The Hidden Cube is anchored at the exact center of the radar as a stationary red circle.
* Your character is displayed as a green circle (labeled "YOU") positioned at the relative distance and direction.
* As you walk towards the cube in the game, your green circle visibly advances across the radar towards the center cube until they intersect at 0 meters.

---

## Features

* **Stationary Target-Lock**: The target cube stays completely fixed at the center, eliminating compass spinning and directional disorientation.
* **Stepped Visual Scale**: Uses calibrated distance tiers (35m, 65m, 100m+) rather than dynamic normalization, allowing you to clearly see your character physically closing the gap step by step.
* **Live Distance and Elevation**: Displays precise 3D distance in meters along with height difference (e.g., `24m (+4m)` indicating the cube is on a cliff or rooftop above you).
* **Live Coordinates**: Shows current player coordinates on the overlay even while searching for cubes.
* **Audible Alert**: Plays a distinct notification beep upon detecting a hidden cube, with a quick mute button on the header.
* **Zero-Storage Privacy**: Character name input is prompted fresh on every startup and is never written to disk or config files.
* **Draggable Overlay**: Left-click and drag the window to place it anywhere on your desktop or secondary monitor.

---

## Requirements

* **Operating System**: Windows 10 or Windows 11 (64-bit)
* **Python**: Version 3.10 or higher
* **Npcap**: Version 1.70 or higher (Free network driver: https://npcap.com/#download)
  * During Npcap setup, ensure "Install Npcap in WinPcap API-compatible Mode" is checked.

---

## Installation

1. Clone or download this repository to your computer:
   ```bash
   git clone https://github.com/your-username/A2HCR.git
   cd A2HCR
   ```

2. Install Python dependencies:
   * Double-click `Install_Requirements.bat`
   * Or manually via command line:
     ```bash
     pip install -r requirements.txt
     ```

3. Ensure Npcap is installed on your system. If not, install from https://npcap.com/#download.

---

## Usage

1. Launch the radar:
   * Double-click `Start_Radar.bat` (automatically requests Administrator privileges required for network sniffing).
   * Or run via terminal as Administrator:
     ```bash
     python aion2_radar.py
     ```

2. Enter your in-game Character Name in the prompt window and click "Start Radar".
   * This allows the sniffer to immediately associate network entities with your character without searching.
   * If left blank, automatic network entity resolution is used.

3. Position the radar overlay over your game (Borderless Fullscreen or Windowed mode recommended).

---

## Controls

* **Move Overlay**: Left-click and drag anywhere on the title bar or radar circle.
* **Mute Button**: Toggle audible notification alerts on or off.
* **Close (X Button)**: Terminate the radar overlay.

---

## Command Line Arguments

```text
usage: aion2_radar.py [-h] [--char CHAR] [--replay REPLAY] [--port PORT]

options:
  -h, --help       show this help message and exit
  --char CHAR      In-game character name
  --replay REPLAY  Replay pcap file for visual testing
  --port PORT      Manual port override (Default: 13328)
```

---

## Disclaimer

This software is developed strictly for educational, network analysis, and research purposes. It interacts solely with local network packets and makes no alterations to the game client or game servers. Users are responsible for complying with the terms of service of the games they play.
