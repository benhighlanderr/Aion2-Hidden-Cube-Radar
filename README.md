<p align="center">
<img width="333" height="202" alt="image" src="https://github.com/user-attachments/assets/4f1d07ac-4967-4935-9eac-15f267559740" />
<img width="249" height="250" alt="image" src="https://github.com/user-attachments/assets/5552ff6d-1bfd-49db-92c5-ebbbdc92fdc6" />
<img width="247" height="248" alt="image" src="https://github.com/user-attachments/assets/b660ee73-b33c-44d6-82df-33af90d79304" />
</p>

A lightweight, high-performance 2D radar overlay designed to passively detect, locate, and navigate to Hidden Cubes in Aion 2 in real time.

---

## Overview

A2 HCR (Aion 2 Hidden Cube Radar) is an external HUD overlay that provides real-time situational awareness for Hidden Cubes. It runs as an independent borderless top-level window over your game screen and tracks hidden cube spawns by analyzing game network traffic completely passively.

### Safety and Anti-Cheat Compliance

* **100% Passive Network Inspection**: The application operates strictly as a network packet reader using Npcap and Scapy on local game TCP traffic across Aion 2 server ports (13328 and 13320).
* **Zero Memory Hooks**: Does not call `OpenProcess`, `ReadProcessMemory`, or `WriteProcessMemory`.
* **Zero Injections**: No DLL injection, API hooking, or thread manipulation.
* **Zero Game File Modifications**: Does not alter game binaries, pak files, or configuration files.
* **Safe from Anti-Cheat**: Because it does not interact with the game process or memory space, it is fundamentally invisible to anti-cheat scanners.

---

## How It Works

### 1. Packet Stream Processing
Aion 2 communicates via TCP with variable-length framed packets compressed with LZ4. A2 HCR passively reconstructs the TCP stream, decompresses LZ4 blocks, and extracts packet frames using unsigned variable-length integer (varint) decoding across both active server ports (13328 and 13320).

### 2. Accurate Cube Detection & Lifecycle
The radar monitors entity spawn, update, and despawn opcodes:
* `0x3634` (13876): Hidden Cube entity spawn. Detected object models and category identifiers are matched against an internal database of valid Hidden Cube textures (`HiddenCube_01`, `HiddenCube_02`, V01 through V05) for both Elyos and Asmodian factions. False positives such as God Fragments, quest containers, and ordinary loot boxes are strictly excluded.
* `0x3635` (13877) & `0x363A` (13882): Cube despawn or collected by any player.
* `0x8D6D` (36205): Gathering interaction completion, instantly clearing harvested cubes.

### 3. Real-Time Movement Synchronization
Player position and movement are synchronized strictly using verified server ground-truth:
* **Identity Lock**: Automatic character identification via `0x3633` (character spawn) and `0x8D00` (server sync), locking your unique Entity ID on startup without writing to disk.
* **Server Action Broadcasts**: Aion 2 server netcode broadcasts 3D coordinates during active movement events:
  * **Dash Maneuvers**: Instant coordinate broadcast via `0x382A` (14378).
  * **Jump & Vertical Evades**: High-precision height and horizontal updates via `0x382A` (14378) and `0x3804` (14340).
  * **Wing Deployment & Gliding**: Flight vector updates via `0x382A` (14378) and `0x382C` (14380).
  * **Combat Stance Movement**: Continuous position broadcasts via `0x382B` (14379) when weapon is drawn (Tab).
* **Zone Transitions**: Teleports and world transitions (`0x3623` / 13859 and `0x561E` / 22046) automatically reset radar state and reposition coordinates.

### 4. Player-Centered 150m Coordinate System
A2 HCR uses an intuitive player-centered 150-meter fixed radar system:
* Your character is anchored stationary at the exact center of the radar as a green circle (labeled "YOU").
* Hidden Cubes appear as red circles positioned around you at their true relative world bearing and distance.
* Fixed 150-meter scale (outer boundary = 150m, middle dashed ring = 75m, center = 0m). No dynamic scale jumps or treadmill effects.
* As you walk towards a cube in the game, the red cube smoothly glides inward directly toward you at the center until you reach it.

---

## Features

* **Player-Centered Navigation**: Your character stays fixed at the center ("YOU"), with cubes moving inward as you approach them.
* **Fixed 150m Visual Range**: Consistent 1:1 scale (outer ring = 150m, middle ring = 75m) eliminating sudden zoom resets.
* **Multi-Cube Tracking**: Renders all detected cubes within 150 meters, prioritizing the closest one with an active tracking line.
* **Live Distance and Elevation**: Displays precise 3D distance in meters along with height difference (e.g., `24m (+4m)` indicating the cube is on a cliff or rooftop above you).
* **Live Coordinates Display**: Shows current player coordinates on the overlay even while searching for cubes.
* **Audible Alert & Sound Profiles**: Select from 5 distinct audio alert profiles (Radar Ping, Classic Beep, Double Chime, Sci-Fi Pulse, Subtle Click) with live volume slider (0-100%) and instant sound preview.
* **Customization Settings**: Dedicated Settings panel (gear icon) to adjust radar opacity (transparency), sound profiles, volume level, and choose custom player and cube colors.
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

### Distance Refresh & In-Game Navigation Tip
Due to Aion 2's network architecture, server position packets are triggered by movement actions rather than peace-mode ground walking. While navigating toward a Hidden Cube, perform any of the following quick in-game actions to immediately refresh the exact target distance and bearing:
* **Dash**: Press your Dash key (Shift).
* **Jump**: Press Space bar.
* **Wings**: Deploy or toggle wings / glide.
* **Combat Stance**: Press `Tab` to draw your weapon.

Each action prompts the game server to emit verified 3D coordinates, updating the radar with 100% ground-truth accuracy.

---

## Controls

* **Move Overlay**: Left-click and drag anywhere on the title bar or radar circle.
* **Settings Button (gear icon)**: Open the settings panel to configure opacity, sound, volume, and colors.
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
