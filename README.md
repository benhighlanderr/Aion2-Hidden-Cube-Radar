# A2 HCR — Aion 2 Modern 3D Navigation Radar

A lightweight, modern, non-intrusive **3D Navigation HUD Overlay** designed to passively detect, track, and guide players to **Hidden Cubes** in Aion 2 in real time.

---

## Important Notice & Prerequisites

> [!IMPORTANT]
> **A2 HCR requires Python and Npcap installed on your system before running.**
> Like popular MMO DPS meters, this application works strictly via passive network packet inspection.

### 1. Prerequisites Installation
1. **Python (3.10 to 3.13 / Tk 9 compatible)**:
   - Download: https://www.python.org/downloads/
   - **Crucial**: Check **"Add Python to PATH"** during installation.
2. **Npcap (Packet Capture Library)**:
   - Download: https://npcap.com/#download
   - **Crucial**: During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.

---

## How It Works & Movement Netcode Note

### Passive Packet Sniffing (DPS Meter Architecture)
* **Zero Memory Hooks**: Does not call `OpenProcess`, `ReadProcessMemory`, or `WriteProcessMemory`.
* **Zero DLL Injection**: No game injection, API hooking, or process modification.
* **100% Passive**: Strictly sniffs local TCP network traffic on game ports 13328 and 13320. Completely invisible to anti-cheat scanners.

### Real-Time Position Updating (`0x382a`)
Due to Aion 2's server architecture and traffic optimization, the game server does not broadcast continuous 3D world coordinates during basic ground walking. Verified 3D server coordinates are broadcast during active movement actions:
* **Opening Wings / Gliding**
* **Dashing (`Shift` / Dash)**
* **Jumping (`Space`)**
* **Skill Casts & Combat Actions**

> [!TIP]
> **When a Hidden Cube is detected nearby**: Continuously **jump, dash, or toggle wings** to refresh and keep your distance and directional arrow pointing with 100% real-time mathematical precision!

---

## Features

### Modern 3D Directional Arrow
When a Hidden Cube is within detection range (up to 150m), an interactive 3D arrow points directly toward the target with an intuitive distance color system:
* **Red Arrow**: Far distance (> 50 meters away).
* **Yellow / Orange Arrow**: Medium distance (< 50 meters away).
* **Green Arrow**: Close proximity (< 15 meters away — you are right next to the cube!).

### Real-Time Distance & Elevation Box
* **Large Metric Distance**: Large bold text displays real-time distance in meters (e.g., `24m`).
* **Vertical Elevation**:
  * `↑ ABOVE BY 8m`: Cube is located on a ledge, cliff, rooftop, or tree above you.
  * `↓ BELOW BY 5m`: Cube is below you in a pit, ravine, or under a bridge.
  * `═ LEVEL (SAME HEIGHT)`: Cube is on the exact same vertical plane.

### Customizable Radar Settings (⚙)
Click the **⚙** icon on the top header to configure:
* **Radar Scale / Size**: Dynamic scale slider (75% to 150%) to adjust overlay size for your screen resolution.
* **Radar Opacity**: Adjustable transparency from 20% to 100%.
* **Character Name (Optional)**: Enter your character name in settings to strictly bind and filter only your Entity ID. If left blank, the radar binds automatically on your first action (`0x382a`).
* **Audible Alert & Profiles**: Toggle sound alerts and choose from 5 audio tone profiles (*Radar Ping, Classic Beep, Double Chime, Sci-Fi Pulse, Subtle Click*) with volume slider and instant sound testing.

### Tk / Tcl 9 Compatibility
Fully tested and verified with modern Python 3.13 and Tk/Tcl 9.0.4.

---

## Installation & Launch

1. Install Python and Npcap as described in Prerequisites.
2. Clone or download this repository.
3. Double-click `Install_Requirements.bat` to install Python dependencies (`scapy`, `lz4`, `psutil`).
4. Double-click `Start_Radar.bat` to launch the radar.
5. In game, perform a jump or dash to bind your position, and search for Hidden Cubes!
