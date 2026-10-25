from __future__ import annotations
import argparse
import io
import json
import math
import os
import struct
import sys
import threading
import time
import wave
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    try:
        import winsound
    except Exception:
        pass

import tkinter as tk
from tkinter import ttk
import lz4.block
import psutil
from scapy.all import sniff, IP, TCP, PcapReader

@dataclass
class Aion2ConnectionInfo:
    pid: int
    process_name: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int

def detect_aion2_connection() -> Optional[Aion2ConnectionInfo]:
    aion_pids = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name'].lower()
            if 'aion2' in name or name in ('aion2.exe', 'aion2-win64-shipping.exe'):
                aion_pids.append((proc.info['pid'], proc.info['name']))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not aion_pids:
        return None
    candidate_conn = None
    for pid, proc_name in aion_pids:
        try:
            p = psutil.Process(pid)
            conns = p.connections(kind='tcp')
            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    rport = c.raddr.port
                    if rport in (13328, 13320):
                        return Aion2ConnectionInfo(pid=pid, process_name=proc_name, local_ip=c.laddr.ip, local_port=c.laddr.port, remote_ip=c.raddr.ip, remote_port=rport)
                    if 10000 <= rport <= 20000:
                        candidate_conn = Aion2ConnectionInfo(pid=pid, process_name=proc_name, local_ip=c.laddr.ip, local_port=c.laddr.port, remote_ip=c.raddr.ip, remote_port=rport)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return candidate_conn

def decode_uvarint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    value = 0
    for i in range(5):
        at = offset + i
        if at >= len(data):
            raise ValueError('incomplete uvarint')
        b = data[at]
        value |= (b & 127) << (7 * i)
        if not (b & 128):
            return (value, i + 1)
    raise ValueError('uvarint exceeds 5 bytes')

SOUND_PROFILES: Dict[str, List[Tuple[float, float, bool]]] = {
    'Radar Ping': [(1250.0, 220.0, True)],
    'Classic Beep': [(900.0, 150.0, False)],
    'Double Chime': [(750.0, 70.0, False), (0.0, 25.0, False), (1250.0, 140.0, True)],
    'Sci-Fi Pulse': [(520.0, 70.0, False), (1040.0, 160.0, True)],
    'Subtle Click': [(1600.0, 45.0, True)]
}

def load_radar_settings() -> dict:
    defaults = {
        'alpha': 0.92,
        'sound_enabled': True,
        'sound_volume': 0.7,
        'sound_profile': 'Radar Ping',
        'theme_color': '#A855F7',
        'character_name': '',
        'radar_scale': 1.0,
        'compass_mode': False
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'radar_settings.json')
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    defaults.update(data)
        except Exception:
            pass
    return defaults

def save_radar_settings(settings: dict):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'radar_settings.json')
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass

def make_profile_wav(profile_name: str, volume: float = 0.7, is_asmodian: bool = False) -> bytes:
    sample_rate = 44100
    if is_asmodian:
        tones = [(1400.0, 120.0, False), (0.0, 30.0, False), (2100.0, 240.0, True)]
    else:
        tones = SOUND_PROFILES.get(profile_name, SOUND_PROFILES['Radar Ping'])
    data = bytearray()
    amp = int(32767 * max(0.0, min(1.0, volume)))
    for freq, dur, decay in tones:
        n_samples = int(sample_rate * (dur / 1000.0))
        for i in range(n_samples):
            if freq <= 0.0:
                data.extend(b'\x00\x00')
            else:
                t = i / sample_rate
                env = (1.0 - (i / n_samples)) if decay else 1.0
                val = int(amp * env * math.sin(2.0 * math.pi * freq * t))
                data.extend(struct.pack('<h', val))
    buf = io.BytesIO()
    with wave.open(buf, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sample_rate)
        wf.writeframes(data)
    return buf.getvalue()

def play_cube_sound(is_asmodian: bool = False, volume: float = 0.7, sound_profile: str = 'Radar Ping'):
    if volume <= 0.001:
        return
    try:
        wav = make_profile_wav(sound_profile, volume, is_asmodian)
        winsound.PlaySound(wav, winsound.SND_MEMORY)
    except Exception:
        try:
            sys.stdout.write('\x07')
            sys.stdout.flush()
        except Exception:
            pass

ASMODIAN_V04_IDS: set[int] = {1301199, 1301200, 1300754, 1300081, 1300082, 1000566, 1200039, 1200040, 1200041}
HIDDEN_CUBE_IDS: Dict[int, str] = {
    1000295: 'Hidden Cube · Basic',
    1000548: 'Hidden Cube · 01_V01',
    1000549: 'Hidden Cube · 01_V02',
    1000550: 'Hidden Cube · 01_V03',
    1000551: 'Hidden Cube · 01_V04',
    1000552: 'Hidden Cube · 01_V05',
    1000553: 'Hidden Cube · 01_V06',
    1000554: 'Hidden Cube · 01_V07',
    1000555: 'Hidden Cube · 01_V08',
    1000556: 'Hidden Cube · 01_V09',
    1000557: 'Hidden Cube · 01_V10',
    1000558: 'Hidden Cube · 01_V11',
    1000559: 'Hidden Cube · 01_V12',
    1000560: 'Hidden Cube · 01_V13',
    1000561: 'Hidden Cube · 01_V14',
    1000562: 'Hidden Cube · 01_V15',
    1000563: 'Hidden Cube · 01_V16',
    1000564: 'Hidden Cube · 01_V17',
    1000565: 'Hidden Cube · 01_V18',
    1000566: 'Hidden Cube · 01_V19 (Asmodian)',
    1200039: 'Hidden Cube · 02_V01 (Asmodian)',
    1200040: 'Hidden Cube · 02_V02 (Asmodian)',
    1200041: 'Hidden Cube · 02_V03 (Asmodian)',
    1300081: 'Hidden Cube · 03_V01 (Asmodian)',
    1300082: 'Hidden Cube · 03_V02 (Asmodian)',
    1300754: 'Hidden Cube · 03_V03 (Asmodian)',
    1301199: 'Hidden Cube · 03_V04 (Asmodian)',
    1301200: 'Hidden Cube · 03_V05 (Asmodian)'
}

def is_target_hidden_cube(npc_id: int) -> bool:
    if npc_id in HIDDEN_CUBE_IDS:
        return True
    if 1000548 <= npc_id <= 1000566:
        return True
    if 1200039 <= npc_id <= 1200041:
        return True
    if 1300081 <= npc_id <= 1300082:
        return True
    if npc_id in (1300754, 1301199, 1301200, 1000295):
        return True
    return False

@dataclass
class CubeItem:
    entity_id: int
    npc_id: int
    name: str
    x: float
    y: float
    z: float
    is_asmodian: bool = False
    model_name: str = 'HiddenCube'

class RadarState:
    def __init__(self):
        self.lock = threading.Lock()
        self.player_pos: Optional[Tuple[float, float, float]] = None
        self.heading_anchor_pos: Optional[Tuple[float, float]] = None
        self.player_heading: Optional[float] = None
        self.last_dist: Optional[float] = None
        self.dist_delta: float = 0.0
        self.player_entity_id: Optional[int] = None
        self.player_id_locked: bool = False
        self.cubes: Dict[int, CubeItem] = {}
        self.packet_count: int = 0
        self.range_meters: float = 150.0
        self.sound_enabled: bool = True
        self.sound_volume: float = 0.7
        self.sound_profile: str = 'Radar Ping'
        self.target_char_name: str = ''
        self.last_pos_time: float = 0.0
        self.on_update_callback: Optional[Any] = None

    def notify_update(self):
        cb = self.on_update_callback
        if cb:
            try:
                cb()
            except Exception:
                pass

    def set_player_pos(self, x: float, y: float, z: float, force: bool = False) -> bool:
        if not is_valid_coord(x, y, z):
            return False
        now = time.time()
        with self.lock:
            if self.player_pos is not None:
                if self.heading_anchor_pos is None:
                    self.heading_anchor_pos = (self.player_pos[0], self.player_pos[1])
                dx = x - self.heading_anchor_pos[0]
                dy = y - self.heading_anchor_pos[1]
                dist = math.hypot(dx, dy)
                if dist >= 3000.0:
                    self.heading_anchor_pos = (x, y)
                elif dist >= 100.0:
                    self.player_heading = math.atan2(dx, -dy)
                    self.heading_anchor_pos = (x, y)
            else:
                self.heading_anchor_pos = (x, y)
            self.player_pos = (x, y, z)
            self.last_pos_time = now
        self.notify_update()
        return True

    def update_dist_delta(self, curr_dist: float):
        with self.lock:
            if self.last_dist is not None:
                self.dist_delta = curr_dist - self.last_dist
            self.last_dist = curr_dist

    def set_player_id(self, entity_id: int, lock: bool = True, force: bool = False):
        if entity_id <= 100:
            return
        with self.lock:
            if self.player_id_locked and not lock and not force:
                return
            self.player_entity_id = entity_id
            if lock:
                self.player_id_locked = True
        self.notify_update()

    def reset_zone(self):
        with self.lock:
            self.cubes.clear()
            self.last_pos_time = 0.0
            self.last_dist = None
            self.dist_delta = 0.0
            self.heading_anchor_pos = None
            self.player_heading = None

    def add_cube(self, cube: CubeItem) -> bool:
        with self.lock:
            is_new = cube.entity_id not in self.cubes
            self.cubes[cube.entity_id] = cube
        self.notify_update()
        return is_new

    def remove_cube(self, entity_id: int):
        with self.lock:
            self.cubes.pop(entity_id, None)
            if not self.cubes:
                self.last_dist = None
                self.dist_delta = 0.0
        self.notify_update()

    def remove_nearby_cubes(self, radius_cm: float = 600.0):
        with self.lock:
            if not self.player_pos:
                return
            px, py, pz = self.player_pos
            r_sq = radius_cm * radius_cm
            to_remove = [eid for eid, c in self.cubes.items() if (c.x - px) ** 2 + (c.y - py) ** 2 + (c.z - pz) ** 2 <= r_sq]
            for eid in to_remove:
                self.cubes.pop(eid, None)
            if not self.cubes:
                self.last_dist = None
                self.dist_delta = 0.0

    def get_snapshot(self):
        with self.lock:
            return {
                'player_pos': self.player_pos,
                'raw_player_pos': self.player_pos,
                'player_heading': self.player_heading,
                'last_dist': self.last_dist,
                'dist_delta': self.dist_delta,
                'player_entity_id': self.player_entity_id,
                'cubes': list(self.cubes.values()),
                'packet_count': self.packet_count,
                'range_meters': self.range_meters,
                'target_char_name': self.target_char_name,
                'player_id_locked': self.player_id_locked,
                'last_pos_time': self.last_pos_time
            }

def is_valid_coord(x: float, y: float, z: float) -> bool:
    if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
        return False
    if abs(x) > 500000.0 or abs(y) > 500000.0 or abs(z) > 120000.0:
        return False
    return True

class PureStreamEngine:
    def __init__(self, state: RadarState, target_port: Optional[int] = None):
        self.state = state
        self.target_port = target_port
        self.tcp_buffers: Dict[Tuple[str, int, str, int], bytearray] = defaultdict(bytearray)

    def feed_payload(self, src: str, sport: int, dst: str, dport: int, payload: bytes):
        if not payload:
            return
        if self.target_port is not None:
            if sport != self.target_port:
                return
        elif sport not in (13328, 13320):
            return
        conn_key = (src, sport, dst, dport)
        buf = self.tcp_buffers[conn_key]
        buf.extend(payload)
        off = 0
        buf_len = len(buf)
        while off < buf_len:
            if buf[off] == 0:
                off += 1
                continue
            try:
                enc_len, varint_len = decode_uvarint(buf, off)
            except ValueError:
                break
            if enc_len < 4:
                off += 1
                continue
            body_len = enc_len - 4
            total_len = varint_len + body_len
            if off + total_len > buf_len:
                break
            frame_body = bytes(buf[off + varint_len:off + total_len])
            off += total_len
            self.handle_frame(frame_body, is_lz4=False, depth=0)
        if off > 0:
            del buf[:off]

    def handle_frame(self, body: bytes, is_lz4: bool = False, depth: int = 0):
        if len(body) < 2 or depth > 4:
            return
        if body[:2] == b'\xff\xff' and len(body) >= 6:
            plain_size = struct.unpack('<I', body[2:6])[0]
            if plain_size <= 0 or plain_size > 262144:
                return
            try:
                decompressed = lz4.block.decompress(body[6:], uncompressed_size=plain_size)
                self.walk_decompressed(decompressed, depth + 1)
                return
            except Exception:
                pass
        elif len(body) >= 7 and 240 <= body[0] < 255 and (body[1:3] == b'\xff\xff'):
            plain_size = struct.unpack('<I', body[3:7])[0]
            if plain_size <= 0 or plain_size > 262144:
                return
            try:
                decompressed = lz4.block.decompress(body[7:], uncompressed_size=plain_size)
                self.walk_decompressed(decompressed, depth + 1)
                return
            except Exception:
                pass

        opcode = struct.unpack('<H', body[:2])[0]
        p = body[2:]

        if self.state.target_char_name:
            tname = self.state.target_char_name.strip()
            if tname:
                u8 = tname.encode('utf-8')
                u16 = tname.encode('utf-16le')
                u8_low = tname.lower().encode('utf-8')
                u16_low = tname.lower().encode('utf-16le')
                p_low = p.lower()
                if u8 in p or u16 in p or u8_low in p_low or u16_low in p_low:
                    try:
                        eid, _ = decode_uvarint(p, 0)
                        if eid > 100:
                            if eid != self.state.player_entity_id:
                                self.state.set_player_id(eid, lock=True, force=True)
                                print(f"[+] [ID LOCKED] '{tname}' found in opcode {opcode} -> Entity ID: {eid}")
                    except Exception:
                        pass

        if opcode == 13893:
            try:
                eid, _ = decode_uvarint(p, 0)
                if self.state.player_id_locked and eid == self.state.player_entity_id:
                    if len(p) >= 37:
                        x, y, z = struct.unpack('<fff', p[25:37])
                        if is_valid_coord(x, y, z):
                            self.state.set_player_pos(x, y, z)
            except Exception:
                pass
        elif opcode == 13876:
            try:
                eid, n = decode_uvarint(p, 0)
                if len(p) >= n + 18:
                    obj_id = struct.unpack('<I', p[n + 2:n + 6])[0]
                    if is_target_hidden_cube(obj_id):
                        x, y, z = struct.unpack('<fff', p[n + 6:n + 18])
                        name = HIDDEN_CUBE_IDS.get(obj_id, f'Hidden Cube · {obj_id}')
                        is_asmodian = obj_id in ASMODIAN_V04_IDS
                        is_new = self.state.add_cube(CubeItem(entity_id=eid, npc_id=obj_id, name=name, x=x, y=y, z=z, is_asmodian=is_asmodian, model_name='HiddenCube'))
                        if is_new and self.state.sound_enabled:
                            threading.Thread(target=play_cube_sound, args=(is_asmodian, self.state.sound_volume, self.state.sound_profile), daemon=True).start()
            except Exception:
                pass
        elif opcode == 13877:
            try:
                eid, _ = decode_uvarint(p, 0)
                self.state.remove_cube(eid)
            except Exception:
                pass
        elif opcode == 13882:
            try:
                eid, _ = decode_uvarint(p, 0)
                self.state.remove_cube(eid)
            except Exception:
                pass
        elif opcode == 36205:
            try:
                self.state.remove_nearby_cubes(radius_cm=600.0)
            except Exception:
                pass
        elif opcode == 13857:
            if len(p) >= 28:
                try:
                    eid, _ = decode_uvarint(p, 0)
                    if eid > 100:
                        self.state.set_player_id(eid, lock=True, force=True)
                    x, y, z = struct.unpack('<fff', p[16:28])
                    if is_valid_coord(x, y, z):
                        self.state.set_player_pos(x, y, z, force=True)
                except Exception:
                    pass
        elif opcode == 13859:
            try:
                self.state.reset_zone()
                eid, n = decode_uvarint(p, 0)
                if eid > 100:
                    self.state.set_player_id(eid, lock=True, force=True)
                pos_offset = n + 5
                if len(p) >= pos_offset + 12:
                    px, py, pz = struct.unpack('<fff', p[pos_offset:pos_offset + 12])
                    if is_valid_coord(px, py, pz):
                        self.state.set_player_pos(px, py, pz, force=True)
            except Exception:
                pass
        elif opcode == 22046:
            try:
                if len(p) >= 29:
                    px, py, pz = struct.unpack('<fff', p[17:29])
                    if is_valid_coord(px, py, pz):
                        self.state.set_player_pos(px, py, pz, force=True)
            except Exception:
                pass
        elif opcode in (14378, 14379, 14380, 14340):
            try:
                eid, n = decode_uvarint(p, 0)
                if not self.state.player_entity_id and eid > 100:
                    self.state.set_player_id(eid, lock=False)
                if self.state.player_entity_id and eid == self.state.player_entity_id:
                    if len(p) >= 30:
                        x, y, z = struct.unpack('<fff', p[-12:])
                        if is_valid_coord(x, y, z):
                            self.state.set_player_pos(x, y, z)
            except Exception:
                pass
        elif opcode == 14338:
            try:
                eid, n = decode_uvarint(p, 0)
                if not self.state.player_entity_id and eid > 100:
                    self.state.set_player_id(eid, lock=False)
                if self.state.player_entity_id and eid == self.state.player_entity_id:
                    if len(p) >= 29:
                        x, y, z = struct.unpack('<fff', p[17:29])
                        if is_valid_coord(x, y, z):
                            self.state.set_player_pos(x, y, z)
            except Exception:
                pass
        elif 14096 <= opcode <= 14160:
            try:
                eid, n = decode_uvarint(p, 0)
                if not self.state.player_entity_id and eid > 100:
                    self.state.set_player_id(eid, lock=False)
                if self.state.player_entity_id and eid == self.state.player_entity_id:
                    if len(p) >= n + 14:
                        x, y, z = struct.unpack('<fff', p[n + 2:n + 14])
                        if is_valid_coord(x, y, z):
                            self.state.set_player_pos(x, y, z)
            except Exception:
                pass
        elif opcode == 13889:
            try:
                eid, n = decode_uvarint(p, 0)
                offset = n + 5
                if len(p) >= offset + 18:
                    npc_id = struct.unpack('<I', p[offset:offset + 4])[0]
                    if is_target_hidden_cube(npc_id):
                        x, y, z = struct.unpack('<fff', p[offset + 6:offset + 18])
                        self.state.add_cube(CubeItem(entity_id=eid, npc_id=npc_id, name=HIDDEN_CUBE_IDS.get(npc_id, f'Hidden Cube · {npc_id}'), x=x, y=y, z=z, is_asmodian=False, model_name='HiddenCube'))
            except Exception:
                pass
        elif opcode == 13890:
            try:
                eid, _ = decode_uvarint(p, 0)
                self.state.remove_cube(eid)
            except Exception:
                pass

    def walk_decompressed(self, data: bytes, depth: int):
        offset = 0
        d_len = len(data)
        while offset < d_len:
            if data[offset] == 0:
                offset += 1
                continue
            try:
                encoded_len, varint_len = decode_uvarint(data, offset)
            except ValueError:
                break
            body_len = encoded_len - 4
            if body_len < 2:
                offset += varint_len + max(0, body_len)
                continue
            frame_total = varint_len + body_len
            if offset + frame_total > d_len:
                break
            frame_slice = data[offset + varint_len:offset + frame_total]
            offset += frame_total
            self.handle_frame(frame_slice, is_lz4=True, depth=depth)

def get_compass_label(deg: float) -> str:
    if -22.5 <= deg < 22.5:
        return 'NORTH (Kuzey)'
    elif 22.5 <= deg < 67.5:
        return 'NORTH-EAST (Kuzeydoğu)'
    elif 67.5 <= deg < 112.5:
        return 'EAST (Doğu)'
    elif 112.5 <= deg < 157.5:
        return 'SOUTH-EAST (Güneydoğu)'
    elif deg >= 157.5 or deg < -157.5:
        return 'SOUTH (Güney)'
    elif -157.5 <= deg < -112.5:
        return 'SOUTH-WEST (Güneybatı)'
    elif -112.5 <= deg < -67.5:
        return 'WEST (Batı)'
    else:
        return 'NORTH-WEST (Kuzeybatı)'

def get_direction_label(deg: float) -> Tuple[str, bool]:
    if -22.5 <= deg < 22.5:
        return ('Directly Ahead', True)
    elif 22.5 <= deg < 67.5:
        return ('Ahead right', True)
    elif 67.5 <= deg < 112.5:
        return ('Right', False)
    elif 112.5 <= deg < 157.5:
        return ('Behind right', False)
    elif deg >= 157.5 or deg < -157.5:
        return ('Directly Behind', False)
    elif -67.5 <= deg < -22.5:
        return ('Ahead left', True)
    elif -112.5 <= deg < -67.5:
        return ('Left', False)
    else:
        return ('Behind left', False)

class Modern3DNavRadarApp:
    def __init__(self, root: tk.Tk, state: RadarState):
        self.root = root
        self.state = state
        settings = load_radar_settings()
        self.theme_color = '#A855F7'
        self.current_alpha = float(settings.get('alpha', 0.92))
        self.scale = float(settings.get('radar_scale', 1.0))
        self.scale = max(0.75, min(1.5, self.scale))
        self.compass_mode = bool(settings.get('compass_mode', False))
        self.state.sound_enabled = bool(settings.get('sound_enabled', True))
        self.state.sound_volume = float(settings.get('sound_volume', 0.7))
        self.state.sound_profile = str(settings.get('sound_profile', 'Radar Ping'))
        self.settings_win: Optional[tk.Toplevel] = None
        self.base_width = 200
        self.base_height = 240
        w = int(self.base_width * self.scale)
        h = int(self.base_height * self.scale)
        self.root.geometry(f'{w}x{h}+1550+100')
        self.root.configure(bg='#0B0813')
        self._drag_x = 0
        self._drag_y = 0
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._has_dragged = False
        self.cur_visual_angle = 0.0
        self.scanner_phase = 0.0
        self._build_ui()
        self._bind_events()
        self.root.update_idletasks()
        try:
            self.root.overrideredirect(True)
        except Exception:
            pass
        try:
            self.root.attributes('-topmost', True)
        except Exception:
            pass
        try:
            self.root.attributes('-alpha', self.current_alpha)
        except Exception:
            pass
        self.root.update_idletasks()
        self.root.after(33, self._render_loop)

    def _build_ui(self):
        w = int(self.base_width * self.scale)
        h = int(self.base_height * self.scale)
        self.canvas = tk.Canvas(self.root, width=w, height=h, bg='#0B0813', highlightthickness=1, highlightbackground='#2E1065')
        self.canvas.pack(fill=tk.BOTH, expand=True)

    def _bind_events(self):
        self.canvas.bind('<ButtonPress-1>', self._start_drag)
        self.canvas.bind('<B1-Motion>', self._on_drag)
        self.canvas.bind('<ButtonRelease-1>', self._on_canvas_click)

    def _start_drag(self, event):
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root
        self._has_dragged = False
        self._drag_x = event.x_root - self.root.winfo_x()
        self._drag_y = event.y_root - self.root.winfo_y()

    def _on_drag(self, event):
        if abs(event.x_root - self._drag_start_x) > 3 or abs(event.y_root - self._drag_start_y) > 3:
            self._has_dragged = True
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self.root.geometry(f'+{x}+{y}')

    def _on_canvas_click(self, event):
        if self._has_dragged:
            return
        scale = getattr(self, 'scale', 1.0)
        w = int(self.base_width * scale)
        if event.y <= int(26 * scale):
            if event.x >= w - int(24 * scale):
                self._on_close()
            elif event.x >= w - int(44 * scale):
                self._open_settings()

    def _save_current_settings(self):
        save_radar_settings({
            'alpha': round(self.current_alpha, 2),
            'sound_enabled': self.state.sound_enabled,
            'sound_volume': round(self.state.sound_volume, 2),
            'sound_profile': self.state.sound_profile,
            'theme_color': '#A855F7',
            'radar_scale': round(self.scale, 2),
            'compass_mode': getattr(self, 'compass_mode', True),
            'character_name': self.state.target_char_name
        })

    def _open_settings(self):
        if self.settings_win and self.settings_win.winfo_exists():
            self.settings_win.lift()
            self.settings_win.focus_force()
            return
        win = tk.Toplevel(self.root)
        self.settings_win = win
        win.title('A2 HCR - Settings')
        win.configure(bg='#0D0717')
        win.resizable(False, False)
        try:
            win.attributes('-topmost', True)
        except Exception:
            pass
        rx = self.root.winfo_rootx()
        ry = self.root.winfo_rooty()
        win_w, win_h = 320, 520
        pos_x = rx - win_w - 10 if rx - win_w - 10 > 20 else rx + int(self.base_width * self.scale) + 10
        pos_y = max(40, ry)
        win.geometry(f'{win_w}x{win_h}+{pos_x}+{pos_y}')

        title_frame = tk.Frame(win, bg='#0D0717')
        title_frame.pack(fill=tk.X, padx=16, pady=(14, 8))
        lbl_set_title = tk.Label(title_frame, text='RADAR SETTINGS', font=('Segoe UI', 11, 'bold'), fg=self.theme_color, bg='#0D0717')
        lbl_set_title.pack(anchor='w')
        tk.Label(title_frame, text='Configure 3D HUD scale, opacity and audio options', font=('Segoe UI', 8), fg='#94A3B8', bg='#0D0717').pack(anchor='w')

        body = tk.Frame(win, bg='#0D0717')
        body.pack(fill=tk.BOTH, expand=True, padx=16)

        sec_view = tk.LabelFrame(body, text=' RADAR DISPLAY & SIZE ', font=('Segoe UI', 8, 'bold'), fg=self.theme_color, bg='#0D0717', bd=1, relief=tk.SOLID)
        sec_view.pack(fill=tk.X, pady=(0, 10), ipady=4)

        char_frame = tk.Frame(sec_view, bg='#0D0717')
        char_frame.pack(fill=tk.X, padx=10, pady=(4, 6))
        tk.Label(char_frame, text='Character Name:', font=('Segoe UI', 9), fg='#E2E8F0', bg='#0D0717').pack(side=tk.LEFT)
        char_var = tk.StringVar(value=self.state.target_char_name)
        char_entry = tk.Entry(char_frame, textvariable=char_var, font=('Segoe UI', 9), bg='#1E1133', fg='#FFFFFF', insertbackground=self.theme_color, relief=tk.FLAT, width=14)
        char_entry.pack(side=tk.RIGHT)

        def on_char_update(*args):
            val = char_var.get().strip()
            self.state.target_char_name = val
            self._save_current_settings()

        char_var.trace_add('write', on_char_update)

        style = ttk.Style(win)
        style.theme_use('clam')
        style.configure('Dark.TCombobox', fieldbackground='#180D2E', background='#251347', foreground='#FFFFFF', arrowcolor=self.theme_color, borderwidth=0)

        nav_frame = tk.Frame(sec_view, bg='#0D0717')
        nav_frame.pack(fill=tk.X, padx=10, pady=(4, 6))
        tk.Label(nav_frame, text='Arrow Mode:', font=('Segoe UI', 9), fg='#E2E8F0', bg='#0D0717').pack(side=tk.LEFT)
        cur_mode_str = 'Compass (North-Up)' if getattr(self, 'compass_mode', False) else 'Movement Relative'
        nav_mode_var = tk.StringVar(value=cur_mode_str)

        def on_nav_mode_change(event=None):
            self.compass_mode = (nav_mode_var.get() == 'Compass (North-Up)')
            self._save_current_settings()
            self._draw_hud()

        cb_nav_mode = ttk.Combobox(nav_frame, textvariable=nav_mode_var, values=['Compass (North-Up)', 'Movement Relative'], state='readonly', style='Dark.TCombobox', font=('Segoe UI', 8), width=16)
        cb_nav_mode.pack(side=tk.RIGHT)
        cb_nav_mode.bind('<<ComboboxSelected>>', on_nav_mode_change)

        scale_frame = tk.Frame(sec_view, bg='#0D0717')
        scale_frame.pack(fill=tk.X, padx=10, pady=(4, 0))
        tk.Label(scale_frame, text='Radar Scale / Size:', font=('Segoe UI', 9), fg='#E2E8F0', bg='#0D0717').pack(side=tk.LEFT)
        lbl_scale_val = tk.Label(scale_frame, text=f'{int(self.scale * 100)}%', font=('Segoe UI', 9, 'bold'), fg='#C084FC', bg='#0D0717')
        lbl_scale_val.pack(side=tk.RIGHT)

        def on_scale_change(val):
            s = int(float(val)) / 100.0
            self.scale = max(0.75, min(1.5, s))
            lbl_scale_val.config(text=f'{int(self.scale * 100)}%')
            nw = int(self.base_width * self.scale)
            nh = int(self.base_height * self.scale)
            cx = self.root.winfo_x()
            cy = self.root.winfo_y()
            self.root.geometry(f'{nw}x{nh}+{cx}+{cy}')
            self.canvas.config(width=nw, height=nh)
            self._save_current_settings()
            self._draw_hud()

        scale_slider = tk.Scale(sec_view, from_=75, to=150, orient=tk.HORIZONTAL, showvalue=0, command=on_scale_change, bg='#0D0717', fg='#C084FC', troughcolor='#1E1133', activebackground=self.theme_color, bd=0, highlightthickness=0)
        scale_slider.set(int(self.scale * 100))
        scale_slider.pack(fill=tk.X, padx=10, pady=(2, 6))

        op_frame = tk.Frame(sec_view, bg='#0D0717')
        op_frame.pack(fill=tk.X, padx=10, pady=(4, 0))
        tk.Label(op_frame, text='Radar Opacity:', font=('Segoe UI', 9), fg='#E2E8F0', bg='#0D0717').pack(side=tk.LEFT)
        lbl_alpha_val = tk.Label(op_frame, text=f'{int(self.current_alpha * 100)}%', font=('Segoe UI', 9, 'bold'), fg='#C084FC', bg='#0D0717')
        lbl_alpha_val.pack(side=tk.RIGHT)

        def on_alpha_change(val):
            alpha = int(float(val)) / 100.0
            self.current_alpha = max(0.2, min(1.0, alpha))
            self.root.attributes('-alpha', self.current_alpha)
            lbl_alpha_val.config(text=f'{int(self.current_alpha * 100)}%')
            self._save_current_settings()

        alpha_scale = tk.Scale(sec_view, from_=20, to=100, orient=tk.HORIZONTAL, showvalue=0, command=on_alpha_change, bg='#0D0717', fg='#C084FC', troughcolor='#1E1133', activebackground=self.theme_color, bd=0, highlightthickness=0)
        alpha_scale.set(int(self.current_alpha * 100))
        alpha_scale.pack(fill=tk.X, padx=10, pady=(2, 6))

        sec_sound = tk.LabelFrame(body, text=' AUDIO SETTINGS ', font=('Segoe UI', 8, 'bold'), fg=self.theme_color, bg='#0D0717', bd=1, relief=tk.SOLID)
        sec_sound.pack(fill=tk.X, pady=(0, 10), ipady=4)
        sound_var = tk.BooleanVar(value=self.state.sound_enabled)

        def on_sound_toggle():
            self.state.sound_enabled = sound_var.get()
            self._save_current_settings()

        chk_sound = tk.Checkbutton(sec_sound, text='Enable Audio Alert', variable=sound_var, command=on_sound_toggle, font=('Segoe UI', 9), fg='#E2E8F0', bg='#0D0717', selectcolor='#1E1133', activebackground='#0D0717', activeforeground='#E2E8F0', bd=0, highlightthickness=0)
        chk_sound.pack(anchor='w', padx=10, pady=(4, 4))
        style = ttk.Style(win)
        style.theme_use('clam')
        style.configure('Dark.TCombobox', fieldbackground='#180D2E', background='#251347', foreground='#FFFFFF', arrowcolor=self.theme_color, borderwidth=0)
        tone_frame = tk.Frame(sec_sound, bg='#0D0717')
        tone_frame.pack(fill=tk.X, padx=10, pady=(2, 6))
        tk.Label(tone_frame, text='Alert Tone:', font=('Segoe UI', 9), fg='#E2E8F0', bg='#0D0717').pack(side=tk.LEFT)
        tone_var = tk.StringVar(value=self.state.sound_profile)

        def on_tone_change(event=None):
            self.state.sound_profile = tone_var.get()
            self._save_current_settings()
            if self.state.sound_enabled:
                threading.Thread(target=play_cube_sound, args=(False, self.state.sound_volume, self.state.sound_profile), daemon=True).start()

        cb_tone = ttk.Combobox(tone_frame, textvariable=tone_var, values=list(SOUND_PROFILES.keys()), state='readonly', style='Dark.TCombobox', font=('Segoe UI', 8), width=14)
        cb_tone.pack(side=tk.RIGHT)
        cb_tone.bind('<<ComboboxSelected>>', on_tone_change)
        vol_frame = tk.Frame(sec_sound, bg='#0D0717')
        vol_frame.pack(fill=tk.X, padx=10, pady=(2, 0))
        tk.Label(vol_frame, text='Sound Volume:', font=('Segoe UI', 9), fg='#E2E8F0', bg='#0D0717').pack(side=tk.LEFT)
        lbl_vol_val = tk.Label(vol_frame, text=f'{int(self.state.sound_volume * 100)}%', font=('Segoe UI', 9, 'bold'), fg='#C084FC', bg='#0D0717')
        lbl_vol_val.pack(side=tk.RIGHT)

        def on_vol_change(val):
            vol = int(float(val)) / 100.0
            self.state.sound_volume = max(0.0, min(1.0, vol))
            lbl_vol_val.config(text=f'{int(self.state.sound_volume * 100)}%')
            self._save_current_settings()

        vol_scale = tk.Scale(sec_sound, from_=0, to=100, orient=tk.HORIZONTAL, showvalue=0, command=on_vol_change, bg='#0D0717', fg='#C084FC', troughcolor='#1E1133', activebackground=self.theme_color, bd=0, highlightthickness=0)
        vol_scale.set(int(self.state.sound_volume * 100))
        vol_scale.pack(fill=tk.X, padx=10, pady=(2, 6))

        def test_sound_click():
            threading.Thread(target=play_cube_sound, args=(False, self.state.sound_volume, self.state.sound_profile), daemon=True).start()

        btn_test_sound = tk.Button(sec_sound, text='Test Sound', font=('Segoe UI', 8, 'bold'), fg=self.theme_color, bg='#1E1133', activebackground='#3B1D66', bd=0, padx=12, pady=3, cursor='hand2', command=test_sound_click)
        btn_test_sound.pack(anchor='e', padx=10, pady=(0, 6))
        btn_close_settings = tk.Button(win, text='Done', font=('Segoe UI', 9, 'bold'), fg='#0B0813', bg=self.theme_color, activebackground='#C084FC', bd=0, pady=5, cursor='hand2', command=win.destroy)
        btn_close_settings.pack(fill=tk.X, padx=16, pady=(4, 14))

    def _on_close(self):
        if self.settings_win and self.settings_win.winfo_exists():
            try:
                self.settings_win.destroy()
            except Exception:
                pass
        self.root.destroy()
        os._exit(0)

    def _render_loop(self):
        try:
            self._draw_hud()
        except Exception:
            pass
        self.root.after(33, self._render_loop)

    def _draw_3d_arrow(self, cx: float, cy: float, angle_rad: float, size: float = 32.0, dist: float = 100.0):
        if dist < 15.0:
            top_l = '#86EFAC'
            top_r = '#22C55E'
            side_c = '#15803D'
            sh_c = '#021B0A'
            border_c = '#14532D'
        elif dist < 50.0:
            top_l = '#FEF08A'
            top_r = '#F59E0B'
            side_c = '#B45309'
            sh_c = '#1F1302'
            border_c = '#78350F'
        else:
            top_l = '#FCA5A5'
            top_r = '#EF4444'
            side_c = '#B91C1C'
            sh_c = '#220808'
            border_c = '#7F1D1D'

        s = size / 40.0
        tip = (0.0, -28.0 * s)
        l_wing = (-17.0 * s, 4.0 * s)
        r_wing = (17.0 * s, 4.0 * s)
        l_in = (-7.5 * s, 2.0 * s)
        r_in = (7.5 * s, 2.0 * s)
        l_tail = (-7.5 * s, 22.0 * s)
        r_tail = (7.5 * s, 22.0 * s)
        c_base = (0.0, 22.0 * s)
        c_spine = (0.0, 2.0 * s)

        def rot(pt: Tuple[float, float], ox: float = 0.0, oy: float = 0.0) -> Tuple[float, float]:
            rad = angle_rad
            px = pt[0] + ox
            py = pt[1] + oy
            return (cx + px * math.cos(rad) - py * math.sin(rad), cy + px * math.sin(rad) + py * math.cos(rad))

        p_tip = rot(tip)
        p_lw = rot(l_wing)
        p_rw = rot(r_wing)
        p_lin = rot(l_in)
        p_rin = rot(r_in)
        p_lt = rot(l_tail)
        p_rt = rot(r_tail)
        p_base = rot(c_base)
        p_spine = rot(c_spine)

        dx, dy = 2.0, 3.5
        sh_pts = [rot(tip, 2, 5), rot(r_wing, 2, 5), rot(r_tail, 2, 5), rot(l_tail, 2, 5), rot(l_wing, 2, 5)]
        self.canvas.create_polygon([c for pt in sh_pts for c in pt], fill=sh_c, outline='', smooth=True)

        ext_poly = [
            (p_tip[0]+dx, p_tip[1]+dy),
            (p_rw[0]+dx, p_rw[1]+dy),
            (p_rin[0]+dx, p_rin[1]+dy),
            (p_rt[0]+dx, p_rt[1]+dy),
            (p_lt[0]+dx, p_lt[1]+dy),
            (p_lin[0]+dx, p_lin[1]+dy),
            (p_lw[0]+dx, p_lw[1]+dy)
        ]
        self.canvas.create_polygon([c for pt in ext_poly for c in pt], fill=side_c, outline=border_c, width=1)

        self.canvas.create_polygon([c for pt in [p_tip, p_spine, p_lin, p_lw] for c in pt], fill=top_l, outline=border_c, width=1)
        self.canvas.create_polygon([c for pt in [p_spine, p_base, p_lt, p_lin] for c in pt], fill=top_l, outline=border_c, width=1)
        self.canvas.create_polygon([c for pt in [p_tip, p_rw, p_rin, p_spine] for c in pt], fill=top_r, outline=border_c, width=1)
        self.canvas.create_polygon([c for pt in [p_spine, p_rin, p_rt, p_base] for c in pt], fill=top_r, outline=border_c, width=1)

    def _draw_hud(self):
        snap = self.state.get_snapshot()
        self.canvas.delete('all')
        scale = getattr(self, 'scale', 1.0)
        w = int(self.base_width * scale)
        h = int(self.base_height * scale)

        self.canvas.create_rectangle(0, 0, w, h, fill='#0B0813', outline='#2E1065', width=1)
        self.canvas.create_line(1, 1, w - 1, 1, fill=self.theme_color, width=1)

        char_name = snap.get('target_char_name', '')
        eid = snap.get('player_entity_id')
        locked = snap.get('player_id_locked', False)
        lpt = snap.get('last_pos_time', 0.0)
        now = time.time()
        pos_age = (now - lpt) if lpt > 0.0 else None

        if eid and locked and pos_age is not None and pos_age <= 4.0:
            status_dot_color = '#00E676'
            age_badge = 'LIVE'
        elif eid and pos_age is not None and pos_age <= 15.0:
            status_dot_color = '#38BDF8'
            age_badge = f'{int(pos_age)}s'
        elif eid:
            status_dot_color = '#F59E0B'
            age_badge = f'{int(pos_age)}s' if pos_age is not None else 'IDLE'
        else:
            status_dot_color = '#94A3B8'
            age_badge = 'WAIT'

        self.canvas.create_oval(int(13 * scale), int(12 * scale), int(19 * scale), int(18 * scale), fill=status_dot_color, outline='')

        title_text = f'A2 HCR · {char_name}' if char_name else 'A2 HCR'
        title_color = '#00E676' if (eid and locked and pos_age is not None and pos_age <= 4.0) else (self.theme_color if eid else '#C084FC')
        self.canvas.create_text(w // 2, int(15 * scale), text=title_text, fill=title_color, font=('Segoe UI', max(7, int(9 * scale)), 'bold'))

        self.canvas.create_text(w - int(32 * scale), int(15 * scale), text='⚙', fill='#94A3B8', activefill=self.theme_color, font=('Segoe UI', max(7, int(9 * scale))))
        self.canvas.create_text(w - int(14 * scale), int(15 * scale), text='✕', fill='#94A3B8', activefill='#FF5252', font=('Segoe UI', max(6, int(8 * scale)), 'bold'))

        player_pos = snap.get('player_pos')
        heading = snap.get('player_heading')
        cubes: List[CubeItem] = snap.get('cubes', [])

        closest_cube: Optional[CubeItem] = None
        closest_dist = float('inf')
        closest_cdz = 0.0
        closest_cdx = 0.0
        closest_cdy = 0.0

        if player_pos and cubes:
            px, py, pz = player_pos
            for c in cubes:
                cdx = (c.x - px) / 100.0
                cdy = (c.y - py) / 100.0
                cdz = (c.z - pz) / 100.0
                d = math.sqrt(cdx * cdx + cdy * cdy + cdz * cdz)
                if d < closest_dist:
                    closest_dist = d
                    closest_cube = c
                    closest_cdz = cdz
                    closest_cdx = cdx
                    closest_cdy = cdy

        disc_cx = w // 2
        disc_cy = int(86 * scale)
        r = int(40 * scale)

        if closest_cube:
            cube_label = closest_cube.name
            if len(cubes) > 1:
                cube_label += f' (1/{len(cubes)})'
            sub_text = f'{cube_label} · {age_badge}'
            self.canvas.create_text(w // 2, int(33 * scale), text=sub_text, fill='#F8FAFC', font=('Segoe UI', max(7, int(8 * scale)), 'bold'))

            bearing_to_cube = math.atan2(closest_cdx, -closest_cdy)
            if getattr(self, 'compass_mode', False):
                target_angle = bearing_to_cube
                deg = math.degrees(target_angle)
                dir_text = get_compass_label(deg)
                dir_color = '#C084FC'
            else:
                if heading is not None:
                    target_angle = (bearing_to_cube - heading + math.pi) % (2.0 * math.pi) - math.pi
                    deg = math.degrees(target_angle)
                    dir_text, is_ahead = get_direction_label(deg)
                    dir_color = '#C084FC' if is_ahead else '#F59E0B'
                else:
                    target_angle = 0.0
                    dir_text = 'Run to align'
                    dir_color = '#94A3B8'

            angle_diff = (target_angle - self.cur_visual_angle + math.pi) % (2.0 * math.pi) - math.pi
            self.cur_visual_angle = (self.cur_visual_angle + angle_diff * 0.35 + math.pi) % (2.0 * math.pi) - math.pi

            if closest_dist < 10.0:
                dist_str = f'{closest_dist:.1f} m'
            else:
                dist_str = f'{closest_dist:.0f} m'

            v_diff = closest_cdz
            if v_diff >= 0.8:
                v_str = f'{v_diff:.1f} m' if v_diff < 10.0 else f'{v_diff:.0f} m'
                box_text = f'↑ ABOVE BY {v_str}'
                box_fg = '#38BDF8'
            elif v_diff <= -0.8:
                v_val = abs(v_diff)
                v_str = f'{v_val:.1f} m' if v_val < 10.0 else f'{v_val:.0f} m'
                box_text = f'↓ BELOW BY {v_str}'
                box_fg = '#F59E0B'
            else:
                box_text = '═ LEVEL (SAME HEIGHT)'
                box_fg = '#A7F3D0'

            self.canvas.create_oval(disc_cx - r, disc_cy - r, disc_cx + r, disc_cy + r, outline='#3B0764', width=1.5, fill='#130A24')
            self.canvas.create_oval(disc_cx - r + int(8 * scale), disc_cy - r + int(8 * scale), disc_cx + r - int(8 * scale), disc_cy + r - int(8 * scale), outline='#240742', width=1, dash=(2, 2))
            cardinal_font = ('Segoe UI', max(6, int(7 * scale)), 'bold')
            if getattr(self, 'compass_mode', False):
                self.canvas.create_text(disc_cx, disc_cy - r + int(7 * scale), text='N', fill='#38BDF8', font=cardinal_font)
                self.canvas.create_text(disc_cx, disc_cy + r - int(7 * scale), text='S', fill='#64748B', font=cardinal_font)
                self.canvas.create_text(disc_cx + r - int(7 * scale), disc_cy, text='E', fill='#64748B', font=cardinal_font)
                self.canvas.create_text(disc_cx - r + int(7 * scale), disc_cy, text='W', fill='#64748B', font=cardinal_font)
            else:
                self.canvas.create_text(disc_cx, disc_cy - r + int(7 * scale), text='▲', fill=self.theme_color, font=cardinal_font)

            self._draw_3d_arrow(disc_cx, disc_cy, self.cur_visual_angle, size=30.0 * scale, dist=closest_dist)

            if closest_dist < 15.0:
                dist_color = '#86EFAC'
            elif closest_dist < 50.0:
                dist_color = '#FEF08A'
            else:
                dist_color = '#FCA5A5'

            self.canvas.create_text(w // 2, int(140 * scale), text=dist_str, fill=dist_color, font=('Segoe UI', max(12, int(19 * scale)), 'bold'))
            self.canvas.create_text(w // 2, int(161 * scale), text=dir_text, fill=dir_color, font=('Segoe UI', max(7, int(8 * scale)), 'bold'))

            bx1, by1, bx2, by2 = int(16 * scale), int(175 * scale), w - int(16 * scale), int(201 * scale)
            self.canvas.create_rectangle(bx1, by1, bx2, by2, outline='#2E1065', fill='#130A21', width=1.5)
            self.canvas.create_text(w // 2, (by1 + by2) // 2, text=box_text, fill=box_fg, font=('Segoe UI', max(6, int(8 * scale)), 'bold'))
        else:
            self.canvas.create_text(w // 2, int(33 * scale), text=f'Searching for Cubes... · {age_badge}', fill='#94A3B8', font=('Segoe UI', max(7, int(8 * scale))))

            self.canvas.create_oval(disc_cx - r, disc_cy - r, disc_cx + r, disc_cy + r, outline='#3B0764', width=1.5, fill='#130A24')
            self.canvas.create_oval(disc_cx - r + int(8 * scale), disc_cy - r + int(8 * scale), disc_cx + r - int(8 * scale), disc_cy + r - int(8 * scale), outline='#240742', width=1, dash=(2, 2))
            cardinal_font = ('Segoe UI', max(6, int(7 * scale)), 'bold')
            if getattr(self, 'compass_mode', False):
                self.canvas.create_text(disc_cx, disc_cy - r + int(7 * scale), text='N', fill='#38BDF8', font=cardinal_font)
                self.canvas.create_text(disc_cx, disc_cy + r - int(7 * scale), text='S', fill='#64748B', font=cardinal_font)
                self.canvas.create_text(disc_cx + r - int(7 * scale), disc_cy, text='E', fill='#64748B', font=cardinal_font)
                self.canvas.create_text(disc_cx - r + int(7 * scale), disc_cy, text='W', fill='#64748B', font=cardinal_font)
            else:
                self.canvas.create_text(disc_cx, disc_cy - r + int(7 * scale), text='▲', fill=self.theme_color, font=cardinal_font)

            self.scanner_phase = (self.scanner_phase + 0.08) % (2.0 * math.pi)
            sx = disc_cx + math.cos(self.scanner_phase) * (r - 2)
            sy = disc_cy + math.sin(self.scanner_phase) * (r - 2)
            self.canvas.create_line(disc_cx, disc_cy, sx, sy, fill=self.theme_color, width=1.5)
            self.canvas.create_oval(disc_cx - 3, disc_cy - 3, disc_cx + 3, disc_cy + 3, fill=self.theme_color, outline='')

            if player_pos:
                self.canvas.create_text(w // 2, int(140 * scale), text='IN RANGE', fill='#94A3B8', font=('Segoe UI', max(11, int(15 * scale)), 'bold'))
                self.canvas.create_text(w // 2, int(161 * scale), text=f'Pos: {player_pos[0]:.0f}, {player_pos[1]:.0f} ({age_badge})', fill=self.theme_color, font=('Segoe UI', max(6, int(8 * scale))))
            else:
                self.canvas.create_text(w // 2, int(140 * scale), text='STANDBY', fill='#94A3B8', font=('Segoe UI', max(11, int(15 * scale)), 'bold'))
                self.canvas.create_text(w // 2, int(161 * scale), text='Jump/Dash for position...', fill='#64748B', font=('Segoe UI', max(6, int(8 * scale))))

            bx1, by1, bx2, by2 = int(16 * scale), int(175 * scale), w - int(16 * scale), int(201 * scale)
            self.canvas.create_rectangle(bx1, by1, bx2, by2, outline='#2E1065', fill='#130A21', width=1)
            self.canvas.create_text(w // 2, (by1 + by2) // 2, text='SCANNING (150m RANGE)', fill='#64748B', font=('Segoe UI', max(6, int(8 * scale)), 'bold'))

        self.canvas.create_text(w // 2, int(222 * scale), text='Drag to move · Click ⚙ for settings', fill='#64748B', font=('Segoe UI', max(5, int(7 * scale))))

def start_pure_sniffer(state: RadarState, port_override: Optional[int] = None):
    conn = detect_aion2_connection()
    target_port = port_override or (conn.remote_port if conn and conn.remote_port else None)
    engine = PureStreamEngine(state, target_port=target_port)
    if target_port and target_port not in (13328, 13320):
        bpf_filter = f'tcp and port {target_port}'
        print(f'[+] 3D Nav Radar Started. Port: {target_port}')
    else:
        bpf_filter = 'tcp and (port 13328 or port 13320)'
        print('[+] 3D Nav Radar Started. Ports: 13328, 13320')

    def on_packet(pkt):
        if TCP in pkt and IP in pkt:
            payload = bytes(pkt[TCP].payload)
            if payload:
                engine.feed_payload(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, payload)

    while True:
        try:
            sniff(filter=bpf_filter, prn=on_packet, store=False)
        except Exception:
            time.sleep(1)

def replay_pure_pcap(state: RadarState, pcap_path: str):
    engine = PureStreamEngine(state)
    print(f'[+] Replay Mode: {pcap_path}')

    def _worker():
        try:
            with PcapReader(pcap_path) as reader:
                for pkt in reader:
                    if TCP in pkt and IP in pkt:
                        payload = bytes(pkt[TCP].payload)
                        if payload:
                            engine.feed_payload(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, payload)
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()

def ask_character_name(cli_arg: Optional[str] = None, default_name: str = '') -> str:
    if cli_arg and cli_arg.strip():
        return cli_arg.strip()
    entered = [default_name]
    prompt_win = tk.Tk()
    prompt_win.title('A2 HCR - Character Name')
    prompt_win.geometry('340x180')
    prompt_win.configure(bg='#0D0717')
    prompt_win.resizable(False, False)
    prompt_win.update_idletasks()
    ws = prompt_win.winfo_screenwidth()
    hs = prompt_win.winfo_screenheight()
    x = max(0, ws // 2 - 170)
    y = max(0, hs // 2 - 90)
    prompt_win.geometry(f'340x180+{x}+{y}')
    try:
        prompt_win.attributes('-topmost', True)
    except Exception:
        pass
    prompt_win.update_idletasks()
    tk.Label(prompt_win, text='A2 HCR - 3D NAV RADAR', font=('Segoe UI', 11, 'bold'), fg='#A855F7', bg='#0D0717').pack(pady=(16, 4))
    tk.Label(prompt_win, text='Please enter your in-game Character Name:', font=('Segoe UI', 9), fg='#94A3B8', bg='#0D0717').pack(pady=(0, 10))
    entry_var = tk.StringVar(value=default_name)
    entry = tk.Entry(prompt_win, textvariable=entry_var, font=('Segoe UI', 11), bg='#180D2E', fg='#FFFFFF', insertbackground='#A855F7', relief=tk.FLAT, justify=tk.CENTER)
    entry.pack(fill=tk.X, padx=30, ipady=4)
    entry.focus_set()

    def on_submit(event=None):
        entered[0] = entry_var.get().strip()
        prompt_win.destroy()

    def on_win_close():
        prompt_win.destroy()
        os._exit(0)

    prompt_win.protocol('WM_DELETE_WINDOW', on_win_close)
    entry.bind('<Return>', on_submit)
    btn_submit = tk.Button(prompt_win, text='Start Radar', font=('Segoe UI', 10, 'bold'), bg='#A855F7', fg='#FFFFFF', activebackground='#C084FC', activeforeground='#FFFFFF', relief=tk.FLAT, cursor='hand2', command=on_submit)
    btn_submit.pack(pady=14, ipadx=10, ipady=2)
    prompt_win.mainloop()
    return entered[0]

def main():
    parser = argparse.ArgumentParser(description='A2 HCR - Modern 3D Navigation Radar')
    parser.add_argument('--char', type=str, help='In-game character name')
    parser.add_argument('--replay', type=str, help='Replay pcap file for visual testing')
    parser.add_argument('--port', type=int, help='Manual port override (Default: 13328)')
    args = parser.parse_args()
    cfg = load_radar_settings()
    saved_char = cfg.get('character_name', '')
    target_char = ask_character_name(args.char, saved_char)
    cfg['character_name'] = target_char
    save_radar_settings(cfg)
    if target_char:
        print(f"[+] Target Character: '{target_char}' set.")
    else:
        print('[*] No character name specified, automatic network detection active on first action.')
    state = RadarState()
    state.target_char_name = target_char
    if args.replay:
        replay_pure_pcap(state, args.replay)
    else:
        t = threading.Thread(target=start_pure_sniffer, args=(state, args.port), daemon=True)
        t.start()
    root = tk.Tk()
    app = Modern3DNavRadarApp(root, state)
    root.mainloop()

if __name__ == '__main__':
    main()
