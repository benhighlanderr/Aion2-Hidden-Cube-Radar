from __future__ import annotations
import argparse
import json
import math
import os
import struct
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import tkinter as tk
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
            conns = p.net_connections(kind='tcp')
            for c in conns:
                if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                    if c.raddr.port in (13328, 13320):
                        return Aion2ConnectionInfo(pid=pid, process_name=proc_name, local_ip=c.laddr.ip, local_port=c.laddr.port, remote_ip=c.raddr.ip, remote_port=c.raddr.port)
                    if c.raddr.port not in (80, 443) and (not c.raddr.ip.startswith('127.')):
                        candidate_conn = Aion2ConnectionInfo(pid=pid, process_name=proc_name, local_ip=c.laddr.ip, local_port=c.laddr.port, remote_ip=c.raddr.ip, remote_port=c.raddr.port)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if candidate_conn:
        return candidate_conn
    return Aion2ConnectionInfo(pid=aion_pids[0][0], process_name=aion_pids[0][1], local_ip='', local_port=0, remote_ip='', remote_port=13328)

def decode_uvarint(data: bytes, offset: int=0) -> Tuple[int, int]:
    value = 0
    for i in range(5):
        at = offset + i
        if at >= len(data):
            raise ValueError('incomplete uvarint')
        b = data[at]
        value |= (b & 127) << 7 * i
        if not b & 128:
            return (value, i + 1)
    raise ValueError('uvarint exceeds 5 bytes')

def play_cube_sound(is_asmodian: bool=False):
    try:
        import winsound
        if is_asmodian:
            winsound.Beep(1400, 180)
            winsound.Beep(2100, 320)
        else:
            winsound.Beep(900, 150)
    except Exception:
        try:
            sys.stdout.write('\x07')
            sys.stdout.flush()
        except Exception:
            pass
ASMODIAN_V04_IDS: set[int] = {1301199, 1301200, 1300754, 1300081, 1300082, 1000566, 1200039, 1200040, 1200041}
HIDDEN_CUBE_IDS: Dict[int, str] = {
    1000295: 'Hidden Cube (Basic_HiddenCube_01)',
    1000548: 'Hidden Cube (Basic_HiddenCube_01_V01)',
    1000556: 'Hidden Cube (Basic_HiddenCube_01_V02)',
    1000568: 'Hidden Cube (Basic_HiddenCube_01_V03)',
    1000566: 'Hidden Cube V04 (Basic_HiddenCube_01_V04)',
    1000567: 'Hidden Cube (Basic_HiddenCube_01_V05)',
    1100056: 'Hidden Cube (E_FE_TB_HiddenCube_01)',
    1100094: 'Hidden Cube (E_FE_SpecterEvasion_HiddenCube_01)',
    1200018: 'Hidden Cube (E_HiddenCube_01_001)',
    1200036: 'Hidden Cube (E_HiddenCube_01_001)',
    1200037: 'Hidden Cube (E_HiddenCube_01_002)',
    1200039: 'Hidden Cube V04 (E_HiddenCube_01_V04_001)',
    1200040: 'Hidden Cube V04 (E_HiddenCube_01_V04_002)',
    1200041: 'Hidden Cube V04 (E_HiddenCube_01_V04_003)',
    1200667: 'Hidden Cube (E_HiddenCube_01_003)',
    1200707: 'Hidden Cube (E_L1_FE_SpecterEvasion_HiddenCube_01)',
    1201054: 'Hidden Cube (E_HiddenCube_01_004)',
    1201055: 'Hidden Cube (E_HiddenCube_01_005)',
    1300081: 'Asmodian Hidden Cube (E_D1_TreasureBoxRare_001)',
    1300082: 'Asmodian Hidden Cube (E_D1_TreasureBoxLegend_001)',
    1300754: 'Asmodian Hidden Cube (E_D1_HiddenCube_01)',
    1301199: 'Asmodian Hidden Cube V04 (E_D1_TreasureBoxRare_002)',
    1301200: 'Asmodian Hidden Cube V04 (E_D1_HiddenCube_02)',
    1401335: 'Hidden Cube (E_HiddenCube_01_006)',
    1401336: 'Hidden Cube (E_HiddenCube_01_007)',
    3682560: 'Hidden Cube (Special_HiddenCube)'
}

def is_target_hidden_cube(obj_id: int) -> bool:
    return obj_id in HIDDEN_CUBE_IDS

@dataclass
class CubeItem:
    entity_id: int
    npc_id: int
    name: str
    x: float
    y: float
    z: float
    is_asmodian: bool
    model_name: str

class RadarState:

    def __init__(self):
        self.lock = threading.Lock()
        self.player_pos: Optional[Tuple[float, float, float]] = None
        self.player_heading: Optional[float] = None
        self.last_dist: Optional[float] = None
        self.dist_delta: float = 0.0
        self.player_entity_id: Optional[int] = None
        self.player_id_locked: bool = False
        self.cubes: Dict[int, CubeItem] = {}
        self.packet_count: int = 0
        self.range_meters: float = 100.0
        self.sound_enabled: bool = True
        self.target_char_name: str = ''
        self.last_pos_time: float = 0.0
        self.last_sim_time: float = 0.0
        self.vel_x: float = 0.0
        self.vel_y: float = 0.0
        self.est_player_pos: Optional[Tuple[float, float, float]] = None
        self.extrapolation_enabled: bool = True
        self.last_c2s_step_time: float = 0.0
        self.last_c2s_move_time: float = 0.0
        self.base_walk_speed: float = 650.0
        self.c2s_step_count: int = 0
        self.on_update_callback: Optional[Any] = None

    def notify_update(self):
        cb = self.on_update_callback
        if cb:
            try:
                cb()
            except Exception:
                pass

    def set_player_pos(self, x: float, y: float, z: float, force: bool=False) -> bool:
        now = time.time()
        with self.lock:
            if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
                return False
            if abs(x) > 500000.0 or abs(y) > 500000.0 or abs(z) > 500000.0:
                return False
            if self.player_pos and (not force):
                dx = x - self.player_pos[0]
                dy = y - self.player_pos[1]
                dist = math.hypot(dx, dy)
                if dist > 50.0:
                    heading = math.atan2(dx, dy)
                    self.player_heading = heading
                    self.vel_x = math.sin(heading) * self.base_walk_speed
                    self.vel_y = math.cos(heading) * self.base_walk_speed
            self.player_pos = (x, y, z)
            self.est_player_pos = (x, y, z)
            self.last_pos_time = now
            self.last_sim_time = now
        self.notify_update()
        return True

    def get_estimated_player_pos(self) -> Optional[Tuple[float, float, float]]:
        if not self.player_pos:
            return None
        now = time.time()
        if not self.extrapolation_enabled or self.last_sim_time <= 0:
            return self.player_pos
        dt = now - self.last_sim_time
        self.last_sim_time = now
        if dt <= 0:
            return self.est_player_pos or self.player_pos
        dt = min(dt, 0.15)
        is_moving = (now - self.last_c2s_step_time) < 0.35
        if not is_moving:
            return self.est_player_pos or self.player_pos
        vx, vy = self.vel_x, self.vel_y
        if vx == 0.0 and vy == 0.0 and self.cubes:
            closest_c = None
            min_d = float('inf')
            cur = self.est_player_pos or self.player_pos
            for c in self.cubes.values():
                d = math.hypot(c.x - cur[0], c.y - cur[1])
                if d < min_d:
                    min_d = d
                    closest_c = c
            if closest_c and min_d > 100.0:
                cdx = closest_c.x - cur[0]
                cdy = closest_c.y - cur[1]
                cd = math.hypot(cdx, cdy)
                vx = (cdx / cd) * self.base_walk_speed
                vy = (cdy / cd) * self.base_walk_speed
        if vx != 0.0 or vy != 0.0:
            cur = self.est_player_pos or self.player_pos
            nx = cur[0] + vx * dt
            ny = cur[1] + vy * dt
            self.est_player_pos = (nx, ny, self.player_pos[2])
            return self.est_player_pos
        return self.est_player_pos or self.player_pos

    def on_c2s_movement_frame(self, frame_len: int):
        now = time.time()
        with self.lock:
            self.last_c2s_step_time = now
            self.last_c2s_move_time = now
            self.c2s_step_count += 1
        self.notify_update()

    def update_dist_delta(self, curr_dist: float):
        with self.lock:
            if self.last_dist is not None:
                self.dist_delta = curr_dist - self.last_dist
            self.last_dist = curr_dist

    def set_player_id(self, eid: int, lock: bool=False, force: bool=False):
        if eid <= 100:
            return
        with self.lock:
            if self.player_id_locked and (not lock) and (not force):
                return
            self.player_entity_id = eid
            if lock:
                self.player_id_locked = True

    def reset_zone(self):
        with self.lock:
            self.cubes.clear()
            self.player_entity_id = None
            self.player_id_locked = False
            self.vel_x = 0.0
            self.vel_y = 0.0
            self.player_heading = None
            self.est_player_pos = None
            self.last_pos_time = 0.0
            self.last_sim_time = 0.0
            self.last_dist = None
            self.dist_delta = 0.0

    def add_cube(self, cube: CubeItem) -> bool:
        with self.lock:
            is_new = cube.entity_id not in self.cubes
            self.cubes[cube.entity_id] = cube
            if len(self.cubes) > 100 and self.player_pos:
                px, py, pz = self.player_pos
                to_pop = [eid for eid, c in self.cubes.items() if (c.x - px) ** 2 + (c.y - py) ** 2 > 35000.0 * 35000.0]
                for eid in to_pop:
                    self.cubes.pop(eid, None)
        self.notify_update()
        return is_new

    def remove_cube(self, eid: int):
        with self.lock:
            self.cubes.pop(eid, None)
            if not self.cubes:
                self.last_dist = None
                self.dist_delta = 0.0
        self.notify_update()

    def remove_nearby_cubes(self, radius_cm: float=600.0):
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
            est_pos = self.get_estimated_player_pos()
            return {'player_pos': est_pos, 'raw_player_pos': self.player_pos, 'player_heading': self.player_heading, 'last_dist': self.last_dist, 'dist_delta': self.dist_delta, 'player_entity_id': self.player_entity_id, 'cubes': list(self.cubes.values()), 'packet_count': self.packet_count, 'range_meters': self.range_meters, 'extrapolation_enabled': self.extrapolation_enabled, 'target_char_name': self.target_char_name, 'player_id_locked': self.player_id_locked}

def is_valid_coord(x: float, y: float, z: float) -> bool:
    if not (math.isfinite(x) and math.isfinite(y) and math.isfinite(z)):
        return False
    if abs(x) > 500000.0 or abs(y) > 500000.0 or abs(z) > 500000.0:
        return False
    return True


class PureStreamEngine:

    def __init__(self, state: RadarState):
        self.state = state
        self.last_pos_print: float = 0.0

    def feed_payload(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes):
        if not payload:
            return
        if dst_port in (13328, 13320) and len(payload) not in (11, 12, 16):
            self.state.on_c2s_movement_frame(len(payload))
            return
        self.state.packet_count += 1
        off = 0
        p_len = len(payload)
        while off < p_len:
            if payload[off] == 0:
                off += 1
                continue
            try:
                encoded_len, varint_len = decode_uvarint(payload, off)
            except Exception:
                break
            body_len = encoded_len - 4
            if body_len < 2:
                off += 1
                continue
            frame_total_len = varint_len + body_len
            if frame_total_len <= varint_len or off + frame_total_len > p_len:
                break
            frame_body = payload[off + varint_len:off + frame_total_len]
            off += frame_total_len
            self.handle_frame(frame_body, is_lz4=False)

    def handle_frame(self, body: bytes, is_lz4: bool, depth: int=0):
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
        if self.state.target_char_name and (not self.state.player_id_locked):
            u8 = self.state.target_char_name.encode('utf-8')
            u16 = self.state.target_char_name.encode('utf-16le')
            if (u8 in p or u16 in p) and len(p) >= 100:
                try:
                    eid, _ = decode_uvarint(p, 0)
                    if eid > 100:
                        self.state.set_player_id(eid, lock=True, force=True)
                        print(f"[+] [ID LOCKED] '{self.state.target_char_name}' found -> Entity ID: {eid}")
                except Exception:
                    pass
        if opcode == 13876:
            try:
                eid, n = decode_uvarint(p, 0)
                if len(p) >= n + 18:
                    obj_id = struct.unpack('<I', p[n + 2:n + 6])[0]
                    if is_target_hidden_cube(obj_id):
                        x, y, z = struct.unpack('<fff', p[n + 6:n + 18])
                        name = HIDDEN_CUBE_IDS.get(obj_id, f'Hidden Cube ({obj_id})')
                        is_asmodian = obj_id in ASMODIAN_V04_IDS
                        is_new = self.state.add_cube(CubeItem(entity_id=eid, npc_id=obj_id, name=name, x=x, y=y, z=z, is_asmodian=is_asmodian, model_name='HiddenCube'))
                        if is_new and self.state.sound_enabled:
                            threading.Thread(target=play_cube_sound, args=(is_asmodian,), daemon=True).start()
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
        elif opcode in (36096, 13875):
            try:
                eid, _ = decode_uvarint(p, 0)
                if eid > 100:
                    self.state.set_player_id(eid, lock=False)
            except Exception:
                pass
        elif opcode == 13859:
            try:
                self.state.reset_zone()
                _, n = decode_uvarint(p, 0)
                pos_offset = n + 5
                if len(p) >= pos_offset + 12:
                    px, py, pz = struct.unpack('<fff', p[pos_offset:pos_offset + 12])
                    self.state.set_player_pos(px, py, pz, force=True)
            except Exception:
                pass
        elif (14096 <= opcode <= 14160) or opcode in (14378, 14379, 14380, 14340):
            try:
                eid, n = decode_uvarint(p, 0)
                if not self.state.player_entity_id and eid > 100:
                    self.state.set_player_id(eid, lock=False)
                if self.state.player_entity_id and eid == self.state.player_entity_id:
                    x, y, z = None, None, None
                    if opcode in (14378, 14379, 14380, 14340) and len(p) >= 12:
                        x, y, z = struct.unpack('<fff', p[-12:])
                    elif len(p) >= n + 14:
                        x, y, z = struct.unpack('<fff', p[n + 2:n + 14])
                    if x is not None and is_valid_coord(x, y, z):
                        self.state.set_player_pos(x, y, z)
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
        elif opcode == 13889:
            try:
                eid, n = decode_uvarint(p, 0)
                offset = n + 5
                if len(p) >= offset + 18:
                    npc_id = struct.unpack('<I', p[offset:offset + 4])[0]
                    if is_target_hidden_cube(npc_id):
                        x, y, z = struct.unpack('<fff', p[offset + 6:offset + 18])
                        self.state.add_cube(CubeItem(entity_id=eid, npc_id=npc_id, name=HIDDEN_CUBE_IDS.get(npc_id, f'Hidden Cube ({npc_id})'), x=x, y=y, z=z, is_asmodian=False, model_name='HiddenCube'))
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
                offset += 1
                continue
            total_len = varint_len + body_len
            if total_len <= varint_len or offset + total_len > d_len:
                break
            frame_body = data[offset + varint_len:offset + total_len]
            offset += total_len
            self.handle_frame(frame_body, is_lz4=True, depth=depth)

class Pure2DRadarApp:

    def __init__(self, root: tk.Tk, state: RadarState):
        self.root = root
        self.state = state
        char_display = self.state.target_char_name or 'Player'
        self.root.title(f'A2 HCR - {char_display}')
        self.base_width = 252
        self.base_height = 282
        self.root.geometry(f'{self.base_width}x{self.base_height}+1600+80')
        self.root.overrideredirect(True)
        self.root.attributes('-topmost', True)
        self.current_alpha = 0.9
        self.root.attributes('-alpha', self.current_alpha)
        self.root.configure(bg='#050811')
        self.player_color = '#00E676'
        self.cube_color = '#FF1744'
        self._drag_x = 0
        self._drag_y = 0
        self.canvas_size = 250
        self.cx = self.canvas_size // 2
        self.cy = self.canvas_size // 2
        self.radar_radius = 112
        self._last_dist: Optional[float] = None
        self._last_title = ''
        self._last_title_fg = ''
        self._build_ui()
        self._bind_events()
        self.root.after(33, self._render_loop)

    def _build_ui(self):
        self.header = tk.Frame(self.root, bg='#0E1626', height=28)
        self.header.pack(fill=tk.X, side=tk.TOP)
        char_display = self.state.target_char_name or 'Player'
        self.lbl_title = tk.Label(self.header, text=f'A2 HCR - {char_display}', font=('Segoe UI', 9, 'bold'), fg='#00E5FF', bg='#0E1626')
        self.lbl_title.pack(side=tk.LEFT, padx=8, pady=4)
        btn_close = tk.Button(self.header, text='X', font=('Segoe UI', 8, 'bold'), fg='#FF5252', bg='#0E1626', bd=0, padx=7, cursor='hand2', command=self._on_close)
        btn_close.pack(side=tk.RIGHT, padx=2)
        self.btn_sound = tk.Button(self.header, text='🔊', font=('Segoe UI', 8), fg='#00E676', bg='#0E1626', bd=0, padx=5, cursor='hand2', command=self._toggle_sound)
        self.btn_sound.pack(side=tk.RIGHT, padx=1)
        self.canvas = tk.Canvas(self.root, width=self.canvas_size, height=self.canvas_size, bg='#050811', highlightthickness=1, highlightbackground='#162238')
        self.canvas.pack(fill=tk.BOTH, expand=True)

    def _bind_events(self):
        for w in (self.header, self.lbl_title, self.canvas):
            w.bind('<ButtonPress-1>', self._start_drag)
            w.bind('<B1-Motion>', self._on_drag)

    def _start_drag(self, event):
        self._drag_x = event.x_root - self.root.winfo_x()
        self._drag_y = event.y_root - self.root.winfo_y()

    def _on_drag(self, event):
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self.root.geometry(f'+{x}+{y}')

    def _toggle_sound(self):
        self.state.sound_enabled = not self.state.sound_enabled
        if self.state.sound_enabled:
            self.btn_sound.config(text='🔊', fg='#00E676')
        else:
            self.btn_sound.config(text='🔇', fg='#94A3B8')

    def _on_close(self):
        self.root.destroy()
        os._exit(0)

    def _render_loop(self):
        try:
            self._draw_radar()
        except Exception:
            pass
        self.root.after(40, self._render_loop)

    def _draw_player_circle(self, px: float, py: float):
        r = 7.0
        self.canvas.create_oval(px - r - 2, py - r - 2, px + r + 2, py + r + 2, outline=self.player_color, width=1)
        self.canvas.create_oval(px - r, py - r, px + r, py + r, fill=self.player_color, outline='#FFFFFF', width=1.5)

    def _draw_cube_circle(self, px: float, py: float):
        r = 7.5
        self.canvas.create_oval(px - r - 3, py - r - 3, px + r + 3, py + r + 3, outline=self.cube_color, width=1)
        self.canvas.create_oval(px - r, py - r, px + r, py + r, fill=self.cube_color, outline='#FFFFFF', width=1.5)
        self.canvas.create_oval(px - 2, py - 2, px + 2, py + 2, fill='#FFFFFF', outline='')

    def _draw_radar(self):
        snap = self.state.get_snapshot()
        self.canvas.delete('all')
        char_name = snap.get('target_char_name', '')
        eid = snap.get('player_entity_id')
        locked = snap.get('player_id_locked', False)
        base_title = f'A2 HCR - {char_name}' if char_name else 'A2 HCR'
        new_title = f'{base_title} [LOCKED]' if (eid and locked) else (base_title if eid else f'{base_title} [WAITING]')
        new_fg = '#00E676' if eid else '#FFD700'
        if new_title != self._last_title or new_fg != self._last_title_fg:
            self.lbl_title.config(text=new_title, fg=new_fg)
            self._last_title = new_title
            self._last_title_fg = new_fg
        cx, cy = (self.cx, self.cy)
        R = self.radar_radius
        player_pos = snap['player_pos']
        self.canvas.create_oval(cx - R, cy - R, cx + R, cy + R, outline='#162238', width=1.5)
        half_r = R * 0.5
        self.canvas.create_oval(cx - half_r, cy - half_r, cx + half_r, cy + half_r, outline='#0E1626', width=1, dash=(2, 2))
        self.canvas.create_line(cx, cy - R + 10, cx, cy + R - 10, fill='#0E1626', width=1, dash=(3, 3))
        self.canvas.create_line(cx - R + 10, cy, cx + R - 10, cy, fill='#0E1626', width=1, dash=(3, 3))
        radar_range_m = 150.0
        eff_scale = (R - 16) / radar_range_m
        self.canvas.create_text(cx, cy + R - 10, text='Radar: 150m', fill='#475569', font=('Segoe UI', 7))
        visible: List[CubeItem] = snap['cubes']
        if player_pos:
            self._draw_player_circle(cx, cy)
            self.canvas.create_text(cx, cy + 12, text='YOU', fill=self.player_color, font=('Segoe UI', 7, 'bold'))
            if visible:
                closest_cube: Optional[CubeItem] = None
                closest_dist = float('inf')
                closest_cdz = 0.0
                closest_screen_pos = None
                max_r = R - 14
                for cube in visible:
                    cdx = (cube.x - player_pos[0]) / 100.0
                    cdy = (cube.y - player_pos[1]) / 100.0
                    cdz = (cube.z - player_pos[2]) / 100.0
                    cdist = math.sqrt(cdx * cdx + cdy * cdy + cdz * cdz)
                    screen_off_x = cdy * eff_scale
                    screen_off_y = -cdx * eff_scale
                    r_dist = math.hypot(screen_off_x, screen_off_y)
                    if r_dist > max_r:
                        ratio = max_r / r_dist
                        cube_x = cx + screen_off_x * ratio
                        cube_y = cy + screen_off_y * ratio
                    else:
                        cube_x = cx + screen_off_x
                        cube_y = cy + screen_off_y
                    self._draw_cube_circle(cube_x, cube_y)
                    if cdist < closest_dist:
                        closest_dist = cdist
                        closest_cube = cube
                        closest_cdz = cdz
                        closest_screen_pos = (cube_x, cube_y)
                if closest_cube and closest_screen_pos:
                    dist_m = closest_dist
                    delta = dist_m - self._last_dist if self._last_dist is not None else 0.0
                    self._last_dist = dist_m
                    ccx, ccy = closest_screen_pos
                    line_color = self.cube_color if delta > 0 else self.player_color
                    self.canvas.create_line(cx, cy, ccx, ccy, fill=line_color, dash=(3, 3), width=1.5)
                    lbl_text = f'{dist_m:.0f}m'
                    if abs(closest_cdz) >= 2.5:
                        lbl_text += f" ({('+' if closest_cdz > 0 else '')}{closest_cdz:.0f}m)"
                    lbl_y = ccy + 14 if ccy < 25 else ccy - 14
                    self.canvas.create_text(ccx, lbl_y, text=lbl_text, fill=self.cube_color, font=('Segoe UI', 8, 'bold'))
            else:
                self._last_dist = None
                self.canvas.create_text(cx, cy - 20, text='Searching Hidden Cube...', fill='#64748B', font=('Segoe UI', 8))
                self.canvas.create_text(cx, cy + 34, text=f'Pos: {player_pos[0]:.0f}, {player_pos[1]:.0f}', fill='#00E676', font=('Segoe UI', 7))
        else:
            self._last_dist = None
            self.canvas.create_oval(cx - 5, cy - 5, cx + 5, cy + 5, fill='#1E293B', outline='#475569')
            self.canvas.create_text(cx, cy + 18, text='Waiting for Player Position...', fill='#64748B', font=('Segoe UI', 8))

def start_pure_sniffer(state: RadarState, port_override: Optional[int]=None):
    engine = PureStreamEngine(state)
    conn = detect_aion2_connection()
    target_port = port_override or (conn.remote_port if conn and conn.remote_port else None)
    if target_port and target_port not in (13328, 13320):
        bpf_filter = f'tcp and port {target_port}'
        print(f'[+] 2D Radar Started. Port: {target_port}')
    else:
        bpf_filter = 'tcp and (port 13328 or port 13320)'
        print('[+] 2D Radar Started. Ports: 13328, 13320')

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

def ask_character_name(root: tk.Tk, cli_arg: Optional[str]=None) -> str:
    if cli_arg and cli_arg.strip():
        return cli_arg.strip()
    entered = ['']
    prompt_win = tk.Toplevel(root)
    prompt_win.title('A2 HCR - Character Name')
    prompt_win.geometry('340x180')
    prompt_win.configure(bg='#0B111E')
    prompt_win.resizable(False, False)
    prompt_win.attributes('-topmost', True)
    prompt_win.update_idletasks()
    ws = prompt_win.winfo_screenwidth()
    hs = prompt_win.winfo_screenheight()
    x = max(0, ws // 2 - 170)
    y = max(0, hs // 2 - 90)
    prompt_win.geometry(f'340x180+{x}+{y}')
    tk.Label(prompt_win, text='A2 HCR - HIDDEN CUBE RADAR', font=('Segoe UI', 11, 'bold'), fg='#00E5FF', bg='#0B111E').pack(pady=(16, 4))
    tk.Label(prompt_win, text='Please enter your in-game Character Name:', font=('Segoe UI', 9), fg='#94A3B8', bg='#0B111E').pack(pady=(0, 10))
    entry_var = tk.StringVar()
    entry = tk.Entry(prompt_win, textvariable=entry_var, font=('Segoe UI', 11), bg='#141E33', fg='#FFFFFF', insertbackground='#00E5FF', relief=tk.FLAT, justify=tk.CENTER)
    entry.pack(fill=tk.X, padx=30, ipady=4)
    entry.focus_set()

    def on_submit(event=None):
        entered[0] = entry_var.get().strip()
        prompt_win.destroy()

    def on_win_close():
        root.destroy()
        os._exit(0)

    prompt_win.protocol('WM_DELETE_WINDOW', on_win_close)
    entry.bind('<Return>', on_submit)
    btn_submit = tk.Button(prompt_win, text='Start Radar', font=('Segoe UI', 10, 'bold'), bg='#00E676', fg='#050811', activebackground='#00C853', activeforeground='#050811', relief=tk.FLAT, cursor='hand2', command=on_submit)
    btn_submit.pack(pady=14, ipadx=10, ipady=2)
    prompt_win.grab_set()
    root.wait_window(prompt_win)
    return entered[0]

def main():
    parser = argparse.ArgumentParser(description='A2 HCR - Hidden Cube Radar')
    parser.add_argument('--char', type=str, help='In-game character name')
    parser.add_argument('--replay', type=str, help='Replay pcap file for visual testing')
    parser.add_argument('--port', type=int, help='Manual port override (Default: 13328)')
    args = parser.parse_args()
    root = tk.Tk()
    root.withdraw()
    target_char = ask_character_name(root, args.char)
    root.deiconify()
    if target_char:
        print(f"[+] Target Character: '{target_char}' set (Not saved to disk).")
    else:
        print('[*] No character name specified, automatic network detection active.')
    state = RadarState()
    state.target_char_name = target_char
    if args.replay:
        replay_pure_pcap(state, args.replay)
    else:
        t = threading.Thread(target=start_pure_sniffer, args=(state, args.port), daemon=True)
        t.start()
    app = Pure2DRadarApp(root, state)
    root.mainloop()
if __name__ == '__main__':
    main()
