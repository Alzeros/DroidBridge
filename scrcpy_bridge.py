#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stdlib-only scrcpy v3.3.4 bridge and RFC 6455 WebSocket transport for DroidBridge.

Layers:
  1. Server binary SHA-256 verification & ADB atomic tcp:0 forward helpers
  2. Pure scrcpy v3.3.4 video/control protocol encoders & decoders
  3. RFC 6455 WebSocket server connection (masking, §5.4 fragmentation, interleaved control)
  4. ScrcpySession & PhoneMirrorManager lifecycle coordinator
"""
from __future__ import annotations

import base64
import collections
import hashlib
import json
import secrets
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent
SCRCPY_SERVER_VERSION = "3.3.4"
SCRCPY_SERVER_SHA256 = "8588238c9a5a00aa542906b6ec7e6d5541d9ffb9b5d0f6e1bc0e365e2303079e"
SCRCPY_REMOTE_PATH = "/data/local/tmp/droidbridge-scrcpy-server.jar"
DEFAULT_SERVER_PATH = ROOT / "vendor" / "scrcpy-server"

CODEC_ID_H264 = 0x68323634  # b"h264"
PACKET_FLAG_CONFIG = 1 << 63
PACKET_FLAG_KEY_FRAME = 1 << 62
MAX_VIDEO_PACKET_BYTES = 16 * 1024 * 1024

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_MAX_MESSAGE_BYTES = 256 * 1024
WS_VIDEO_TYPE = 0x01
WS_FLAG_CONFIG = 0x01
WS_FLAG_KEYFRAME = 0x02

# scrcpy v3.3.4 ControlMessage types (verified against ControlMessage.java)
TYPE_INJECT_KEYCODE = 0
TYPE_INJECT_TEXT = 1
TYPE_INJECT_TOUCH_EVENT = 2
TYPE_INJECT_SCROLL_EVENT = 3
TYPE_BACK_OR_SCREEN_ON = 4
TYPE_EXPAND_NOTIFICATION_PANEL = 5
TYPE_EXPAND_SETTINGS_PANEL = 6
TYPE_COLLAPSE_PANELS = 7
TYPE_GET_CLIPBOARD = 8
TYPE_SET_CLIPBOARD = 9
TYPE_SET_DISPLAY_POWER = 10
TYPE_ROTATE_DEVICE = 11
TYPE_RESET_VIDEO = 17

# scrcpy v3.3.4 DeviceMessage types (verified against DeviceMessageWriter.java)
DEVICE_MSG_CLIPBOARD = 0
DEVICE_MSG_ACK_CLIPBOARD = 1
DEVICE_MSG_UHID_OUTPUT = 2

ACTION_DOWN = 0
ACTION_UP = 1
ACTION_MOVE = 2

POINTER_ID_GENERIC_FINGER = -2
INJECT_TEXT_MAX_BYTES = 300
CLIPBOARD_TEXT_MAX_BYTES = (1 << 18) - 14  # 256 KiB - 14B header

# Quality presets: max_size caps the LONG edge (aligned to 8px by scrcpy-server)
QUALITY_PRESETS: dict[str, tuple[int, int]] = {
    "720": (720, 4_000_000),
    "1080": (1080, 8_000_000),
    "native": (0, 8_000_000),
}
ALLOWED_MAX_FPS = (30, 60)

SIMPLE_ACTION_MAP = {
    "expand_notifications": TYPE_EXPAND_NOTIFICATION_PANEL,
    "expand_settings": TYPE_EXPAND_SETTINGS_PANEL,
    "collapse_panels": TYPE_COLLAPSE_PANELS,
    "rotate": TYPE_ROTATE_DEVICE,
    "reset_video": TYPE_RESET_VIDEO,
}


class ScrcpyError(Exception):
    """Raised when scrcpy setup, handshake, or runtime fails."""


class WebSocketError(Exception):
    """Base error for RFC 6455 WebSocket transport."""


class WebSocketCloseError(WebSocketError):
    """Raised when a peer violates RFC 6455 or exceeds limits and we send Close."""

    def __init__(self, code: int, reason: str = ""):
        super().__init__(reason or f"WebSocket closed with code {code}")
        self.code = code
        self.reason = reason


# ------------------------------------------------------- binary & helpers ----

def verify_server_binary(
    path: Path | str = DEFAULT_SERVER_PATH,
    expected_sha256: str = SCRCPY_SERVER_SHA256,
) -> Path:
    target = Path(path)
    if not target.is_file():
        raise ScrcpyError(f"内置 scrcpy-server 文件缺失：{target}")
    digest = hashlib.sha256()
    try:
        with target.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise ScrcpyError(f"无法读取 scrcpy-server：{exc}") from exc
    actual = digest.hexdigest().lower()
    if actual != expected_sha256.lower():
        raise ScrcpyError(
            f"scrcpy-server SHA-256 校验失败（期望 {expected_sha256[:12]}…，实际 {actual[:12]}…）"
        )
    return target


def parse_adb_forward_port(stdout: str) -> int:
    text = str(stdout or "").strip()
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ScrcpyError("adb forward tcp:0 未返回分配端口")
    try:
        port = int(lines[-1])
    except ValueError as exc:
        raise ScrcpyError(f"无法解析 adb 分配的端口：{lines[-1]}") from exc
    if not (1 <= port <= 65535):
        raise ScrcpyError(f"adb 分配的端口超出范围：{port}")
    return port


def normalize_quality(quality: str | None) -> str:
    value = str(quality or "1080").strip().lower()
    if value not in QUALITY_PRESETS:
        raise ScrcpyError(f"不支持的画质档位：{value}（可选 720 / 1080 / native）")
    return value


def normalize_max_fps(max_fps: int | str | None) -> int:
    if max_fps is None or max_fps == "":
        return 60
    if isinstance(max_fps, bool):
        raise ScrcpyError("帧率上限必须是 30 或 60")
    try:
        fps = int(max_fps)
    except (TypeError, ValueError) as exc:
        raise ScrcpyError("帧率上限必须是 30 或 60") from exc
    if fps not in ALLOWED_MAX_FPS:
        raise ScrcpyError(f"不支持的帧率上限：{fps}（可选 30 / 60）")
    return fps


def build_server_cmd(scid: int, quality: str = "1080", max_fps: int = 60) -> list[str]:
    """Build minimal non-default scrcpy v3.3.4 server args.

    Keep /proc/self/cmdline compact (<220 bytes): Samsung Android 12 libstagefright
    (ACodec::reconfigEncoder4OtherApps) copies cmdline into a fixed 256-byte stack buffer.
    Defaults already true/set in scrcpy v3.3.4: video=true, control=true, video_codec=h264,
    video_bit_rate=8000000, max_size=0, cleanup=true, power_on=true, send_*_meta=true.
    """
    q = normalize_quality(quality)
    fps = normalize_max_fps(max_fps)
    max_size, bitrate = QUALITY_PRESETS[q]
    if not (0 <= scid <= 0x7FFFFFFF):
        raise ScrcpyError("scid 超出 31 位无符号整数范围")
    cmd = [
        "shell",
        f"CLASSPATH={SCRCPY_REMOTE_PATH}",
        "app_process",
        "/",
        "com.genymobile.scrcpy.Server",
        SCRCPY_SERVER_VERSION,
        f"scid={scid:08x}",
        "log_level=warn",
        "audio=false",
        "tunnel_forward=true",
        "stay_awake=true",
        "clipboard_autosync=false",
        f"max_fps={fps}",
    ]
    if max_size > 0:
        cmd.append(f"max_size={max_size}")
    if bitrate != 8_000_000:
        cmd.append(f"video_bit_rate={bitrate}")
    return cmd


# --------------------------------------------------------- scrcpy protocol ----

def parse_device_meta(raw: bytes) -> str:
    if len(raw) != 64:
        raise ScrcpyError(f"设备元数据长度错误：{len(raw)}")
    return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace").strip()


def parse_video_header(raw: bytes) -> tuple[int, int, int]:
    if len(raw) != 12:
        raise ScrcpyError(f"视频流头部长度错误：{len(raw)}")
    codec_id, width, height = struct.unpack(">III", raw)
    if codec_id != CODEC_ID_H264:
        raise ScrcpyError(f"不支持的视频编码格式：0x{codec_id:08x}")
    if width <= 0 or height <= 0 or width > 16384 or height > 16384:
        raise ScrcpyError(f"无效的视频分辨率：{width}x{height}")
    return codec_id, width, height


def parse_frame_header(raw: bytes) -> tuple[bool, bool, int, int]:
    if len(raw) != 12:
        raise ScrcpyError(f"视频帧头部长度错误：{len(raw)}")
    pts_and_flags, packet_size = struct.unpack(">QI", raw)
    if packet_size > MAX_VIDEO_PACKET_BYTES:
        raise ScrcpyError(f"视频数据包过大：{packet_size}")
    is_config = bool(pts_and_flags & PACKET_FLAG_CONFIG)
    is_keyframe = bool(pts_and_flags & PACKET_FLAG_KEY_FRAME)
    pts_us = pts_and_flags & 0x3FFFFFFFFFFFFFFF
    return is_config, is_keyframe, pts_us, packet_size


def pack_ws_video_packet(is_config: bool, is_keyframe: bool, pts_us: int, payload: bytes) -> bytes:
    flags = (WS_FLAG_CONFIG if is_config else 0) | (WS_FLAG_KEYFRAME if is_keyframe else 0)
    return struct.pack(">BBQ", WS_VIDEO_TYPE, flags, max(0, int(pts_us))) + payload


def pack_inject_keycode(action: int, keycode: int, repeat: int = 0, meta_state: int = 0) -> bytes:
    if action not in (ACTION_DOWN, ACTION_UP):
        raise ValueError("invalid key action")
    return struct.pack(">BBiii", TYPE_INJECT_KEYCODE, action, int(keycode), int(repeat), int(meta_state))


def pack_inject_text(text: str) -> bytes:
    raw = str(text).encode("utf-8")
    if not raw:
        raise ValueError("text cannot be empty")
    if len(raw) > INJECT_TEXT_MAX_BYTES:
        raise ValueError(f"text exceeds {INJECT_TEXT_MAX_BYTES} bytes")
    return struct.pack(">BI", TYPE_INJECT_TEXT, len(raw)) + raw


def pack_inject_touch(
    action: int,
    x: int,
    y: int,
    width: int,
    height: int,
    pointer_id: int = POINTER_ID_GENERIC_FINGER,
    pressure: int | None = None,
    action_button: int = 0,
    buttons: int = 0,
) -> bytes:
    if action not in (ACTION_DOWN, ACTION_UP, ACTION_MOVE):
        raise ValueError("invalid touch action")
    w, h = int(width), int(height)
    if not (1 <= w <= 0xFFFF and 1 <= h <= 0xFFFF):
        raise ValueError("invalid screen dimensions")
    px = max(0, min(w - 1, int(round(x))))
    py = max(0, min(h - 1, int(round(y))))
    if pressure is None:
        p_val = 0 if action == ACTION_UP else 0xFFFF
    else:
        p_val = max(0, min(0xFFFF, int(pressure)))
    return struct.pack(
        ">BBqiiHHHii",
        TYPE_INJECT_TOUCH_EVENT,
        action,
        int(pointer_id),
        px,
        py,
        w,
        h,
        p_val,
        int(action_button),
        int(buttons),
    )


def _encode_scroll_fixed16(value: float) -> int:
    # scrcpy v3.3.4 ControlMessageReader decodes i16FixedPointToFloat(short) * 16 -> [-16, 16]
    clamped = max(-16.0, min(16.0, float(value)))
    scaled = int(round((clamped / 16.0) * 32768.0))
    return max(-32768, min(32767, scaled))


def pack_inject_scroll(
    x: int,
    y: int,
    width: int,
    height: int,
    h_scroll: float,
    v_scroll: float,
    buttons: int = 0,
) -> bytes:
    w, h = int(width), int(height)
    if not (1 <= w <= 0xFFFF and 1 <= h <= 0xFFFF):
        raise ValueError("invalid screen dimensions")
    px = max(0, min(w - 1, int(round(x))))
    py = max(0, min(h - 1, int(round(y))))
    hs = _encode_scroll_fixed16(h_scroll)
    vs = _encode_scroll_fixed16(v_scroll)
    return struct.pack(">BiiHHhhi", TYPE_INJECT_SCROLL_EVENT, px, py, w, h, hs, vs, int(buttons))


def pack_back_or_screen_on(action: int) -> bytes:
    if action not in (ACTION_DOWN, ACTION_UP):
        raise ValueError("invalid back action")
    return struct.pack(">BB", TYPE_BACK_OR_SCREEN_ON, action)


def pack_set_clipboard(sequence: int, text: str, paste: bool) -> bytes:
    raw = str(text).encode("utf-8")
    if len(raw) > CLIPBOARD_TEXT_MAX_BYTES:
        raise ValueError("clipboard text too large")
    return struct.pack(">BQBI", TYPE_SET_CLIPBOARD, int(sequence) & 0xFFFFFFFFFFFFFFFF, 1 if paste else 0, len(raw)) + raw


def pack_set_display_power(on: bool) -> bytes:
    return struct.pack(">BB", TYPE_SET_DISPLAY_POWER, 1 if on else 0)


def pack_simple_action(msg_type: int) -> bytes:
    return struct.pack(">B", int(msg_type) & 0xFF)


def encode_control_command(
    cmd: dict,
    seq_fn: Callable[[], int] | None = None,
) -> list[bytes]:
    if not isinstance(cmd, dict):
        raise ValueError("control command must be an object")
    kind = str(cmd.get("type") or "").strip().lower()

    if kind == "touch":
        act_map = {"down": ACTION_DOWN, "up": ACTION_UP, "move": ACTION_MOVE}
        act_name = str(cmd.get("action") or "").strip().lower()
        if act_name not in act_map:
            raise ValueError(f"invalid touch action: {act_name}")
        return [
            pack_inject_touch(
                act_map[act_name],
                cmd.get("x", 0),
                cmd.get("y", 0),
                cmd.get("width", 0),
                cmd.get("height", 0),
            )
        ]

    if kind == "scroll":
        return [
            pack_inject_scroll(
                cmd.get("x", 0),
                cmd.get("y", 0),
                cmd.get("width", 0),
                cmd.get("height", 0),
                float(cmd.get("dx", 0.0)),
                float(cmd.get("dy", 0.0)),
            )
        ]

    if kind == "key":
        keycode = int(cmd.get("keycode"))
        if not (0 <= keycode <= 1024):
            raise ValueError("keycode out of range")
        meta = int(cmd.get("meta", 0))
        act_name = str(cmd.get("action") or "tap").strip().lower()
        if act_name == "tap":
            return [
                pack_inject_keycode(ACTION_DOWN, keycode, 0, meta),
                pack_inject_keycode(ACTION_UP, keycode, 0, meta),
            ]
        if act_name == "down":
            return [pack_inject_keycode(ACTION_DOWN, keycode, int(cmd.get("repeat", 0)), meta)]
        if act_name == "up":
            return [pack_inject_keycode(ACTION_UP, keycode, 0, meta)]
        raise ValueError(f"invalid key action: {act_name}")

    if kind == "text":
        text = str(cmd.get("text") or "")
        if not text:
            raise ValueError("text cannot be empty")
        return [pack_inject_text(text)]

    if kind == "clipboard":
        text = str(cmd.get("text") or "")
        if not text:
            raise ValueError("clipboard text cannot be empty")
        paste = bool(cmd.get("paste", True))
        seq = int(seq_fn()) if seq_fn else int(time.time_ns() & 0xFFFFFFFFFFFFFFFF)
        return [pack_set_clipboard(seq, text, paste=paste)]

    if kind == "display_power":
        return [pack_set_display_power(bool(cmd.get("on", True)))]

    if kind == "action":
        name = str(cmd.get("name") or "").strip().lower()
        if name == "back_or_screen_on":
            return [pack_back_or_screen_on(ACTION_DOWN), pack_back_or_screen_on(ACTION_UP)]
        if name in SIMPLE_ACTION_MAP:
            return [pack_simple_action(SIMPLE_ACTION_MAP[name])]
        raise ValueError(f"unknown action: {name}")

    raise ValueError(f"unknown control command type: {kind}")


def drain_device_message(read_exact: Callable[[int], bytes]) -> tuple[int, bytes | int]:
    msg_type = read_exact(1)[0]
    if msg_type == DEVICE_MSG_CLIPBOARD:
        length = struct.unpack(">I", read_exact(4))[0]
        if length > (1 << 20):
            raise ScrcpyError(f"设备剪贴板消息过大：{length}")
        return msg_type, read_exact(length) if length else b""
    if msg_type == DEVICE_MSG_ACK_CLIPBOARD:
        seq = struct.unpack(">Q", read_exact(8))[0]
        return msg_type, seq
    if msg_type == DEVICE_MSG_UHID_OUTPUT:
        _uhid_id, size = struct.unpack(">HH", read_exact(4))
        return msg_type, read_exact(size) if size else b""
    raise ScrcpyError(f"未知的设备回传消息类型：{msg_type}")


# --------------------------------------------------------- RFC 6455 WS ----

def ws_accept_key(sec_key: str) -> str:
    digest = hashlib.sha1((sec_key.strip() + WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    if n <= 0:
        return b""
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        count = sock.recv_into(view[received:], n - received)
        if count <= 0:
            raise EOFError("socket closed")
        received += count
    return bytes(buf)


def _unmask_payload(data: bytes, mask_key: bytes) -> bytes:
    if not data:
        return b""
    out = bytearray(data)
    m0, m1, m2, m3 = mask_key[0], mask_key[1], mask_key[2], mask_key[3]
    for i in range(0, len(out), 4):
        out[i] ^= m0
    for i in range(1, len(out), 4):
        out[i] ^= m1
    for i in range(2, len(out), 4):
        out[i] ^= m2
    for i in range(3, len(out), 4):
        out[i] ^= m3
    return bytes(out)


class WebSocketConn:
    """Minimal, RFC 6455 §5.4 compliant server-side WebSocket connection."""

    def __init__(self, sock: socket.socket, max_message_bytes: int = WS_MAX_MESSAGE_BYTES):
        self.sock = sock
        self.max_message_bytes = max(1, int(max_message_bytes))
        self._write_lock = threading.Lock()
        self._closed = False
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    @property
    def closed(self) -> bool:
        return self._closed

    def _send_frame(self, opcode: int, payload: bytes = b""):
        first = 0x80 | (opcode & 0x0F)
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", first, length)
        elif length < 65536:
            header = struct.pack("!BBH", first, 126, length)
        else:
            header = struct.pack("!BBQ", first, 127, length)
        with self._write_lock:
            if self._closed:
                return
            self.sock.sendall(header + payload)

    def send_text(self, text: str):
        self._send_frame(0x1, text.encode("utf-8"))

    def send_binary(self, data: bytes):
        self._send_frame(0x2, data)

    def send_pong(self, payload: bytes = b""):
        self._send_frame(0xA, payload[:125])

    def send_close(self, code: int = 1000, reason: str = ""):
        payload = struct.pack("!H", int(code) & 0xFFFF) + reason.encode("utf-8")[:120]
        with self._write_lock:
            if self._closed:
                return
            self._closed = True
            header = struct.pack("!BB", 0x88, len(payload))
            try:
                self.sock.sendall(header + payload)
            except OSError:
                pass

    def close(self):
        self._closed = True
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def _fail_protocol(self, code: int, reason: str):
        self.send_close(code, reason)
        raise WebSocketCloseError(code, reason)

    def recv_message(self) -> tuple[str, str | bytes] | None:
        """Read next complete message, supporting RFC 6455 §5.4 fragmentation and interleaved control frames."""
        frag_opcode: int | None = None
        frag_chunks: list[bytes] = []
        frag_total = 0

        while True:
            try:
                b1, b2 = _recv_exact(self.sock, 2)
            except (EOFError, OSError):
                return None

            fin = bool(b1 & 0x80)
            rsv = b1 & 0x70
            opcode = b1 & 0x0F
            masked = bool(b2 & 0x80)
            length = b2 & 0x7F

            if rsv != 0:
                self._fail_protocol(1002, "non-zero RSV bits")
            if not masked:
                self._fail_protocol(1002, "client frame must be masked")

            try:
                if length == 126:
                    length = struct.unpack("!H", _recv_exact(self.sock, 2))[0]
                elif length == 127:
                    length = struct.unpack("!Q", _recv_exact(self.sock, 8))[0]
                    if length & (1 << 63):
                        self._fail_protocol(1002, "invalid 64-bit length")
            except (EOFError, OSError):
                return None

            # Control frames (0x8..0xF) may be interleaved mid-fragmentation (RFC 6455 §5.4)
            if opcode >= 0x8:
                if not fin or length > 125 or opcode not in (0x8, 0x9, 0xA):
                    self._fail_protocol(1002, "invalid control frame")
                try:
                    mask_key = _recv_exact(self.sock, 4)
                    raw_payload = _recv_exact(self.sock, length)
                except (EOFError, OSError):
                    return None
                payload = _unmask_payload(raw_payload, mask_key)
                if opcode == 0x9:
                    try:
                        self.send_pong(payload)
                    except OSError:
                        return None
                    continue
                if opcode == 0xA:
                    continue
                if opcode == 0x8:
                    close_code = 1000
                    if len(payload) >= 2:
                        close_code = struct.unpack("!H", payload[:2])[0]
                    self.send_close(close_code)
                    return None

            # Data frames (0x0 continuation, 0x1 text, 0x2 binary)
            if opcode == 0x0:
                if frag_opcode is None:
                    self._fail_protocol(1002, "unexpected continuation frame")
            elif opcode in (0x1, 0x2):
                if frag_opcode is not None:
                    self._fail_protocol(1002, "interleaved data frame during fragmentation")
            else:
                self._fail_protocol(1002, f"unsupported opcode 0x{opcode:x}")

            if frag_total + length > self.max_message_bytes:
                self._fail_protocol(1009, "message too large")

            try:
                mask_key = _recv_exact(self.sock, 4)
                raw_payload = _recv_exact(self.sock, length)
            except (EOFError, OSError):
                return None
            payload = _unmask_payload(raw_payload, mask_key)

            frag_chunks.append(payload)
            frag_total += len(payload)
            if not fin:
                if frag_opcode is None:
                    frag_opcode = opcode
                continue

            final_opcode = frag_opcode if frag_opcode is not None else opcode
            full_bytes = b"".join(frag_chunks)
            if final_opcode == 0x1:
                try:
                    return ("text", full_bytes.decode("utf-8"))
                except UnicodeDecodeError:
                    self._fail_protocol(1007, "invalid utf-8 payload")
            return ("binary", full_bytes)


# ------------------------------------------------------- session & manager ----

class _WsClient:
    """Thread-safe bounded-queue wrapper for a connected WebSocket viewer."""

    MAX_VIDEO_QUEUE = 24

    def __init__(self, ws: WebSocketConn, on_need_keyframe: Callable[[], None]):
        self.ws = ws
        self._on_need_keyframe = on_need_keyframe
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._queue: collections.deque = collections.deque()
        self._video_count = 0
        self._paused = False
        self._awaiting_keyframe = False
        self._closed = False
        self._sender = threading.Thread(target=self._send_loop, daemon=True)
        self._sender.start()

    @property
    def paused(self) -> bool:
        with self._lock:
            return self._paused

    def set_paused(self, paused: bool) -> bool:
        """Update paused state; returns True when transitioning paused -> resumed."""
        with self._lock:
            was_paused = self._paused
            self._paused = bool(paused)
            if self._paused:
                # Drop queued video packets while paused; preserve status/text messages
                kept = collections.deque(item for item in self._queue if item[0] == "text")
                self._queue = kept
                self._video_count = 0
                self._awaiting_keyframe = True
            elif was_paused:
                self._awaiting_keyframe = True
            self._cond.notify()
            return was_paused and not self._paused

    def enqueue_text(self, text: str):
        with self._lock:
            if self._closed:
                return
            self._queue.append(("text", text))
            self._cond.notify()

    def enqueue_video(self, is_config: bool, is_keyframe: bool, packet: bytes):
        trigger_reset = False
        with self._lock:
            if self._closed or self._paused:
                return
            if self._awaiting_keyframe and not is_config and not is_keyframe:
                return
            if is_keyframe:
                self._awaiting_keyframe = False

            if self._video_count >= self.MAX_VIDEO_QUEUE:
                # Drop stale non-config video frames first
                new_q = collections.deque()
                vcount = 0
                for item in self._queue:
                    if item[0] == "text" or item[1]:  # keep text and config packets
                        new_q.append(item)
                        if item[0] == "video":
                            vcount += 1
                self._queue = new_q
                self._video_count = vcount
                if not is_config and not is_keyframe:
                    self._awaiting_keyframe = True
                    trigger_reset = True
                    self._cond.notify()
                    # Fall through outside lock to trigger reset
                else:
                    self._queue.append(("video", is_config, is_keyframe, packet))
                    self._video_count += 1
                    self._cond.notify()
            else:
                self._queue.append(("video", is_config, is_keyframe, packet))
                self._video_count += 1
                self._cond.notify()

        if trigger_reset:
            self._on_need_keyframe()

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._queue.clear()
            self._video_count = 0
            self._cond.notify_all()
        self.ws.close()

    def _send_loop(self):
        while True:
            with self._lock:
                while not self._queue and not self._closed:
                    self._cond.wait(timeout=1.0)
                if self._closed:
                    return
                item = self._queue.popleft()
                if item[0] == "video":
                    self._video_count = max(0, self._video_count - 1)
            try:
                if item[0] == "text":
                    self.ws.send_text(item[1])
                else:
                    self.ws.send_binary(item[3])
            except OSError:
                self.close()
                return


class ScrcpySession:
    """Manages one active scrcpy-server process, ADB forward, and video/control sockets."""

    def __init__(
        self,
        adb,
        serial: str,
        quality: str,
        max_fps: int,
        server_path: Path,
        popen_fn,
        socket_factory,
        handshake_timeout: float,
        on_video_packet: Callable[[bool, bool, bytes], None],
        on_terminated: Callable[["ScrcpySession", str], None],
    ):
        self.adb = adb
        self.serial = serial
        self.quality = normalize_quality(quality)
        self.max_fps = normalize_max_fps(max_fps)
        self.server_path = server_path
        self._popen_fn = popen_fn
        self._socket_factory = socket_factory
        self._handshake_timeout = float(handshake_timeout)
        self._on_video_packet = on_video_packet
        self._on_terminated = on_terminated

        self.scid = secrets.randbelow(0x7FFFFFFE) + 1
        self.local_port: int | None = None
        self.device_name = ""
        self.width = 0
        self.height = 0
        self.screen_off = False
        self.last_config_packet: bytes | None = None

        self._proc = None
        self._video_sock: socket.socket | None = None
        self._control_sock: socket.socket | None = None
        self._ctrl_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._closed = False
        self._stopping = False
        self._seq_counter = 1

    def next_sequence(self) -> int:
        with self._ctrl_lock:
            val = self._seq_counter
            self._seq_counter += 1
            return val

    def _read_proc_stderr(self) -> str:
        proc = self._proc
        if proc is None:
            return ""
        parts = []
        for stream in (getattr(proc, "stderr", None), getattr(proc, "stdout", None)):
            if stream is None:
                continue
            try:
                data = stream.read()
                if data:
                    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
                    parts.append(text.strip())
            except Exception:
                pass
        combined = "\n".join(p for p in parts if p).strip()
        if not combined:
            return ""
        lines = [ln.strip() for ln in combined.splitlines() if ln.strip()]
        return " | ".join(lines[-3:])[:300]

    def start(self, screen_off: bool = False):
        verified = verify_server_binary(self.server_path)
        adb_argv = self.adb.resolve()
        if not adb_argv:
            raise ScrcpyError("未找到 adb 可执行文件，请在「连接与设置」中配置 adb 路径")

        # 1. Push scrcpy-server jar
        code, _out, err = self.adb.run(["-s", self.serial, "push", str(verified), SCRCPY_REMOTE_PATH])
        if code != 0:
            raise ScrcpyError(f"推送 scrcpy-server 到手机失败：{err.strip() or f'exit {code}'}")

        # 2. Atomically allocate a free port via `adb forward tcp:0`
        socket_name = f"localabstract:scrcpy_{self.scid:08x}"
        code, out, err = self.adb.run(["-s", self.serial, "forward", "tcp:0", socket_name])
        if code != 0:
            raise ScrcpyError(f"建立临时 ADB 投屏转发失败：{err.strip() or f'exit {code}'}")
        self.local_port = parse_adb_forward_port(out)

        try:
            # 3. Launch scrcpy-server on Android device
            full_cmd = list(adb_argv) + ["-s", self.serial] + build_server_cmd(
                self.scid, quality=self.quality, max_fps=self.max_fps
            )
            try:
                self._proc = self._popen_fn(
                    full_cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except OSError as exc:
                raise ScrcpyError(f"启动手机投屏进程失败：{exc}") from exc

            # 4. Wait for video socket dummy byte (0x00), checking early process exit
            deadline = time.monotonic() + self._handshake_timeout
            video_sock = None
            while time.monotonic() < deadline:
                exit_code = self._proc.poll()
                if exit_code is not None:
                    detail = self._read_proc_stderr()
                    raise ScrcpyError(
                        f"手机端 scrcpy-server 提前退出（code {exit_code}）"
                        + (f"：{detail}" if detail else "")
                    )
                cand = None
                try:
                    cand = self._socket_factory(("127.0.0.1", self.local_port), timeout=0.4)
                    cand.settimeout(0.4)
                    dummy = cand.recv(1)
                    if dummy == b"\x00":
                        video_sock = cand
                        break
                    cand.close()
                except OSError:
                    if cand is not None:
                        try:
                            cand.close()
                        except OSError:
                            pass
                time.sleep(0.05)

            if video_sock is None:
                detail = self._read_proc_stderr() if self._proc.poll() is not None else ""
                raise ScrcpyError(
                    "连接手机投屏超时，请确认手机已解锁并允许 USB 调试"
                    + (f"（{detail}）" if detail else "")
                )

            self._video_sock = video_sock
            self._video_sock.settimeout(5.0)
            try:
                self._video_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

            # 5. Connect control socket immediately
            control_sock = None
            ctrl_deadline = time.monotonic() + 2.0
            while time.monotonic() < ctrl_deadline:
                try:
                    control_sock = self._socket_factory(("127.0.0.1", self.local_port), timeout=1.0)
                    break
                except OSError:
                    time.sleep(0.03)
            if control_sock is None:
                raise ScrcpyError("建立手机控制通道失败")
            self._control_sock = control_sock
            self._control_sock.settimeout(None)
            try:
                self._control_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

            # 6. Read device metadata (64B) + video codec header (12B)
            self.device_name = parse_device_meta(_recv_exact(self._video_sock, 64))
            _codec_id, self.width, self.height = parse_video_header(_recv_exact(self._video_sock, 12))
            self._video_sock.settimeout(None)

            # 7. Start video reader and control drain threads
            threading.Thread(target=self._video_reader_loop, daemon=True).start()
            threading.Thread(target=self._control_drain_loop, daemon=True).start()

            if screen_off:
                self.set_display_power(False)
        except Exception:
            self.close()
            raise

    def send_control_packets(self, packets: list[bytes]):
        with self._ctrl_lock:
            sock = self._control_sock
            if sock is None or self._closed:
                raise ScrcpyError("投屏会话未运行")
            payload = b"".join(packets)
            try:
                sock.sendall(payload)
            except OSError as exc:
                raise ScrcpyError(f"发送控制指令失败：{exc}") from exc

    def set_display_power(self, on: bool):
        self.send_control_packets([pack_set_display_power(on)])
        with self._state_lock:
            self.screen_off = not bool(on)

    def reset_video(self):
        try:
            self.send_control_packets([pack_simple_action(TYPE_RESET_VIDEO)])
        except ScrcpyError:
            pass

    def _video_reader_loop(self):
        error_msg = ""
        try:
            sock = self._video_sock
            while sock is not None and not self._closed:
                hdr = _recv_exact(sock, 12)
                is_config, is_keyframe, pts_us, size = parse_frame_header(hdr)
                payload = _recv_exact(sock, size) if size else b""
                ws_pkt = pack_ws_video_packet(is_config, is_keyframe, pts_us, payload)
                if is_config:
                    with self._state_lock:
                        self.last_config_packet = ws_pkt
                self._on_video_packet(is_config, is_keyframe, ws_pkt)
        except (EOFError, OSError, ScrcpyError) as exc:
            if not self._stopping:
                detail = self._read_proc_stderr()
                error_msg = detail or (str(exc) if isinstance(exc, ScrcpyError) else "手机投屏连接已断开")
        finally:
            was_stopping = self._stopping
            self.close()
            if not was_stopping:
                self._on_terminated(self, error_msg or "手机投屏连接已断开")

    def _control_drain_loop(self):
        sock = self._control_sock
        if sock is None:
            return
        try:
            while not self._closed:
                drain_device_message(lambda n: _recv_exact(sock, n))
        except (EOFError, OSError, ScrcpyError):
            pass

    def close(self):
        with self._state_lock:
            if self._closed:
                return
            self._stopping = True
            should_restore_power = self.screen_off
            self.screen_off = False
            ctrl_sock = self._control_sock
            vid_sock = self._video_sock
            proc = self._proc
            port = self.local_port

        # Best-effort restore physical screen before tearing down control socket
        if should_restore_power and ctrl_sock is not None:
            try:
                with self._ctrl_lock:
                    ctrl_sock.sendall(pack_set_display_power(True))
                time.sleep(0.04)
            except OSError:
                pass

        with self._state_lock:
            self._closed = True
            self._control_sock = None
            self._video_sock = None
            self._proc = None
            self.local_port = None

        for sock in (vid_sock, ctrl_sock):
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=1.0)
                    except Exception:
                        proc.kill()
            except Exception:
                pass
            for stream in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass

        # Remove ONLY our allocated tcp:<port> forward; preserve existing proxy forwards
        if port is not None:
            try:
                self.adb.run(["-s", self.serial, "forward", "--remove", f"tcp:{port}"])
            except Exception:
                pass


class PhoneMirrorManager:
    """Single-session coordinator shared across HTTP API and WebSocket viewers."""

    def __init__(
        self,
        adb_factory: Callable[[dict], object],
        server_path: Path | str = DEFAULT_SERVER_PATH,
        popen_fn=subprocess.Popen,
        socket_factory=socket.create_connection,
        handshake_timeout: float = 8.0,
    ):
        self._adb_factory = adb_factory
        self._server_path = Path(server_path)
        self._popen_fn = popen_fn
        self._socket_factory = socket_factory
        self._handshake_timeout = float(handshake_timeout)

        self._lock = threading.RLock()
        self._session: ScrcpySession | None = None
        self._starting = False
        self._quality = "1080"
        self._max_fps = 60
        self._last_error = ""
        self._clients: set[_WsClient] = set()

    def _server_ready(self) -> bool:
        try:
            verify_server_binary(self._server_path)
            return True
        except ScrcpyError:
            return False

    def status(self) -> dict:
        with self._lock:
            sess = self._session
            return {
                "ok": True,
                "running": sess is not None,
                "starting": self._starting,
                "serial": sess.serial if sess else "",
                "device_name": sess.device_name if sess else "",
                "width": sess.width if sess else 0,
                "height": sess.height if sess else 0,
                "screen_off": sess.screen_off if sess else False,
                "quality": sess.quality if sess else self._quality,
                "max_fps": sess.max_fps if sess else self._max_fps,
                "clients": len(self._clients),
                "server_ready": self._server_ready(),
                "error": self._last_error,
            }

    def _broadcast_status(self):
        payload = json.dumps({"type": "status", **self.status()}, ensure_ascii=False)
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            client.enqueue_text(payload)

    def _on_video_packet(self, is_config: bool, is_keyframe: bool, packet: bytes):
        with self._lock:
            clients = list(self._clients)
        for client in clients:
            client.enqueue_video(is_config, is_keyframe, packet)

    def _on_session_terminated(self, session: ScrcpySession, reason: str):
        with self._lock:
            if self._session is not session:
                return
            self._session = None
            self._last_error = reason
        self._broadcast_status()

    def _trigger_reset_video(self):
        with self._lock:
            sess = self._session
        if sess is not None:
            sess.reset_video()

    def start(
        self,
        cfg: dict,
        serial: str = "",
        quality: str | None = None,
        max_fps: int | str | None = None,
        screen_off: bool = False,
    ) -> dict:
        q = normalize_quality(quality if quality is not None else self._quality)
        fps = normalize_max_fps(max_fps if max_fps is not None else self._max_fps)

        adb = self._adb_factory(cfg)
        try:
            device = adb.online_device(serial=str(serial or "").strip())
        except Exception as exc:
            raise ScrcpyError(str(exc)) from exc
        if device is None:
            raise ScrcpyError("未检测到在线 Android 设备，请先连接 USB 并开启调试")
        target_serial = device["serial"]

        old_session = None
        with self._lock:
            if self._starting:
                raise ScrcpyError("正在连接手机屏幕，请稍候")
            cur = self._session
            if cur is not None and cur.serial == target_serial and cur.quality == q and cur.max_fps == fps:
                if cur.screen_off != bool(screen_off):
                    cur.set_display_power(not bool(screen_off))
                    self._broadcast_status()
                return self.status()
            old_session = cur
            self._session = None
            self._starting = True
            self._quality = q
            self._max_fps = fps
            self._last_error = ""

        if old_session is not None:
            old_session.close()

        session = ScrcpySession(
            adb=adb,
            serial=target_serial,
            quality=q,
            max_fps=fps,
            server_path=self._server_path,
            popen_fn=self._popen_fn,
            socket_factory=self._socket_factory,
            handshake_timeout=self._handshake_timeout,
            on_video_packet=self._on_video_packet,
            on_terminated=self._on_session_terminated,
        )
        try:
            session.start(screen_off=bool(screen_off))
        except Exception as exc:
            with self._lock:
                self._starting = False
                self._last_error = str(exc)
            self._broadcast_status()
            raise

        with self._lock:
            self._session = session
            self._starting = False
            self._last_error = ""
            clients = list(self._clients)

        self._broadcast_status()
        if clients:
            session.reset_video()
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            sess = self._session
            self._session = None
            self._last_error = ""
        if sess is not None:
            sess.close()
        self._broadcast_status()
        return self.status()

    def shutdown(self):
        with self._lock:
            sess = self._session
            self._session = None
            clients = list(self._clients)
            self._clients.clear()
        for client in clients:
            client.close()
        if sess is not None:
            sess.close()

    def handle_websocket(self, ws: WebSocketConn):
        client = _WsClient(ws, on_need_keyframe=self._trigger_reset_video)
        with self._lock:
            self._clients.add(client)
            sess = self._session
            cached_config = sess.last_config_packet if sess is not None else None

        try:
            client.enqueue_text(json.dumps({"type": "status", **self.status()}, ensure_ascii=False))
            if sess is not None:
                if cached_config:
                    client.enqueue_video(True, False, cached_config)
                sess.reset_video()

            while True:
                msg = ws.recv_message()
                if msg is None:
                    break
                kind, payload = msg
                if kind != "text":
                    continue
                try:
                    cmd = json.loads(payload)
                except ValueError:
                    client.enqueue_text(json.dumps({"type": "error", "message": "控制指令 JSON 格式错误"}, ensure_ascii=False))
                    continue
                if not isinstance(cmd, dict):
                    client.enqueue_text(json.dumps({"type": "error", "message": "控制指令必须是 JSON 对象"}, ensure_ascii=False))
                    continue

                cmd_type = str(cmd.get("type") or "").strip().lower()
                if cmd_type == "pause":
                    resumed = client.set_paused(bool(cmd.get("paused", False)))
                    if resumed:
                        with self._lock:
                            cur = self._session
                            cfg_pkt = cur.last_config_packet if cur is not None else None
                        if cur is not None:
                            if cfg_pkt:
                                client.enqueue_video(True, False, cfg_pkt)
                            cur.reset_video()
                    continue

                with self._lock:
                    cur = self._session
                if cur is None:
                    client.enqueue_text(json.dumps({"type": "error", "message": "当前未连接手机投屏"}, ensure_ascii=False))
                    continue

                if cmd_type == "display_power":
                    try:
                        cur.set_display_power(bool(cmd.get("on", True)))
                        self._broadcast_status()
                    except ScrcpyError as exc:
                        client.enqueue_text(json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False))
                    continue

                try:
                    packets = encode_control_command(cmd, seq_fn=cur.next_sequence)
                    cur.send_control_packets(packets)
                except (ValueError, ScrcpyError) as exc:
                    client.enqueue_text(json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False))
        except WebSocketError:
            pass
        finally:
            with self._lock:
                self._clients.discard(client)
            client.close()
