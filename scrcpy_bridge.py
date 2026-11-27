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
import re
import secrets
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable
from urllib.parse import quote as _url_quote

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
TYPE_START_APP = 16
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

VD_PRESETS: dict[str, dict] = {
    "phone": {"new_display": "480x856/213", "win_w": 510, "win_h": 947, "label": "竖屏小窗 480×856"},
    "phone_hd": {"new_display": "720x1280/320", "win_w": 500, "win_h": 930, "label": "竖屏高清 720×1280"},
    "tablet": {"new_display": "960x600/200", "win_w": 990, "win_h": 691, "label": "横屏适中 960×600"},
    "tablet_hd": {"new_display": "1280x720/240", "win_w": 1310, "win_h": 811, "label": "横屏高清 1280×720"},
    "tablet_fhd": {"new_display": "1600x900/280", "win_w": 1630, "win_h": 991, "label": "横屏大屏 1600×900"},
}
ALLOWED_IME_POLICIES = ("local", "hide", "fallback")
_NEW_DISPLAY_RE = re.compile(r"^(\d{3,4})x(\d{3,4})(?:/(\d{2,3}))?$")
_APP_LINE_RE = re.compile(r"^\s*([*-])\s+(.+?)\s+([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+)\s*$")
_APPS_CACHE_TTL = 60.0
_apps_cache_lock = threading.Lock()
_apps_cache: dict[str, tuple[float, list[dict]]] = {}

SIMPLE_ACTION_MAP = {
    "expand_notifications": TYPE_EXPAND_NOTIFICATION_PANEL,
    "expand_settings": TYPE_EXPAND_SETTINGS_PANEL,
    "collapse_panels": TYPE_COLLAPSE_PANELS,
    "rotate": TYPE_ROTATE_DEVICE,
    "reset_video": TYPE_RESET_VIDEO,
}

KNOWN_PROXY_APPS: tuple[tuple[str, str], ...] = (
    ("com.follow.clash", "FlClash"),
    ("com.github.metacubex.clash.meta", "Clash Meta"),
    ("com.github.kr328.clash.foss", "Clash for Android"),
    ("com.github.kr328.clash", "Clash for Android"),
    ("io.nekohasekai.sfa", "sing-box"),
    ("moe.nb4a", "NekoBox"),
    ("com.v2ray.ang", "v2rayNG"),
    ("com.getsurfboard", "Surfboard"),
    ("com.karing.app", "Karing"),
    ("app.hiddify.com", "Hiddify"),
)

_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+$")
_FILENAME_BAD_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f;`$()&!]')


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


def normalize_vd_preset(preset: str | None) -> str:
    value = str(preset or "phone").strip().lower()
    if value not in VD_PRESETS:
        raise ScrcpyError(
            f"不支持的虚拟屏规格：{value}（可选 phone / phone_hd / tablet / tablet_hd / tablet_fhd）"
        )
    return value


def normalize_ime_policy(policy: str | None, default: str = "local") -> str:
    value = str(policy or default).strip().lower()
    if value not in ALLOWED_IME_POLICIES:
        raise ScrcpyError(f"不支持的虚拟屏输入法策略：{value}（可选 local / hide / fallback）")
    return value


def validate_new_display(spec: str) -> str:
    raw = str(spec or "").strip()
    m = _NEW_DISPLAY_RE.match(raw)
    if not m:
        raise ScrcpyError(f"无效的虚拟屏幕尺寸参数：{raw}")
    w = int(m.group(1))
    h = int(m.group(2))
    dpi = int(m.group(3)) if m.group(3) else 0
    if not (320 <= w <= 2560 and 320 <= h <= 2560):
        raise ScrcpyError(f"虚拟屏幕宽高需在 320~2560 之间：{w}x{h}")
    w = max(320, min(2560, (w // 8) * 8))
    h = max(320, min(2560, (h // 8) * 8))
    if dpi:
        dpi = max(120, min(560, dpi))
        return f"{w}x{h}/{dpi}"
    return f"{w}x{h}"


def session_id_for_package(package: str) -> str:
    pkg = str(package or "").strip()
    if not _PACKAGE_RE.match(pkg):
        raise ScrcpyError(f"无效的 Android 应用包名：{pkg}")
    return "app_" + re.sub(r"[^A-Za-z0-9_]", "_", pkg)


def build_server_cmd(
    scid: int,
    quality: str = "1080",
    max_fps: int = 60,
    *,
    remote_path: str = SCRCPY_REMOTE_PATH,
    new_display: str = "",
    start_app: str = "",
    ime_policy: str = "local",
) -> list[str]:
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

    vd = str(new_display or "").strip()
    pkg = str(start_app or "").strip()
    if vd and not _NEW_DISPLAY_RE.match(vd):
        raise ScrcpyError(f"无效的虚拟屏幕尺寸参数：{vd}")
    if pkg and not _PACKAGE_RE.match(pkg):
        raise ScrcpyError(f"无效的 Android 应用包名：{pkg}")

    cmd = [
        "shell",
        f"CLASSPATH={remote_path}",
        "app_process",
        "/",
        "com.genymobile.scrcpy.Server",
        SCRCPY_SERVER_VERSION,
        f"scid={scid:08x}",
        "log_level=warn",
        "audio=false",
        "tunnel_forward=true",
        f"max_fps={fps}",
    ]
    if vd:
        pol = normalize_ime_policy(ime_policy, default="local")
        cmd.append(f"new_display={vd}")
        cmd.append(f"display_ime_policy={pol}")
    else:
        cmd.append("stay_awake=true")
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


def pack_get_clipboard(copy_key: int = 0) -> bytes:
    ck = int(copy_key)
    if ck not in (0, 1, 2):
        raise ValueError("invalid copy_key")
    return struct.pack(">BB", TYPE_GET_CLIPBOARD, ck)


def pack_set_clipboard(sequence: int, text: str, paste: bool) -> bytes:
    raw = str(text).encode("utf-8")
    if len(raw) > CLIPBOARD_TEXT_MAX_BYTES:
        raise ValueError("clipboard text too large")
    return struct.pack(">BQBI", TYPE_SET_CLIPBOARD, int(sequence) & 0xFFFFFFFFFFFFFFFF, 1 if paste else 0, len(raw)) + raw


def pack_set_display_power(on: bool) -> bytes:
    return struct.pack(">BB", TYPE_SET_DISPLAY_POWER, 1 if on else 0)


def pack_start_app(app_spec: str) -> bytes:
    """Encode scrcpy v3.3.4 TYPE_START_APP (16): 1B type + 1B length + UTF-8 app/package."""
    raw = str(app_spec or "").strip().encode("utf-8")
    if not raw or len(raw) > 255:
        raise ValueError("start_app name must be 1..255 UTF-8 bytes")
    return struct.pack(">BB", TYPE_START_APP, len(raw)) + raw


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
        raw_pid = cmd.get("pointer_id", POINTER_ID_GENERIC_FINGER)
        if isinstance(raw_pid, bool):
            raise ValueError("invalid pointer_id")
        pointer_id = int(raw_pid)
        return [
            pack_inject_touch(
                act_map[act_name],
                cmd.get("x", 0),
                cmd.get("y", 0),
                cmd.get("width", 0),
                cmd.get("height", 0),
                pointer_id=pointer_id,
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

    if kind == "get_clipboard":
        return [pack_get_clipboard(int(cmd.get("copy_key", 0)))]

    if kind == "clipboard":
        text = str(cmd.get("text") or "")
        if not text:
            raise ValueError("clipboard text cannot be empty")
        paste = bool(cmd.get("paste", True))
        seq = int(seq_fn()) if seq_fn else int(time.time_ns() & 0xFFFFFFFFFFFFFFFF)
        return [pack_set_clipboard(seq, text, paste=paste)]

    if kind == "display_power":
        return [pack_set_display_power(bool(cmd.get("on", True)))]

    if kind == "start_app":
        pkg = str(cmd.get("package") or cmd.get("name") or "").strip()
        if not pkg:
            raise ValueError("start_app package cannot be empty")
        return [pack_start_app(pkg)]

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
        on_device_clipboard: Callable[[str], None] | None = None,
        on_ack_clipboard: Callable[[int], None] | None = None,
        *,
        session_id: str = "main",
        new_display: str = "",
        start_app: str = "",
        app_name: str = "",
        preset: str = "",
        ime_policy: str = "local",
    ):
        self.adb = adb
        self.serial = serial
        self.session_id = str(session_id or "main")
        self.quality = normalize_quality(quality)
        self.max_fps = normalize_max_fps(max_fps)
        self.new_display = str(new_display or "").strip()
        self.start_app = str(start_app or "").strip()
        self.app_name = str(app_name or "").strip() or self.start_app
        self.preset = str(preset or "").strip()
        self.ime_policy = normalize_ime_policy(ime_policy, default="local") if self.new_display else ""
        self.server_path = server_path
        self._popen_fn = popen_fn
        self._socket_factory = socket_factory
        self._handshake_timeout = float(handshake_timeout)
        self._on_video_packet = on_video_packet
        self._on_terminated = on_terminated
        self._on_device_clipboard = on_device_clipboard
        self._on_ack_clipboard = on_ack_clipboard

        self.scid = secrets.randbelow(0x7FFFFFFE) + 1
        self.remote_path = f"/data/local/tmp/dbs_{self.scid:08x}.jar"
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

    @property
    def is_virtual(self) -> bool:
        return bool(self.new_display)

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

        # 1. Push scrcpy-server jar to an isolated per-session path (avoids cleanup races)
        code, _out, err = self.adb.run(["-s", self.serial, "push", str(verified), self.remote_path])
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
                self.scid,
                quality=self.quality,
                max_fps=self.max_fps,
                remote_path=self.remote_path,
                new_display=self.new_display,
                start_app=self.start_app,
                ime_policy=self.ime_policy or "local",
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

            if self.start_app:
                self.send_control_packets([pack_start_app(self.start_app)])

            if screen_off and not self.is_virtual:
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
                msg_type, payload = drain_device_message(lambda n: _recv_exact(sock, n))
                if msg_type == DEVICE_MSG_CLIPBOARD and isinstance(payload, bytes) and self._on_device_clipboard is not None:
                    text = payload.decode("utf-8", errors="replace")
                    if text:
                        try:
                            self._on_device_clipboard(text)
                        except Exception:
                            pass
                elif msg_type == DEVICE_MSG_ACK_CLIPBOARD and isinstance(payload, int) and self._on_ack_clipboard is not None:
                    try:
                        self._on_ack_clipboard(payload)
                    except Exception:
                        pass
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
        if should_restore_power and not self.is_virtual and ctrl_sock is not None:
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


class _SessionSlot:
    """State bucket for one mirror or virtual-display session."""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.session: ScrcpySession | None = None
        self.starting = False
        self.quality = "1080"
        self.max_fps = 60
        self.preset = ""
        self.ime_policy = "local"
        self.package = ""
        self.app_name = ""
        self.last_error = ""
        self.clients: set[_WsClient] = set()
        self.last_sent_clipboard: tuple[str, float] = ("", 0.0)
        self.last_device_clipboard = ""
        self.grace_timer: threading.Timer | None = None


class PhoneMirrorManager:
    """Multi-session coordinator for main phone mirror ('main') and virtual app windows."""

    def __init__(
        self,
        adb_factory: Callable[[dict], object],
        server_path: Path | str = DEFAULT_SERVER_PATH,
        popen_fn=subprocess.Popen,
        socket_factory=socket.create_connection,
        handshake_timeout: float = 8.0,
        virtual_idle_grace: float = 5.0,
    ):
        self._adb_factory = adb_factory
        self._server_path = Path(server_path)
        self._popen_fn = popen_fn
        self._socket_factory = socket_factory
        self._handshake_timeout = float(handshake_timeout)
        self._virtual_idle_grace = float(virtual_idle_grace)

        self._lock = threading.RLock()
        self._slots: dict[str, _SessionSlot] = {"main": _SessionSlot("main")}

    def _get_slot(self, session_id: str = "main", create: bool = True) -> _SessionSlot | None:
        sid = str(session_id or "main").strip() or "main"
        slot = self._slots.get(sid)
        if slot is None and create:
            slot = _SessionSlot(sid)
            self._slots[sid] = slot
        return slot

    def _cancel_grace(self, slot: _SessionSlot):
        t = slot.grace_timer
        slot.grace_timer = None
        if t is not None:
            try:
                t.cancel()
            except Exception:
                pass

    def _server_ready(self) -> bool:
        try:
            verify_server_binary(self._server_path)
            return True
        except ScrcpyError:
            return False

    def list_sessions(self) -> list[dict]:
        with self._lock:
            out = []
            for sid, slot in self._slots.items():
                sess = slot.session
                if sess is None and not slot.starting:
                    continue
                out.append({
                    "session_id": sid,
                    "running": sess is not None,
                    "starting": slot.starting,
                    "is_virtual": bool(sess.is_virtual) if sess is not None else (sid != "main"),
                    "serial": sess.serial if sess else "",
                    "device_name": sess.device_name if sess else "",
                    "package": sess.start_app if sess else slot.package,
                    "app_name": sess.app_name if sess else slot.app_name,
                    "preset": sess.preset if sess else slot.preset,
                    "width": sess.width if sess else 0,
                    "height": sess.height if sess else 0,
                    "clients": len(slot.clients),
                })
            return out

    def status(self, session_id: str = "main") -> dict:
        sid = str(session_id or "main").strip() or "main"
        with self._lock:
            slot = self._slots.get(sid)
            sess = slot.session if slot else None
            return {
                "ok": True,
                "session_id": sid,
                "is_virtual": bool(sess.is_virtual) if sess is not None else (sid != "main"),
                "package": sess.start_app if sess else (slot.package if slot else ""),
                "app_name": sess.app_name if sess else (slot.app_name if slot else ""),
                "preset": sess.preset if sess else (slot.preset if slot else ""),
                "ime_policy": sess.ime_policy if sess else (slot.ime_policy if slot else "local"),
                "running": sess is not None,
                "starting": slot.starting if slot else False,
                "serial": sess.serial if sess else "",
                "device_name": sess.device_name if sess else "",
                "width": sess.width if sess else 0,
                "height": sess.height if sess else 0,
                "screen_off": sess.screen_off if sess else False,
                "quality": sess.quality if sess else (slot.quality if slot else "1080"),
                "max_fps": sess.max_fps if sess else (slot.max_fps if slot else 60),
                "clients": len(slot.clients) if slot else 0,
                "server_ready": self._server_ready(),
                "error": slot.last_error if slot else "",
                "sessions": self.list_sessions(),
            }

    def _broadcast_status(self, session_id: str = "main", notify_main: bool = False):
        sid = str(session_id or "main").strip() or "main"
        payload = json.dumps({"type": "status", **self.status(sid)}, ensure_ascii=False)
        with self._lock:
            slot = self._slots.get(sid)
            clients = list(slot.clients) if slot else []
        for client in clients:
            client.enqueue_text(payload)
        if notify_main and sid != "main":
            self._broadcast_status("main", notify_main=False)

    def _on_video_packet(self, session_id: str, is_config: bool, is_keyframe: bool, packet: bytes):
        with self._lock:
            slot = self._slots.get(session_id)
            clients = list(slot.clients) if slot else []
        for client in clients:
            client.enqueue_video(is_config, is_keyframe, packet)

    def _on_device_clipboard(self, session_id: str, text: str):
        now = time.monotonic()
        with self._lock:
            slot = self._slots.get(session_id)
            if slot is None:
                return
            sent_text, sent_at = slot.last_sent_clipboard
            if sent_text and text == sent_text and (now - sent_at) < 2.5:
                return
            slot.last_device_clipboard = text
            clients = list(slot.clients)
        payload = json.dumps(
            {"type": "clipboard", "text": text, "time": time.strftime("%H:%M:%S")},
            ensure_ascii=False,
        )
        for client in clients:
            client.enqueue_text(payload)

    def _on_ack_clipboard(self, session_id: str, seq: int):
        with self._lock:
            slot = self._slots.get(session_id)
            clients = list(slot.clients) if slot else []
        if not clients:
            return
        payload = json.dumps({"type": "ack_clipboard", "seq": int(seq)}, ensure_ascii=False)
        for client in clients:
            client.enqueue_text(payload)

    def _on_session_terminated(self, session: ScrcpySession, reason: str):
        sid = session.session_id
        with self._lock:
            slot = self._slots.get(sid)
            if slot is None or slot.session is not session:
                return
            self._cancel_grace(slot)
            slot.session = None
            slot.last_error = reason
        self._broadcast_status(sid, notify_main=True)

    def _trigger_reset_video(self, session_id: str = "main"):
        with self._lock:
            slot = self._slots.get(session_id)
            sess = slot.session if slot else None
        if sess is not None:
            sess.reset_video()

    def start(
        self,
        cfg: dict,
        serial: str = "",
        quality: str | None = None,
        max_fps: int | str | None = None,
        screen_off: bool = False,
        *,
        session_id: str = "main",
        new_display: str = "",
        start_app: str = "",
        app_name: str = "",
        preset: str = "",
        ime_policy: str = "local",
    ) -> dict:
        sid = str(session_id or "main").strip() or "main"
        vd = str(new_display or "").strip()
        pkg = str(start_app or "").strip()
        pol = normalize_ime_policy(ime_policy, default="local") if vd else ""
        with self._lock:
            slot = self._get_slot(sid, create=True)
            q = normalize_quality(quality if quality is not None else slot.quality)
            fps = normalize_max_fps(max_fps if max_fps is not None else slot.max_fps)

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
            slot = self._get_slot(sid, create=True)
            if slot.starting:
                raise ScrcpyError("正在连接手机屏幕，请稍候")
            self._cancel_grace(slot)
            cur = slot.session
            if (
                cur is not None
                and cur.serial == target_serial
                and cur.quality == q
                and cur.max_fps == fps
                and cur.new_display == vd
                and cur.start_app == pkg
                and (not vd or cur.ime_policy == pol)
            ):
                if cur.is_virtual and cur.start_app:
                    try:
                        cur.send_control_packets([pack_start_app(cur.start_app)])
                    except ScrcpyError:
                        pass
                elif not cur.is_virtual and cur.screen_off != bool(screen_off):
                    cur.set_display_power(not bool(screen_off))
                    self._broadcast_status(sid)
                return self.status(sid)
            old_session = cur
            slot.session = None
            slot.starting = True
            slot.quality = q
            slot.max_fps = fps
            slot.preset = str(preset or "")
            slot.ime_policy = pol or "local"
            slot.package = pkg
            slot.app_name = str(app_name or "").strip() or pkg
            slot.last_error = ""

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
            on_video_packet=lambda c, k, p, s_id=sid: self._on_video_packet(s_id, c, k, p),
            on_terminated=self._on_session_terminated,
            on_device_clipboard=lambda txt, s_id=sid: self._on_device_clipboard(s_id, txt),
            on_ack_clipboard=lambda seq, s_id=sid: self._on_ack_clipboard(s_id, seq),
            session_id=sid,
            new_display=vd,
            start_app=pkg,
            app_name=str(app_name or "").strip() or pkg,
            preset=str(preset or ""),
            ime_policy=pol or "local",
        )
        try:
            session.start(screen_off=bool(screen_off) and not session.is_virtual)
        except Exception as exc:
            with self._lock:
                slot = self._get_slot(sid, create=True)
                slot.starting = False
                slot.last_error = str(exc)
            self._broadcast_status(sid, notify_main=True)
            raise

        with self._lock:
            slot = self._get_slot(sid, create=True)
            slot.session = session
            slot.starting = False
            slot.last_error = ""
            clients = list(slot.clients)

        self._broadcast_status(sid, notify_main=True)
        if clients:
            session.reset_video()
        return self.status(sid)

    def stop(self, session_id: str = "main") -> dict:
        sid = str(session_id or "main").strip() or "main"
        with self._lock:
            slot = self._slots.get(sid)
            if slot is None:
                return self.status(sid)
            self._cancel_grace(slot)
            sess = slot.session
            slot.session = None
            slot.last_error = ""
        if sess is not None:
            sess.close()
        self._broadcast_status(sid, notify_main=True)
        if sid != "main":
            with self._lock:
                cur_slot = self._slots.get(sid)
                if cur_slot is not None and cur_slot.session is None and not cur_slot.clients and not cur_slot.starting:
                    self._slots.pop(sid, None)
        return self.status(sid)

    def shutdown(self):
        with self._lock:
            sessions: list[ScrcpySession] = []
            clients: list[_WsClient] = []
            for slot in self._slots.values():
                self._cancel_grace(slot)
                if slot.session is not None:
                    sessions.append(slot.session)
                    slot.session = None
                clients.extend(slot.clients)
                slot.clients.clear()
            self._slots = {"main": _SessionSlot("main")}
        for client in clients:
            client.close()
        for sess in sessions:
            sess.close()

    def _schedule_virtual_idle_stop(self, sid: str):
        if sid == "main" or self._virtual_idle_grace <= 0:
            return
        with self._lock:
            slot = self._slots.get(sid)
            if slot is None or slot.session is None or not slot.session.is_virtual or slot.clients:
                return
            self._cancel_grace(slot)

            def _expire():
                with self._lock:
                    cur = self._slots.get(sid)
                    if cur is None or cur.clients or cur.session is None:
                        return
                self.stop(sid)

            timer = threading.Timer(self._virtual_idle_grace, _expire)
            timer.daemon = True
            slot.grace_timer = timer
            timer.start()

    def handle_websocket(self, ws: WebSocketConn, session_id: str = "main"):
        sid = str(session_id or "main").strip() or "main"
        client = _WsClient(ws, on_need_keyframe=lambda s_id=sid: self._trigger_reset_video(s_id))
        with self._lock:
            slot = self._get_slot(sid, create=True)
            self._cancel_grace(slot)
            slot.clients.add(client)
            sess = slot.session
            cached_config = sess.last_config_packet if sess is not None else None

        try:
            client.enqueue_text(json.dumps({"type": "status", **self.status(sid)}, ensure_ascii=False))
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
                            cur_slot = self._slots.get(sid)
                            cur = cur_slot.session if cur_slot else None
                            cfg_pkt = cur.last_config_packet if cur is not None else None
                        if cur is not None:
                            if cfg_pkt:
                                client.enqueue_video(True, False, cfg_pkt)
                            cur.reset_video()
                    continue

                with self._lock:
                    cur_slot = self._slots.get(sid)
                    cur = cur_slot.session if cur_slot else None
                if cur is None:
                    client.enqueue_text(json.dumps({"type": "error", "message": "当前未连接手机投屏"}, ensure_ascii=False))
                    continue

                if cmd_type == "display_power":
                    if cur.is_virtual:
                        continue
                    try:
                        cur.set_display_power(bool(cmd.get("on", True)))
                        self._broadcast_status(sid)
                    except ScrcpyError as exc:
                        client.enqueue_text(json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False))
                    continue

                try:
                    if cmd_type == "clipboard":
                        clip_text = str(cmd.get("text") or "")
                        if clip_text:
                            with self._lock:
                                if cur_slot is not None:
                                    cur_slot.last_sent_clipboard = (clip_text, time.monotonic())
                    elif cmd_type == "get_clipboard":
                        with self._lock:
                            if cur_slot is not None:
                                cur_slot.last_sent_clipboard = ("", 0.0)
                    packets = encode_control_command(cmd, seq_fn=cur.next_sequence)
                    cur.send_control_packets(packets)
                except (ValueError, ScrcpyError) as exc:
                    client.enqueue_text(json.dumps({"type": "error", "message": str(exc)}, ensure_ascii=False))
        except WebSocketError:
            pass
        finally:
            should_grace = False
            with self._lock:
                cur_slot = self._slots.get(sid)
                if cur_slot is not None:
                    cur_slot.clients.discard(client)
                    if cur_slot.session is not None and cur_slot.session.is_virtual and not cur_slot.clients:
                        should_grace = True
            client.close()
            if should_grace:
                self._schedule_virtual_idle_stop(sid)


# ---------------------------------------------- ADB device helpers (info/app/push) ----

def _adb_run(adb, args: list[str], timeout: float | None = None) -> tuple[int, str, str]:
    if timeout is None:
        return adb.run(args)
    try:
        return adb.run(args, timeout=timeout)
    except TypeError:
        return adb.run(args)


def sanitize_upload_filename(name: str) -> str:
    raw = str(name or "").replace("\\", "/")
    base = Path(raw).name.strip()
    cleaned = _FILENAME_BAD_RE.sub("_", base).strip(" .")
    if not cleaned:
        return "upload.bin"
    if len(cleaned) > 160:
        p = Path(cleaned)
        ext = p.suffix[:24]
        cleaned = (p.stem[: 160 - len(ext)] or "upload") + ext
    return cleaned


def parse_device_info_output(output: str) -> dict:
    section = ""
    bat_level: int | None = None
    bat_temp: float | None = None
    bat_status = 0
    ac_powered = False
    usb_powered = False
    wireless_powered = False
    wifi_ip = ""
    cellular_ip = ""
    installed: set[str] = set()

    for raw_line in str(output or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line in ("===BAT===", "===NET===", "===PKG==="):
            section = line
            continue
        if section == "===BAT===":
            key, sep, val = line.partition(":")
            if not sep:
                continue
            k = key.strip().lower()
            v = val.strip()
            if k == "level":
                try:
                    bat_level = int(v)
                except ValueError:
                    pass
            elif k == "temperature":
                try:
                    bat_temp = round(int(v) / 10.0, 1)
                except ValueError:
                    pass
            elif k == "status":
                try:
                    bat_status = int(v)
                except ValueError:
                    pass
            elif k == "ac powered":
                ac_powered = v.lower() == "true"
            elif k == "usb powered":
                usb_powered = v.lower() == "true"
            elif k == "wireless powered":
                wireless_powered = v.lower() == "true"
        elif section == "===NET===":
            m = re.search(r"^\d+:\s+([^\s]+)\s+inet\s+([0-9.]+)/", line)
            if not m:
                continue
            iface, ip_addr = m.group(1), m.group(2)
            if ip_addr.startswith("127."):
                continue
            if iface.startswith(("wlan", "eth")) and not wifi_ip:
                wifi_ip = ip_addr
            elif iface.startswith(("rmnet", "ccmni", "pdp", "wwan", "cell")) and not cellular_ip:
                cellular_ip = ip_addr
        elif section == "===PKG===":
            if line.startswith("package:"):
                installed.add(line[len("package:"):].strip())

    plugged = ac_powered or usb_powered or wireless_powered
    charging = bat_status == 2
    full = bat_status == 5
    net_type = "Wi-Fi" if wifi_ip else ("移动网络" if cellular_ip else "未联网")
    net_ip = wifi_ip or cellular_ip
    proxy_apps = [
        {"package": pkg, "label": label}
        for pkg, label in KNOWN_PROXY_APPS
        if pkg in installed
    ]
    return {
        "battery": {
            "level": bat_level,
            "temp_c": bat_temp,
            "charging": charging,
            "full": full,
            "plugged": plugged,
            "status": bat_status,
        },
        "network": {
            "type": net_type,
            "ip": net_ip,
            "wifi_ip": wifi_ip,
            "cellular_ip": cellular_ip,
        },
        "proxy_apps": proxy_apps,
    }


def parse_scrcpy_apps_output(output: str) -> list[dict]:
    seen: set[str] = set()
    apps: list[dict] = []
    for line in str(output or "").splitlines():
        m = _APP_LINE_RE.match(line)
        if not m:
            continue
        marker, name, pkg = m.group(1), m.group(2).strip(), m.group(3).strip()
        if pkg in seen:
            continue
        seen.add(pkg)
        apps.append({"name": name or pkg, "package": pkg, "system": marker == "*"})
    apps.sort(key=lambda item: (1 if item["system"] else 0, item["name"].lower(), item["package"].lower()))
    return apps


def list_device_apps(
    adb,
    serial: str = "",
    *,
    server_path: Path | str = DEFAULT_SERVER_PATH,
    force_refresh: bool = False,
) -> dict:
    try:
        device = adb.online_device(serial=str(serial or "").strip())
    except Exception as exc:
        raise ScrcpyError(str(exc)) from exc
    if device is None:
        raise ScrcpyError("未检测到在线 Android 设备")
    target_serial = device["serial"]

    now = time.monotonic()
    if not force_refresh:
        with _apps_cache_lock:
            cached = _apps_cache.get(target_serial)
            if cached and (now - cached[0]) < _APPS_CACHE_TTL:
                return {"ok": True, "serial": target_serial, "apps": [dict(a) for a in cached[1]]}

    verified = verify_server_binary(server_path)
    remote_jar = f"/data/local/tmp/dbs_la_{secrets.token_hex(4)}.jar"
    code, _out, err = _adb_run(adb, ["-s", target_serial, "push", str(verified), remote_jar], timeout=15)
    if code != 0:
        raise ScrcpyError(f"推送 scrcpy-server 失败：{err.strip() or f'exit {code}'}")
    try:
        code, out, err = _adb_run(
            adb,
            [
                "-s",
                target_serial,
                "shell",
                f"CLASSPATH={remote_jar}",
                "app_process",
                "/",
                "com.genymobile.scrcpy.Server",
                SCRCPY_SERVER_VERSION,
                "list_apps=true",
            ],
            timeout=20,
        )
    finally:
        try:
            _adb_run(adb, ["-s", target_serial, "shell", "rm", "-f", remote_jar], timeout=5)
        except Exception:
            pass
    if code != 0 and "List of apps:" not in out:
        raise ScrcpyError((err or out).strip() or "读取手机应用列表失败")
    apps = parse_scrcpy_apps_output(out)
    with _apps_cache_lock:
        _apps_cache[target_serial] = (time.monotonic(), [dict(a) for a in apps])
    return {"ok": True, "serial": target_serial, "apps": apps}


def get_device_info(adb, serial: str = "") -> dict:
    try:
        device = adb.online_device(serial=str(serial or "").strip())
    except Exception as exc:
        raise ScrcpyError(str(exc)) from exc
    if device is None:
        raise ScrcpyError("未检测到在线 Android 设备")
    target_serial = device["serial"]
    code, out, err = _adb_run(
        adb,
        [
            "-s",
            target_serial,
            "shell",
            "echo ===BAT===; dumpsys battery; echo ===NET===; ip -o -4 addr show 2>/dev/null; echo ===PKG===; pm list packages",
        ],
    )
    if code != 0 and not out.strip():
        raise ScrcpyError(err.strip() or "读取手机设备信息失败")
    parsed = parse_device_info_output(out)
    return {"ok": True, "serial": target_serial, "model": device.get("model") or "", **parsed}


def launch_device_app(adb, package: str, serial: str = "") -> dict:
    pkg = str(package or "").strip()
    if not _PACKAGE_RE.match(pkg):
        raise ScrcpyError(f"无效的 Android 应用包名：{pkg}")
    try:
        device = adb.online_device(serial=str(serial or "").strip())
    except Exception as exc:
        raise ScrcpyError(str(exc)) from exc
    if device is None:
        raise ScrcpyError("未检测到在线 Android 设备")
    target_serial = device["serial"]

    component = ""
    code, out, _err = _adb_run(
        adb,
        ["-s", target_serial, "shell", "cmd", "package", "resolve-activity", "--brief", pkg],
    )
    if code == 0:
        for line in reversed(out.splitlines()):
            cand = line.strip()
            if _COMPONENT_RE.match(cand):
                component = cand
                break

    if component:
        code, out, err = _adb_run(adb, ["-s", target_serial, "shell", "am", "start", "-n", component])
        if code == 0 and "Error:" not in out and "Error:" not in err:
            return {"ok": True, "serial": target_serial, "package": pkg, "component": component}

    code, out, err = _adb_run(
        adb,
        ["-s", target_serial, "shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
    )
    if code != 0 or "No activities found" in out or "No activities found" in err:
        raise ScrcpyError((err or out).strip() or f"无法启动手机应用 {pkg}")
    return {"ok": True, "serial": target_serial, "package": pkg, "component": component}


def push_or_install_file(
    adb,
    local_path: Path | str,
    filename: str,
    serial: str = "",
    action: str = "auto",
) -> dict:
    src = Path(local_path)
    if not src.is_file():
        raise ScrcpyError("待发送的本地文件不存在")
    safe_name = sanitize_upload_filename(filename or src.name)
    size = src.stat().st_size
    act = str(action or "auto").strip().lower()
    if act not in ("auto", "push", "install"):
        raise ScrcpyError(f"不支持的传输模式：{act}")
    mode = "install" if (act == "install" or (act == "auto" and safe_name.lower().endswith(".apk"))) else "push"

    try:
        device = adb.online_device(serial=str(serial or "").strip())
    except Exception as exc:
        raise ScrcpyError(str(exc)) from exc
    if device is None:
        raise ScrcpyError("未检测到在线 Android 设备")
    target_serial = device["serial"]

    if mode == "install":
        code, out, err = _adb_run(adb, ["-s", target_serial, "install", "-r", str(src)], timeout=120)
        combined = "\n".join(x for x in (out.strip(), err.strip()) if x)
        if code != 0 or "Failure" in combined:
            raise ScrcpyError(f"安装 APK 失败：{combined or f'exit {code}'}")
        return {
            "ok": True,
            "mode": "install",
            "serial": target_serial,
            "filename": safe_name,
            "size": size,
            "message": f"已安装 APK：{safe_name}",
        }

    remote_path = f"/sdcard/Download/{safe_name}"
    code, out, err = _adb_run(adb, ["-s", target_serial, "push", str(src), remote_path], timeout=120)
    if code != 0:
        raise ScrcpyError(f"发送文件失败：{(err or out).strip() or f'exit {code}'}")

    # Best-effort trigger media scanner so pushed photos/videos appear in Gallery
    quoted = _url_quote(safe_name, safe="")
    try:
        _adb_run(
            adb,
            [
                "-s",
                target_serial,
                "shell",
                "am",
                "broadcast",
                "-a",
                "android.intent.action.MEDIA_SCANNER_SCAN_FILE",
                "-d",
                f"file:///sdcard/Download/{quoted}",
            ],
            timeout=10,
        )
    except Exception:
        pass

    return {
        "ok": True,
        "mode": "push",
        "serial": target_serial,
        "filename": safe_name,
        "remote_path": remote_path,
        "size": size,
        "message": f"已发送至手机 {remote_path}",
    }
