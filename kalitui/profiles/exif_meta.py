"""EXIF 元数据提取：从图片/文档提取 GPS 坐标、作者、设备、软件版本。

白帽定位：侦察/社工场景——目标发布在官网/社交媒体的图片常带 EXIF：
GPS 定位实际位置（办公室/数据中心）、作者名（员工枚举）、相机/软件版本
（指纹内部工具链）。纯本地文件分析（exiftool），零网络。
"""

from __future__ import annotations

import os
import re
from typing import Any

from .base import ToolProfile, check_installed

_FIELD_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9 _\-()/]{0,40}):\s*(.+)$")

# 关键字段（英文名，exiftool 输出）
_KEY_FIELDS = [
    "GPS Latitude", "GPS Longitude", "GPS Altitude",
    "Artist", "Author", "Creator", "By-line", "Copyright",
    "Software", "Make", "Model", "Lens", "DateTimeOriginal",
    "CreateDate", "ModifyDate", "ImageDescription", "Comment",
    "UserComment", "URL", "OwnerName", "XMP:Creator", "XMP:Artist",
]
_GPS_DMS_RE = re.compile(
    r"^\s*(\d+)\s*deg\s*(\d+)'\s*([\d.]+)\"\s*([NSEW])", re.IGNORECASE)

SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "exif_meta",
            "description": (
                "EXIF 元数据提取：从本地图片/文档提取 GPS 坐标（转十进制+地图链接）、"
                "作者、拍摄设备、软件版本等——侦察定位/员工枚举/工具链指纹。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file": {
                        "type": "string",
                        "description": "本地文件路径，如 /tmp/photo.jpg",
                    },
                },
                "required": ["file"],
            },
        },
    },
]


def _build_cmd(path: str) -> str:
    return f"exiftool '{path}'"


def _parse(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in raw.splitlines():
        m = _FIELD_RE.match(line)
        if m:
            name, val = m.group(1).strip(), m.group(2).strip()
            if name in _KEY_FIELDS and val:
                out[name] = val[:200]
    return out


def _dms_to_decimal(dms: str) -> float | None:
    """'39 deg 54' 26.10\" N' → 39.90725（南/西为负）。"""
    m = _GPS_DMS_RE.match(dms)
    if not m:
        return None
    deg, minute, sec, hemi = int(m.group(1)), int(m.group(2)), float(m.group(3)), m.group(4).upper()
    dec = deg + minute / 60 + sec / 3600
    return -dec if hemi in ("S", "W") else dec


def _summarize(raw: str, path: str) -> str:
    info = _parse(raw)
    head: list[str] = [f"📷 {path} EXIF 摘要:"]
    lat = _dms_to_decimal(info.get("GPS Latitude", ""))
    lon = _dms_to_decimal(info.get("GPS Longitude", ""))
    if lat is not None and lon is not None:
        head.append(f"  📍 GPS: {lat:.6f}, {lon:.6f}")
        head.append(f"     → https://www.google.com/maps?q={lat:.6f},{lon:.6f}")
    for name in _KEY_FIELDS:
        if name in info and not (name.startswith("GPS") and lat is not None):
            head.append(f"  {name}: {info[name]}")
    if len(head) == 1:
        head.append("  （未提取到关键元数据——图片可能被清理过 EXIF）")
        head.append("提示：检查文档属性（PDF 作者/Word 元数据）、压缩包注释；"
                    "社交平台常剥离 EXIF，官网原图常保留。")
    else:
        head.append("下一步：GPS 定位目标办公/数据中心实际位置；作者名接用户枚举"
                    "（theharvester）；软件版本指纹内部工具链。")
    return ToolProfile._summary(raw, head, tail=20)


class ExifMetaProfile(ToolProfile):
    name = "exif_meta"
    aliases = ["exif 提取", "元数据提取", "gps 定位", "图片信息", "exif", "照片定位", "元数据"]
    summary = "EXIF 元数据提取（GPS/作者/设备）"
    lore = """### EXIF 元数据提取使用要点
- 定位：目标官网/社交媒体发布的图片常带 EXIF——GPS 定位（办公室/机房实际位置）、
  作者名（员工枚举）、相机/软件（内部工具链指纹）。
- 用法：exif_meta(file='/tmp/photo.jpg')——纯本地分析，零网络请求。
- GPS：度分秒自动转十进制 + 生成 Google Maps 链接；南纬/西经为负值。
- 结合流程：GPS 定位 → 物理位置（配合社工）；作者名 → 员工枚举 → 用户名猜测
  （登录接口爆破）；软件版本 → cve_lookup 查已知漏洞。
- 注意：社交平台（微博/微信/INS）通常剥离 EXIF；官网原图/邮件附件常保留；
  PDF 元数据（作者/软件）在文档属性里，同样可提取。"""
    extra_schemas = SCHEMAS

    async def exec_exif_meta(self, ex: Any, args: dict[str, Any]) -> str:
        if not check_installed("exiftool"):
            return "exiftool 未安装（apt install libimage-exiftool-perl）。"
        path = str(args.get("file") or "").strip()
        if not path or len(path) > 500 or "\n" in path:
            return "file 路径非法。"
        if not os.path.isfile(path):
            return f"文件不存在: {path}"
        raw = await self._run(ex, _build_cmd(path), timeout=30)
        return _summarize(raw, path)
