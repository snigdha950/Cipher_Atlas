from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

MAX_FILES = 250
MAX_TOTAL_UNCOMPRESSED = 12 * 1024 * 1024
MAX_SINGLE_FILE = 2 * 1024 * 1024
MAX_PATH_LENGTH = 300
MAX_COMPRESSION_RATIO = 120
SUPPORTED_SUFFIXES = {".py", ".conf", ".cnf", ".cfg", ".ini", ".json", ".pem", ".crt", ".cer"}


@dataclass(frozen=True)
class ArchiveEntry:
    path: str
    data: bytes
    supported: bool


class UnsafeArchive(ValueError):
    pass


def _safe_name(name: str) -> bool:
    if not name or len(name) > MAX_PATH_LENGTH or "\x00" in name:
        return False
    p = PurePosixPath(name.replace("\\", "/"))
    return not p.is_absolute() and ".." not in p.parts and not name.startswith(("/", "\\"))


def read_zip_safely(blob: bytes) -> list[ArchiveEntry]:
    """Inspect a ZIP in memory. Repository content is never executed or extracted."""
    entries: list[ArchiveEntry] = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_FILES:
            raise UnsafeArchive(f"Archive has {len(infos)} files; limit is {MAX_FILES}.")
        for info in infos:
            if info.flag_bits & 0x1:
                raise UnsafeArchive(f"Encrypted ZIP entries are not accepted: {info.filename}")
            if not _safe_name(info.filename):
                raise UnsafeArchive(f"Unsafe archive path: {info.filename}")
            if info.file_size > MAX_SINGLE_FILE:
                raise UnsafeArchive(f"File too large: {info.filename}")
            if info.compress_size > 0 and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                raise UnsafeArchive(f"Suspicious compression ratio: {info.filename}")
            total += info.file_size
            if total > MAX_TOTAL_UNCOMPRESSED:
                raise UnsafeArchive("Archive exceeds uncompressed size limit.")
            data = zf.read(info)
            suffix = PurePosixPath(info.filename).suffix.lower()
            entries.append(ArchiveEntry(info.filename, data, suffix in SUPPORTED_SUFFIXES))
    return entries
