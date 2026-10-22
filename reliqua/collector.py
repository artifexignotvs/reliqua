"""Bounded, read-only observations of visible Linux processes."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import stat

from . import __version__
from .packages import package_for

PROC_ROOT = Path("/proc")
OS_RELEASE = Path("/etc/os-release")
HOST_ROOT = Path("/")
MAX_MAP_BYTES = 8 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_PID_COUNT = 65536
MAX_CANDIDATES = 512
MAX_COMPONENTS = 16
MODULE_NAME = re.compile(r"libphp(?:[0-9]+(?:\.[0-9]+)*)?\.so(?:\.[0-9]+)*\Z")


def _add(errors: list[str], value: str) -> None:
    if value not in errors:
        errors.append(value)


def _read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("read_limit")
    return data


def _stat_data(path: Path) -> tuple[int, int, str]:
    data = _read(path, 16384).decode("utf-8", "strict")
    left, right = data.find("("), data.rfind(")")
    if left < 0 or right <= left:
        raise ValueError("invalid_stat")
    fields = data[right + 1:].split()
    return int(fields[19]), int(fields[6]), data[left + 1:right]


def _device(value: int) -> str:
    return f"{os.major(value):x}:{os.minor(value):x}"


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _kind(name: str) -> str | None:
    name = Path(name.removesuffix(" (deleted)")).name.lower()
    if re.fullmatch(r"php-fpm(?:[0-9.]+)?", name):
        return "fpm"
    if re.fullmatch(r"php-cgi(?:[0-9.]+)?", name):
        return "cgi"
    if re.fullmatch(r"php(?:[0-9.]+)?", name):
        return "cli"
    if name in {"apache", "apache2", "httpd"}:
        return "apache"
    if name in {"frankenphp", "caddy"} or re.fullmatch(r"lsphp(?:[0-9.]+)?", name):
        return "embedded"
    return None


def _mappings(data: bytes) -> list[tuple[str, int, str]]:
    result = []
    for line in data.decode("utf-8", "strict").splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise ValueError("invalid_maps")
        if len(fields) == 6 and fields[5].startswith("/"):
            major, minor = fields[3].split(":", 1)
            device = f"{int(major, 16):x}:{int(minor, 16):x}"
            result.append((device, int(fields[4]), fields[5]))
    return list(dict.fromkeys(result))


def _same_context(directory: Path) -> bool:
    namespace = os.stat(directory / "ns/mnt")
    own_namespace = os.stat(PROC_ROOT / "self/ns/mnt")
    root = os.stat(directory / "root")
    host_root = os.stat(HOST_ROOT)
    return ((namespace.st_dev, namespace.st_ino) == (own_namespace.st_dev, own_namespace.st_ino)
            and (root.st_dev, root.st_ino) == (host_root.st_dev, host_root.st_ino))


def _component(path: str, role: str, device: str, inode: int,
               directory: Path, trusted_context: bool, cache: dict) -> dict:
    result = {"path": path.removesuffix(" (deleted)"), "role": role,
              "state": "unknown", "mapped_device": device, "mapped_inode": inode,
              "disk_device": None, "disk_inode": None, "package": None, "errors": []}
    if path.endswith(" (deleted)"):
        result["state"] = "deleted"
        result["errors"].append("mapped_file_deleted")
        return result
    if (len(path) > 4096 or not path.startswith("/")
            or any(char in path for char in "\x00\r\n\\")
            or ".." in Path(path).parts):
        result["errors"].append("unsupported_runtime_path")
        return result
    if not trusted_context:
        result["errors"].append("namespace_unverified")
        return result
    target = directory / "root" / path.lstrip("/")
    try:
        fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            result["disk_device"] = _device(before.st_dev)
            result["disk_inode"] = before.st_ino
            if not stat.S_ISREG(before.st_mode):
                result["errors"].append("runtime_not_regular")
                return result
            if (device, inode) != (_device(before.st_dev), before.st_ino):
                result["state"] = "replaced"
                result["errors"].append("mapped_file_replaced")
                return result
            if before.st_size > MAX_BINARY_BYTES:
                result["errors"].append("runtime_size_limit")
                return result
            signature = _identity(before)
            key = (path, signature)
            if key in cache:
                digest = cache[key]
            else:
                sha = hashlib.sha256()
                total = 0
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_BINARY_BYTES:
                        result["errors"].append("runtime_size_limit")
                        return result
                    sha.update(chunk)
                if total != before.st_size:
                    result["errors"].append("runtime_changed")
                    return result
                digest = sha.hexdigest()
            package = package_for(path)
            after = os.fstat(stream.fileno())
            current = os.stat(target, follow_symlinks=False)
            local = os.stat(path, follow_symlinks=False)
            if any(_identity(item) != signature for item in (after, current, local)):
                result["errors"].append("runtime_changed")
                return result
            cache[key] = digest
            result.update(state="current", sha256=digest, package=package)
            if package is None:
                result["errors"].append("package_unverified")
            return result
    except FileNotFoundError:
        result["state"] = "replaced"
        result["errors"].append("runtime_path_missing")
    except (OSError, ValueError):
        result["errors"].append("runtime_unreadable")
    return result


def _observe(pid: int, selected: bool, cache: dict) -> tuple[dict | None, str | None]:
    directory = PROC_ROOT / str(pid)
    result = {"pid": pid, "start_ticks": 0, "kind": "unknown", "components": [], "errors": []}
    try:
        start, flags, comm = _stat_data(directory / "stat")
        result["start_ticks"] = start
        if flags & 0x00200000:
            if selected:
                result["errors"].append("php_runtime_not_observed")
                return result, None
            return None, None
        executable = os.readlink(directory / "exe")
        initial_exe = os.stat(directory / "exe")
        maps_before = _read(directory / "maps", MAX_MAP_BYTES)
        mappings = _mappings(maps_before)
        modules = [item for item in mappings
                   if MODULE_NAME.fullmatch(Path(item[2].removesuffix(" (deleted)")).name)]
        kind = _kind(executable) or _kind(comm)
        if modules:
            kind = "apache" if kind == "apache" else (kind or "embedded")
        if (kind is None or (kind == "apache" and not modules)) and not selected:
            return None, None
        result["kind"] = kind or "unknown"
        try:
            trusted_context = _same_context(directory)
        except OSError:
            trusted_context = False
        if not trusted_context:
            result["errors"].append("namespace_unverified")
        components = [(path, "module", dev, ino) for dev, ino, path in modules]
        if kind in {"fpm", "cgi", "cli", "embedded"}:
            components.insert(0, (executable, "executable", _device(initial_exe.st_dev), initial_exe.st_ino))
        if not components:
            result["errors"].append("php_runtime_not_observed")
        if len(components) > MAX_COMPONENTS:
            result["errors"].append("component_limit")
        result["components"] = [_component(path, role, dev, ino, directory, trusted_context, cache)
                                for path, role, dev, ino in components[:MAX_COMPONENTS]]
        start_after, _, _ = _stat_data(directory / "stat")
        maps_after = _read(directory / "maps", MAX_MAP_BYTES)
        exe_after = os.stat(directory / "exe")
        if (start != start_after or maps_before != maps_after
                or executable != os.readlink(directory / "exe")
                or _identity(initial_exe) != _identity(exe_after)
                or trusted_context != _same_context(directory)):
            result["errors"].append("process_changed")
            for component in result["components"]:
                component["state"] = "unknown"
                component["package"] = None
                component.pop("sha256", None)
                _add(component["errors"], "process_changed")
        return result, None
    except PermissionError:
        code = "proc_access_denied"
    except FileNotFoundError:
        code = "proc_disappeared"
    except (OSError, ValueError, UnicodeError, IndexError):
        code = "proc_unreadable"
    result["errors"].append(code)
    for component in result["components"]:
        component["state"] = "unknown"
        component["package"] = None
        component.pop("sha256", None)
    return (result if selected or result["kind"] != "unknown" else None), code


def _os_release() -> dict:
    result = {"id": "unknown", "version_id": "unknown"}
    try:
        for line in _read(OS_RELEASE, 65536).decode("utf-8", "strict").splitlines():
            name, separator, value = line.partition("=")
            if separator and name in {"ID", "VERSION_ID"}:
                value = value.strip().strip("\"'")
                if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
                    result[name.lower()] = value
    except (OSError, ValueError, UnicodeError):
        pass
    return result


def _pids() -> list[int]:
    result = []
    with os.scandir(PROC_ROOT) as entries:
        for entry in entries:
            if entry.name.isascii() and entry.name.isdigit():
                result.append(int(entry.name))
                if len(result) > MAX_PID_COUNT:
                    raise ValueError("pid_limit")
    return sorted(result)


def collect(node: str, pids: list[int] | None = None) -> dict:
    """Return one scoped observation; absence of evidence is not clearance."""
    if not isinstance(node, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", node):
        raise ValueError("invalid_node_alias")
    if pids is not None and (not isinstance(pids, list) or not pids
                            or len(pids) > MAX_CANDIDATES
                            or any(type(pid) is not int or pid <= 0 or pid > 2**31 - 1 for pid in pids)):
        raise ValueError("invalid_pid_selection")
    result = {"schema": 1, "tool_version": __version__, "node": node,
              "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
              "boot_id": "", "scope": "selected-pids" if pids is not None else "visible-proc",
              "processes": [], "errors": [], "os": _os_release()}
    try:
        boot_id = _read(PROC_ROOT / "sys/kernel/random/boot_id", 128).decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", boot_id):
            raise ValueError("boot_id_invalid")
        result["boot_id"] = boot_id.lower()
    except (OSError, ValueError, UnicodeError):
        result["errors"].append("boot_id_unavailable")
    if "unknown" in result["os"].values():
        result["errors"].append("os_release_unavailable")
    try:
        selected = sorted(set(pids)) if pids is not None else _pids()
    except (OSError, ValueError):
        result["errors"].append("proc_inventory_unavailable")
        return result
    if not selected:
        result["errors"].append("no_processes_visible")
    cache: dict = {}
    for pid in selected:
        observation, error = _observe(pid, pids is not None, cache)
        if error:
            _add(result["errors"], error)
        if observation is not None:
            if len(result["processes"]) >= MAX_CANDIDATES:
                _add(result["errors"], "process_limit")
                break
            result["processes"].append(observation)
    if pids is None:
        try:
            if selected != _pids():
                _add(result["errors"], "proc_inventory_changed")
        except (OSError, ValueError):
            _add(result["errors"], "proc_inventory_unavailable")
    if not result["processes"]:
        _add(result["errors"], "no_php_runtime_observed")
    return result
