"""Manage the Go OpenField server processes from the admin panel.

Processes are started detached from the Flask process and tracked by PID in a
JSON config file, so running services survive a Flask restart and their status
can be checked by polling the PID.
"""

import ctypes
import json
import os
import signal
import subprocess

import config

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_config.json")

# Windows executables carry a .exe suffix; Linux ELF binaries do not. The
# suffix follows the platform the panel runs on.
def _exe_suffix():
    return ".exe" if os.name == "nt" else ""

# Service name -> built executable base name (suffix added at runtime) +
# source directory.
SERVICES = {
    "gateway": {"exe": "openfield-gateway", "dir": "gateway"},
    "account": {"exe": "openfield-account", "dir": "account"},
    "storage": {"exe": "openfield-storage", "dir": "storage"},
    "chat": {"exe": "openfield-chat", "dir": "chat"},
    "posts": {"exe": "openfield-posts", "dir": "posts"},
    "push": {"exe": "openfield-push", "dir": "push"},
}

# Keep references to open log files so they aren't garbage collected.
_open_log_files = {}


def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            cfg.setdefault("server_root", config.SERVER_ROOT)
            cfg.setdefault("pids", {})
            return cfg
        except (json.JSONDecodeError, OSError):
            pass
    return {"server_root": config.SERVER_ROOT, "pids": {}}


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def pid_alive(pid):
    if not pid:
        return False
    if os.name == "nt":
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def bin_dir(root):
    return os.path.join(root, "bin")


def service_exe_name(name):
    """Built binary file name for a service (with platform-appropriate suffix)."""
    return SERVICES[name]["exe"] + _exe_suffix()


def service_exe_path(root, name):
    return os.path.join(bin_dir(root), service_exe_name(name))


def discover(root):
    """Return a list of services with their build state and running state."""
    root = root or ""
    bdir = bin_dir(root) if root else ""
    result = []
    for name in SERVICES:
        exe_name = service_exe_name(name)
        exe_path = os.path.join(bdir, exe_name) if bdir else ""
        built = os.path.isfile(exe_path) if exe_path else False
        pid = None
        result.append(
            {
                "name": name,
                "exe": exe_name,
                "source_dir": SERVICES[name]["dir"],
                "built": built,
                "exe_path": exe_path,
                "running": False,
                "pid": pid,
            }
        )
    return result


def refresh_status(cfg, services):
    pids = cfg.get("pids", {})
    for svc in services:
        pid = pids.get(svc["name"])
        svc["pid"] = pid
        svc["running"] = pid_alive(pid)
    return services


def start_service(cfg, name):
    root = cfg.get("server_root", "")
    if not root:
        return False, "未设置服务器根目录"
    if name not in SERVICES:
        return False, f"未知服务: {name}"
    if pid_alive(cfg.get("pids", {}).get(name)):
        return False, f"{name} 已在运行"

    exe_path = service_exe_path(root, name)
    if not os.path.isfile(exe_path):
        return False, f"未找到可执行文件: {exe_path}"

    logs_dir = os.path.join(root, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.join(logs_dir, f"{name}.log")
    log_file = open(log_path, "a", encoding="utf-8", buffering=1)
    _open_log_files[name] = log_file

    if os.name == "nt":
        kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS}
    else:
        kwargs = {"start_new_session": True}

    try:
        proc = subprocess.Popen(
            [exe_path],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=log_file,
            **kwargs,
        )
    except OSError as e:
        log_file.close()
        _open_log_files.pop(name, None)
        return False, f"启动失败: {e}"

    cfg.setdefault("pids", {})[name] = proc.pid
    save_config(cfg)
    return True, f"{name} 已启动 (PID {proc.pid})"


def stop_service(cfg, name):
    pid = cfg.get("pids", {}).get(name)
    if not pid_alive(pid):
        cfg.get("pids", {}).pop(name, None)
        save_config(cfg)
        return True, f"{name} 未在运行"
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                timeout=30,
            )
        else:
            os.kill(pid, signal.SIGTERM)
    except (OSError, subprocess.TimeoutExpired):
        pass
    cfg.get("pids", {}).pop(name, None)
    save_config(cfg)
    return True, f"{name} 已停止"


def run_migrations(cfg):
    """Initialize the database schema by running the Go server's migrations.

    Invokes the account service in migrate-only mode using the configured
    server root. Returns (ok, message).
    """
    root = cfg.get("server_root", "")
    if not root:
        return False, "未设置服务器根目录"
    exe_path = service_exe_path(root, "account")
    if not os.path.isfile(exe_path):
        return False, f"未找到 account 服务可执行文件: {exe_path}，请先在服务管理页构建"
    try:
        result = subprocess.run(
            [exe_path, "-migrate"],
            cwd=root,
            capture_output=True,
            timeout=600,
        )
    except FileNotFoundError:
        return False, "未找到可执行文件"
    except subprocess.TimeoutExpired:
        return False, "数据库初始化超时（10 分钟）"
    if result.returncode != 0:
        return False, f"数据库初始化失败:\n{result.stderr.decode('utf-8', 'replace')}"
    return True, "数据库初始化完成"


def build_service(cfg, name):
    root = cfg.get("server_root", "")
    if not root:
        return False, "未设置服务器根目录"
    if name not in SERVICES:
        return False, f"未知服务: {name}"
    source_dir = os.path.join(root, "services", SERVICES[name]["dir"])
    if not os.path.isdir(source_dir):
        return False, f"未找到源码目录: {source_dir}"

    out_path = service_exe_path(root, name)
    os.makedirs(bin_dir(root), exist_ok=True)
    try:
        result = subprocess.run(
            ["go", "build", "-o", out_path, "./cmd"],
            cwd=source_dir,
            capture_output=True,
            timeout=600,
        )
    except FileNotFoundError:
        return False, "未找到 go 命令，请确认已安装 Go 并加入 PATH"
    except subprocess.TimeoutExpired:
        return False, "构建超时（10 分钟）"
    if result.returncode != 0:
        return False, f"构建失败:\n{result.stderr.decode('utf-8', 'replace')}"
    return True, f"{name} 构建完成: {out_path}"
