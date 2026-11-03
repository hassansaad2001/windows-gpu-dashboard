"""Thin wrappers around Windows APIs: accounts, sessions, auth, notifications."""
import ctypes
import logging
import time
import winreg
from ctypes import wintypes
from functools import lru_cache

import pywintypes
import win32api
import win32con
import win32evtlog
import win32evtlogutil
import win32net
import win32netcon
import win32security
import win32service
import win32ts

from .config import CFG

log = logging.getLogger("aidash.win")

EVENT_SOURCE = "AIDashboard"
UF_ACCOUNTDISABLE = 0x0002
WTS_STATES = {0: "Active", 1: "Connected", 2: "ConnectQuery", 3: "Shadow", 4: "Disconnected",
              5: "Idle", 6: "Listen", 7: "Reset", 8: "Down", 9: "Init"}


def filetime_to_unix(ft: int):
    return None if not ft else (ft - 116444736000000000) / 1e7


def short_name(account: str) -> str:
    """'HOST\\user' -> 'user'."""
    return account.split("\\")[-1] if account else account


# ---------------------------------------------------------------- accounts

@lru_cache(maxsize=1)
def admin_group_name() -> str:
    sid = win32security.ConvertStringSidToSid(CFG["admin_group_sid"])
    return win32security.LookupAccountSid(None, sid)[0]


def local_users():
    users, resume = [], 0
    while True:
        data, _, resume = win32net.NetUserEnum(None, 2, win32netcon.FILTER_NORMAL_ACCOUNT, resume)
        for u in data:
            users.append({
                "name": u["name"],
                "full_name": u.get("full_name", ""),
                "disabled": bool(u["flags"] & UF_ACCOUNTDISABLE),
                "last_logon": u.get("last_logon") or None,
            })
        if not resume:
            break
    return users


def admin_members():
    """Direct members of the local Administrators group (short names)."""
    members, resume = [], 0
    while True:
        data, _, resume = win32net.NetLocalGroupGetMembers(None, admin_group_name(), 2, resume)
        members.extend(short_name(m["domainandname"]) for m in data)
        if not resume:
            break
    return members


def computer_name() -> str:
    """NetBIOS computer name, the prefix Windows uses for local accounts (HOST\\user)."""
    return win32api.GetComputerName()


def service_accounts():
    """Short names (lowercase) of the accounts Windows services log on as."""
    out = set()
    try:
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
    except pywintypes.error as e:
        log.warning("cannot list services: %s", e)
        return out
    try:
        for svc in win32service.EnumServicesStatus(scm, win32service.SERVICE_WIN32,
                                                   win32service.SERVICE_STATE_ALL):
            try:
                h = win32service.OpenService(scm, svc[0], win32service.SERVICE_QUERY_CONFIG)
                try:
                    start_name = win32service.QueryServiceConfig(h)[7]
                finally:
                    win32service.CloseServiceHandle(h)
            except pywintypes.error:
                continue
            if start_name:
                out.add(short_name(start_name.split("@")[0]).lower())
    finally:
        win32service.CloseServiceHandle(scm)
    return out


def is_admin(username: str) -> bool:
    try:
        groups = win32net.NetUserGetLocalGroups(None, username, win32netcon.LG_INCLUDE_INDIRECT)
    except pywintypes.error:
        return False
    return admin_group_name().lower() in (g.lower() for g in groups)


@lru_cache(maxsize=512)
def sid_to_name(sid_str: str) -> str:
    try:
        name, _domain, _type = win32security.LookupAccountSid(
            None, win32security.ConvertStringSidToSid(sid_str))
        return name
    except pywintypes.error:
        return ""


def profiles_directory() -> str:
    """Folder Windows creates user profiles in (ProfileList\\ProfilesDirectory)."""
    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as k:
            path, _ = winreg.QueryValueEx(k, "ProfilesDirectory")
        return win32api.ExpandEnvironmentStrings(path)
    except OSError:
        return win32api.ExpandEnvironmentStrings(r"%SystemDrive%\Users")


def profile_map():
    """Profile folder (lowercase path) -> (sid, username) from the registry ProfileList."""
    out = {}
    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            try:
                with winreg.OpenKey(root, sid) as k:
                    path, _ = winreg.QueryValueEx(k, "ProfileImagePath")
            except OSError:
                continue
            path = win32api.ExpandEnvironmentStrings(path)
            out[path.lower().rstrip("\\")] = (sid, sid_to_name(sid))
    return out


# ---------------------------------------------------------------- sessions

class WTSINFOW(ctypes.Structure):
    _fields_ = [
        ("State", ctypes.c_int), ("SessionId", wintypes.DWORD),
        ("IncomingBytes", wintypes.DWORD), ("OutgoingBytes", wintypes.DWORD),
        ("IncomingFrames", wintypes.DWORD), ("OutgoingFrames", wintypes.DWORD),
        ("IncomingCompressedBytes", wintypes.DWORD), ("OutgoingCompressedBytes", wintypes.DWORD),
        ("WinStationName", wintypes.WCHAR * 32), ("Domain", wintypes.WCHAR * 17),
        ("UserName", wintypes.WCHAR * 21),
        ("ConnectTime", ctypes.c_longlong), ("DisconnectTime", ctypes.c_longlong),
        ("LastInputTime", ctypes.c_longlong), ("LogonTime", ctypes.c_longlong),
        ("CurrentTime", ctypes.c_longlong),
    ]


_wtsapi = ctypes.WinDLL("wtsapi32")
_wtsapi.WTSQuerySessionInformationW.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.DWORD)]
_wtsapi.WTSFreeMemory.argtypes = [ctypes.c_void_p]
WTSSessionInfo = 24


def _session_info(session_id: int):
    buf, size = ctypes.c_void_p(), wintypes.DWORD()
    if not _wtsapi.WTSQuerySessionInformationW(None, session_id, WTSSessionInfo,
                                               ctypes.byref(buf), ctypes.byref(size)):
        return None
    try:
        return WTSINFOW.from_buffer_copy(ctypes.string_at(buf, ctypes.sizeof(WTSINFOW)))
    finally:
        _wtsapi.WTSFreeMemory(buf)


def sessions():
    """User sessions with state and idle time (seconds)."""
    out = []
    for s in win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE):
        sid = s["SessionId"]
        info = _session_info(sid)
        if not info or not info.UserName:
            continue
        now = filetime_to_unix(info.CurrentTime) or time.time()
        state = WTS_STATES.get(info.State, str(info.State))
        if state == "Disconnected" and info.DisconnectTime:
            idle = now - filetime_to_unix(info.DisconnectTime)
        elif info.LastInputTime:
            idle = now - filetime_to_unix(info.LastInputTime)
        else:
            idle = 0
        out.append({
            "session_id": sid,
            "username": info.UserName,
            "domain": info.Domain,
            "station": info.WinStationName or s["WinStationName"],
            "state": state,
            "logon_ts": filetime_to_unix(info.LogonTime),
            "idle_seconds": max(0, int(idle)),
        })
    return out


def logoff_session(session_id: int):
    win32ts.WTSLogoffSession(win32ts.WTS_CURRENT_SERVER_HANDLE, session_id, False)


def send_message(session_id: int, title: str, text: str):
    """Non-blocking popup in a user's session (like msg.exe)."""
    try:
        win32ts.WTSSendMessage(win32ts.WTS_CURRENT_SERVER_HANDLE, session_id, title, text,
                               win32con.MB_OK | win32con.MB_ICONWARNING, 60, False)
        return True
    except pywintypes.error as e:
        log.warning("WTSSendMessage to session %s failed: %s", session_id, e)
        return False


# ---------------------------------------------------------------- auth

def authenticate(username: str, password: str):
    """Validate local Windows credentials. Returns the canonical account name or None."""
    domain = "."
    if "\\" in username:
        domain, username = username.split("\\", 1)
    try:
        token = win32security.LogonUser(username, domain, password,
                                        win32con.LOGON32_LOGON_NETWORK,
                                        win32con.LOGON32_PROVIDER_DEFAULT)
    except pywintypes.error:
        return None
    try:
        user_sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
        return win32security.LookupAccountSid(None, user_sid)[0]
    finally:
        token.Close()


# ---------------------------------------------------------------- event log

def register_event_source():
    try:
        win32evtlogutil.AddSourceToRegistry(EVENT_SOURCE, "Application")
    except Exception as e:  # needs admin; harmless if already registered
        log.debug("AddSourceToRegistry: %s", e)


def write_event(event_id: int, message: str, level: str = "warning"):
    etype = {"info": win32evtlog.EVENTLOG_INFORMATION_TYPE,
             "warning": win32evtlog.EVENTLOG_WARNING_TYPE,
             "error": win32evtlog.EVENTLOG_ERROR_TYPE}[level]
    try:
        win32evtlogutil.ReportEvent(EVENT_SOURCE, event_id, eventType=etype, strings=[message])
    except Exception as e:
        log.warning("ReportEvent failed: %s", e)
