#!/usr/bin/env python3
"""
PE Triage Dashboard - local, static-only analysis of Windows PE samples.

  * NEVER executes the sample. Everything is parsing + disassembly.
  * The sample is held in memory only (never written to disk by this tool).
  * Binds to 127.0.0.1 only.

Run inside an isolated analysis VM (no shared folders, host-only or no network).

    pip install -r requirements.txt
    python pe_triage.py                      # then upload via the browser
    python pe_triage.py --sample bad.bin     # preload a sample
    python pe_triage.py --rules ./yara       # optional YARA rules (file or dir)
"""
import argparse
import base64
import collections
import csv
import io
import hashlib
import math
import json
import os
import re
import sqlite3
import struct
import threading
import time
import traceback

from flask import Flask, Response, jsonify, request

import pefile
from capstone import (CS_ARCH_X86, CS_GRP_CALL, CS_GRP_JUMP,
                      CS_GRP_RET, CS_MODE_32, CS_MODE_64, Cs)
from capstone.x86 import (X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_EBP,
                          X86_REG_ESP, X86_REG_RBP, X86_REG_RIP, X86_REG_RSP)

from lifter import Lifter, to_text
from triage_db import TriageDB

try:
    import yara  # optional
except ImportError:
    yara = None

# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------

API_CATEGORIES = {
    "crypto": """CryptAcquireContext CryptGenKey CryptDeriveKey CryptEncrypt CryptDecrypt
        CryptImportKey CryptExportKey CryptGenRandom CryptCreateHash CryptHashData
        CryptStringToBinary CryptBinaryToString CryptDestroyKey BCryptOpenAlgorithmProvider
        BCryptEncrypt BCryptDecrypt BCryptGenRandom BCryptGenerateSymmetricKey
        BCryptImportKeyPair BCryptImportKey BCryptExportKey BCryptGenerateKeyPair
        BCryptSetProperty NCryptEncrypt NCryptImportKey SystemFunction036 RtlGenRandom""",
    "ransom_ops": """RmStartSession RmRegisterResources RmGetList RmShutdown RmEndSession
        SystemParametersInfo SHEmptyRecycleBin Wow64DisableWow64FsRedirection
        SetVolumeMountPoint FindFirstVolume FindNextVolume GetVolumePathNamesForVolumeName""",
    "file_ops": """FindFirstFile FindFirstFileEx FindNextFile GetLogicalDrives
        GetLogicalDriveStrings GetDriveType GetVolumeInformation CreateFile ReadFile
        WriteFile SetFilePointer SetFilePointerEx MoveFile MoveFileEx CopyFile DeleteFile
        SetFileAttributes GetFileSize GetFileSizeEx SetEndOfFile FlushFileBuffers
        ReplaceFile CreateFileMapping MapViewOfFile NtCreateFile NtWriteFile""",
    "share_enum": """NetShareEnum NetServerEnum WNetOpenEnum WNetEnumResource
        WNetAddConnection2 GetIpNetTable GetAdaptersInfo NetWkstaGetInfo DsGetDcName""",
    "parallel_io": """CreateIoCompletionPort GetQueuedCompletionStatus
        PostQueuedCompletionStatus CreateThread WaitForMultipleObjects""",
    "network": """InternetOpen InternetConnect InternetOpenUrl HttpOpenRequest
        HttpSendRequest InternetReadFile WinHttpOpen WinHttpConnect WinHttpSendRequest
        WinHttpReadData URLDownloadToFile WSAStartup socket connect send recv
        gethostbyname getaddrinfo DnsQuery""",
    "process": """CreateProcess ShellExecute WinExec OpenProcess TerminateProcess
        CreateToolhelp32Snapshot Process32First Process32Next EnumProcesses
        CreateRemoteThread VirtualAllocEx WriteProcessMemory NtWriteVirtualMemory
        QueueUserAPC SetThreadContext ResumeThread NtUnmapViewOfSection""",
    "services": """OpenSCManager OpenService ControlService DeleteService
        ChangeServiceConfig EnumServicesStatus EnumServicesStatusEx CreateService
        EnumDependentServices""",
    "registry": """RegOpenKey RegCreateKey RegSetValue RegDeleteValue RegDeleteKey
        RegQueryValue""",
    "privilege": """OpenProcessToken AdjustTokenPrivileges LookupPrivilegeValue
        ImpersonateLoggedOnUser DuplicateToken DuplicateTokenEx CheckTokenMembership
        AllocateAndInitializeSid GetTokenInformation""",
    "anti_analysis": """IsDebuggerPresent CheckRemoteDebuggerPresent
        NtQueryInformationProcess OutputDebugString NtSetInformationThread
        GetTickCount GetTickCount64 QueryPerformanceCounter""",
    "geo_check": """GetUserDefaultUILanguage GetSystemDefaultUILanguage
        GetKeyboardLayoutList GetUserDefaultLangID GetSystemDefaultLangID GetLocaleInfo""",
    "dynamic_resolve": """LoadLibrary GetProcAddress LdrLoadDll LdrGetProcedureAddress
        GetModuleHandle""",
    "com_wmi": """CoCreateInstance CoInitializeEx CoInitializeSecurity CoSetProxyBlanket""",
}
API_WEIGHT = {"crypto": 6, "ransom_ops": 6, "file_ops": 2, "share_enum": 4,
              "parallel_io": 3, "network": 3, "process": 3, "services": 3,
              "registry": 2, "privilege": 2, "anti_analysis": 2, "geo_check": 3,
              "dynamic_resolve": 1, "com_wmi": 3}


def _norm_api(name):
    """Strip A/W/Ex suffixes so CreateFileW == CreateFile."""
    return re.sub(r"(ExA|ExW|Ex|A|W)$", "", name).lower()


_API_LOOKUP = {}
for _cat, _names in API_CATEGORIES.items():
    for _n in _names.split():
        _API_LOOKUP[_norm_api(_n)] = _cat


def api_category(name):
    return _API_LOOKUP.get(_norm_api(name))


STRING_RULES = [
    ("url", re.compile(r"https?://[^\s\"'<>]{4,}", re.I)),
    ("onion", re.compile(r"[a-z2-7]{16,56}\.onion", re.I)),
    ("ipv4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ("email", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")),
    ("btc", re.compile(r"^(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")),
    ("xmr", re.compile(r"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$")),
    ("registry", re.compile(r"HKEY_|HKLM|HKCU|SOFTWARE\\|SYSTEM\\CurrentControlSet", re.I)),
    ("shadow_backup", re.compile(r"vssadmin|shadowcopy|shadowstorage|wbadmin|bcdedit|"
                                 r"recoveryenabled|bootstatuspolicy|delete shadows|"
                                 r"Win32_ShadowCopy|catalog -quiet", re.I)),
    ("ransom_note", re.compile(r"your (?:files|data|network)|encrypted|decrypt|ransom|"
                               r"bitcoin|private key|tor browser|recover|leak|"
                               r"how_to|readme|restore", re.I)),
    ("crypto_ref", re.compile(r"BEGIN (?:RSA )?PUBLIC KEY|Microsoft Enhanced|RSA|AES|"
                              r"ChaCha|Salsa20|Curve25519|expand 32-byte k|NTRU|Sosemanuk", re.I)),
    ("command", re.compile(r"cmd(?:\.exe)? /c|powershell|schtasks|net stop|taskkill|"
                           r"\bsc (?:stop|config|delete)|icacls|attrib |wevtutil|"
                           r"fsutil|netsh", re.I)),
    ("kill_list", re.compile(r"^(?:sql|oracle|ocssd|dbsnmp|synctime|agntsvc|isqlplussvc|"
                             r"xfssvccon|mydesktopservice|ocautoupds|encsvc|firefox|"
                             r"tbirdconfig|ocomm|steam|thebat|thunderbird|visio|winword|"
                             r"wordpad|notepad|excel|onenote|outlook|powerpnt|veeam|"
                             r"backup|vss|msexchange|sophos|memtas|mepocs|svc\$)[\w.$-]{0,30}$", re.I)),
    ("path", re.compile(r"[a-z]:\\[^\s\"]{3,}|%[a-z]+%\\|\\\\\?\\", re.I)),
    ("extension", re.compile(r"^\*?\.[A-Za-z0-9]{2,8}$")),
    ("pdb", re.compile(r"\.pdb$", re.I)),
    ("base64", re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$")),
]
IOC_EXTRACT = {"url", "onion", "ipv4", "email"}           # pull the matching part out
IOC_WHOLE = {"btc", "xmr", "command", "shadow_backup", "kill_list",
             "extension", "registry", "pdb"}               # keep the whole string
STRING_WEIGHT = {"shadow_backup": 5, "ransom_note": 3, "crypto_ref": 3, "onion": 4,
                 "btc": 3, "xmr": 3, "command": 3, "kill_list": 2, "url": 2,
                 "ipv4": 1, "registry": 1, "extension": 1}

CRYPTO_CONSTANTS = [
    ("AES S-box", bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")),
    ("AES inverse S-box", bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb")),
    ("AES T-table Te0 (LE)", bytes.fromhex("a56363c6847c7cf8")),
    ("ChaCha/Salsa sigma 'expand 32-byte k'", b"expand 32-byte k"),
    ("ChaCha/Salsa tau 'expand 16-byte k'", b"expand 16-byte k"),
    ("SHA-256 initial hash (LE)", struct.pack("<II", 0x6A09E667, 0xBB67AE85)),
    ("SHA-256 round constants (LE)", struct.pack("<II", 0x428A2F98, 0x71374491)),
    ("SHA-512 initial hash (LE)", struct.pack("<Q", 0x6A09E667F3BCC908)),
    ("MD5/SHA-1 initial state (LE)", struct.pack("<II", 0x67452301, 0xEFCDAB89)),
    ("CRC32 table (LE)", struct.pack("<II", 0x00000000, 0x77073096)),
    ("Blowfish P-array (LE)", struct.pack("<II", 0x243F6A88, 0x85A308D3)),
    ("CryptoAPI RSA PUBLICKEYBLOB", b"\x06\x02\x00\x00\x00\xa4\x00\x00RSA1"),
    ("CryptoAPI RSA PRIVATEKEYBLOB", b"\x07\x02\x00\x00\x00\xa4\x00\x00RSA2"),
    ("Base64 alphabet", b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    ("Curve25519 basepoint", b"\x09" + b"\x00" * 31),
]

NOTE_WEIGHT = {"AES-NI": 6, "ChaCha rotations": 6, "Salsa20 rotations": 6,
               "xor-heavy": 1, "stack strings": 2, "direct syscall": 3,
               "rdtsc": 1, "cpuid": 1, "rdrand": 1, "int 2d (anti-debug)": 2}

MAX_FN_INSNS = 30000
MAX_FUNCTIONS = 40000
MIN_STR = 5
MAX_STRINGS = 60000
MAX_IMAGE = 256 * 1024 * 1024     # refuse PEs whose mapped image would exceed this
MAX_SECTIONS = 96


def entropy(buf):
    if not buf:
        return 0.0
    n = len(buf)
    return -sum(c / n * math.log2(c / n) for c in collections.Counter(buf).values())


def try_b64(text):
    """Decode a base64 string if the result is mostly readable text (configs, notes)."""
    if len(text) % 4:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:  # noqa: BLE001
        return None
    for enc in ("utf-8", "utf-16le"):
        try:
            out = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if out and sum(c.isprintable() or c in "\r\n\t" for c in out) / len(out) > 0.9:
            return out
    return None


def safe_str(b):
    if isinstance(b, bytes):
        return b.decode("utf-8", "replace")
    return str(b) if b is not None else ""


# --------------------------------------------------------------------------
# Sample model
# --------------------------------------------------------------------------

class Sample:
    def __init__(self, data, name, yara_rules=None):
        self.data = data
        self.name = name
        self.lock = threading.RLock()
        self.pe = pefile.PE(data=data, fast_load=False)
        pe = self.pe
        self.machine = pe.FILE_HEADER.Machine
        self.is64 = {0x14C: False, 0x8664: True}.get(self.machine)
        self.base = pe.OPTIONAL_HEADER.ImageBase
        self.mask = (1 << 64) - 1 if self.is64 else 0xFFFFFFFF
        self._sanity_check()
        self.image = pe.get_memory_mapped_image()
        self.entry = self.base + pe.OPTIONAL_HEADER.AddressOfEntryPoint

        self.exec_ranges = []
        for s in pe.sections:
            if s.Characteristics & 0x20000000:
                start = self.base + s.VirtualAddress
                self.exec_ranges.append((start, start + max(s.Misc_VirtualSize, s.SizeOfRawData)))

        if self.is64 is None:
            self.md = self.md_ui = None
        else:
            mode = CS_MODE_64 if self.is64 else CS_MODE_32
            self.md, self.md_ui = Cs(CS_ARCH_X86, mode), Cs(CS_ARCH_X86, mode)
            self.md.detail = self.md_ui.detail = True
        self.ui_lock = threading.Lock()

        self.labels = {}
        self.imports = {}           # IAT va -> "dll!func"
        self.import_list = []
        self._parse_imports()
        self._parse_exports()
        self.tls_callbacks = self._parse_tls()
        self.strings, self.str_by_va = self._extract_strings()
        self.constants = self._scan_constants()
        self.yara_hits = self._run_yara(yara_rules)
        self.overview = self._build_overview()
        self.embedded = self.carve_embedded()
        self.children = []            # embedded PEs registered in the DB (filled by load_sample)
        self.db_id = None
        self.on_done = None
        self.user_names, self.user_comments = {}, {}

        # analysis state
        self.functions = {}
        self.owner = {}                                   # insn va -> function start
        self.callers = collections.defaultdict(set)
        self.import_xrefs = collections.defaultdict(set)
        self.string_xrefs = collections.defaultdict(set)
        self.queue = collections.deque()
        self.queued = set()
        self.status = {"phase": "queued", "analyzed": 0, "queue": 0, "started": None,
                       "finished": None, "error": None, "version": 0}

    # -------------------- parsing --------------------

    def _sanity_check(self):
        """Reject headers crafted to exhaust memory before mapping the image."""
        pe = self.pe
        if len(pe.sections) > MAX_SECTIONS:
            raise ValueError(f"{len(pe.sections)} sections; refusing (limit {MAX_SECTIONS})")
        span = pe.OPTIONAL_HEADER.SizeOfImage
        for sec in pe.sections:
            span = max(span, sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData))
        if span > MAX_IMAGE:
            raise ValueError(f"Headers claim a {span / 2**20:.0f} MB image; refusing "
                             f"(limit {MAX_IMAGE // 2**20} MB). Likely malformed or anti-analysis.")

    def read(self, va, n):
        rva = va - self.base
        if rva < 0 or rva >= len(self.image):
            return b""
        return self.image[rva:rva + n]

    def is_exec(self, va):
        return any(a <= va < b for a, b in self.exec_ranges)

    def _parse_imports(self):
        pe = self.pe
        dirs = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dirs += [(e, False) for e in pe.DIRECTORY_ENTRY_IMPORT]
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            dirs += [(e, True) for e in pe.DIRECTORY_ENTRY_DELAY_IMPORT]
        for entry, delayed in dirs:
            dll = safe_str(entry.dll).lower()
            for imp in entry.imports:
                fname = safe_str(imp.name) if imp.name else f"ord_{imp.ordinal}"
                va = imp.address
                self.imports[va] = f"{dll}!{fname}"
                self.import_list.append({"va": va, "dll": dll, "name": fname,
                                         "delayed": delayed, "cat": api_category(fname)})

    def _parse_exports(self):
        self.exports = []
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                va = self.base + sym.address
                name = safe_str(sym.name) if sym.name else f"ordinal_{sym.ordinal}"
                self.exports.append({"va": va, "name": name})
                self.labels[va] = name
        self.labels[self.entry] = "entry_point"

    def _parse_tls(self):
        cbs = []
        if hasattr(self.pe, "DIRECTORY_ENTRY_TLS"):
            ptr = self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
            size = 8 if self.is64 else 4
            fmt = "<Q" if self.is64 else "<I"
            for i in range(64):
                raw = self.read(ptr + i * size, size)
                if len(raw) < size:
                    break
                cb = struct.unpack(fmt, raw)[0]
                if not cb:
                    break
                cbs.append(cb)
                self.labels[cb] = f"tls_callback_{i}"
        return cbs

    def _classify(self, text):
        return [cat for cat, rx in STRING_RULES if rx.search(text)]

    def _extract_strings(self):
        out, by_va = [], {}
        rx_a = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_STR)
        rx_u = re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % MIN_STR)
        for enc, rx in (("ascii", rx_a), ("utf16", rx_u)):
            for m in rx.finditer(self.data):
                if len(out) >= MAX_STRINGS:
                    break
                raw = m.group()
                text = raw.decode("ascii" if enc == "ascii" else "utf-16le", "replace")
                off = m.start()
                rva = self.pe.get_rva_from_offset(off)
                va = self.base + rva if rva is not None else None
                rec = {"id": len(out), "off": off, "va": va, "enc": enc,
                       "text": text[:2000], "cats": self._classify(text)}
                out.append(rec)
                if va is not None:
                    by_va[va] = rec["id"]
        return out, by_va

    def _scan_constants(self):
        hits = []
        for name, pat in CRYPTO_CONSTANTS:
            start, n = 0, 0
            while n < 8:
                off = self.data.find(pat, start)
                if off < 0:
                    break
                rva = self.pe.get_rva_from_offset(off)
                hits.append({"name": name, "off": off,
                             "va": self.base + rva if rva is not None else None})
                start, n = off + 1, n + 1
        return hits

    def _run_yara(self, rules):
        if not rules:
            return []
        try:
            return [{"rule": m.rule, "tags": list(m.tags), "meta": dict(m.meta)}
                    for m in rules.match(data=self.data)]
        except Exception as e:  # noqa: BLE001
            return [{"rule": "yara error", "tags": [], "meta": {"error": str(e)}}]

    def _build_overview(self):
        pe, d = self.pe, self.data
        oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
        dd = oh.DATA_DIRECTORY

        sections = []
        for s in pe.sections:
            raw = s.get_data()
            sections.append({
                "name": safe_str(s.Name.rstrip(b"\x00")),
                "va": self.base + s.VirtualAddress, "vsize": s.Misc_VirtualSize,
                "rsize": s.SizeOfRawData, "entropy": round(entropy(raw), 3),
                "r": bool(s.Characteristics & 0x40000000),
                "w": bool(s.Characteristics & 0x80000000),
                "x": bool(s.Characteristics & 0x20000000)})

        resources = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for t in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                tname = safe_str(t.name) if t.name else pefile.RESOURCE_TYPE.get(t.id, str(t.id))
                for e in getattr(t, "directory", None) and t.directory.entries or []:
                    ename = safe_str(e.name) if e.name else str(e.id)
                    for lang in getattr(e, "directory", None) and e.directory.entries or []:
                        rva, size = lang.data.struct.OffsetToData, lang.data.struct.Size
                        blob = pe.get_data(rva, min(size, 4 << 20))
                        resources.append({
                            "type": tname, "name": ename, "lang": lang.data.lang,
                            "size": size, "entropy": round(entropy(blob), 3),
                            "magic": blob[:4].hex(), "embedded_pe": blob[:2] == b"MZ"})

        pdb = None
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                ent = getattr(dbg, "entry", None)
                if ent is not None and hasattr(ent, "PdbFileName"):
                    pdb = safe_str(ent.PdbFileName.rstrip(b"\x00"))

        overlay_off = pe.get_overlay_data_start_offset()
        overlay = None
        if overlay_off:
            ov = d[overlay_off:]
            overlay = {"offset": overlay_off, "size": len(ov), "entropy": round(entropy(ov), 3)}

        try:
            imphash = pe.get_imphash()
        except Exception:  # noqa: BLE001
            imphash = None

        # packer / obfuscation heuristics
        packer = []
        names = [s["name"].lower() for s in sections]
        if any(n.startswith("upx") for n in names):
            packer.append("UPX section names")
        if any(n in (".aspack", ".adata", ".petite", ".nsp0", ".mpress1", ".themida", ".vmp0", ".vmp1", ".enigma1") for n in names):
            packer.append("Known packer/protector section name")
        for s in sections:
            if s["x"] and s["entropy"] > 7.2:
                packer.append(f"High-entropy executable section {s['name']} ({s['entropy']})")
            if s["w"] and s["x"]:
                packer.append(f"Writable + executable section {s['name']}")
            if s["rsize"] == 0 and s["vsize"] > 0x10000 and s["x"]:
                packer.append(f"Empty-on-disk executable section {s['name']} (unpacks at runtime)")
        if len(self.import_list) < 15:
            packer.append(f"Very small import table ({len(self.import_list)} imports)")
        if not self.is_exec(self.entry):
            packer.append("Entry point is not in an executable section")
        for r in resources:
            if r["embedded_pe"]:
                packer.append(f"Embedded PE in resource {r['type']}/{r['name']}")
            elif r["size"] > 4096 and r["entropy"] > 7.5:
                packer.append(f"High-entropy resource {r['type']}/{r['name']} ({r['entropy']})")
        if overlay and overlay["size"] > 4096 and overlay["entropy"] > 7.5:
            packer.append("High-entropy overlay")

        notes = []
        if dd[14].Size:
            notes.append(".NET assembly: native disassembly is mostly meaningless; use dnSpyEx/ILSpy for IL.")
        if self.is64 is None:
            notes.append(f"Machine 0x{self.machine:X} is not x86/x64; disassembly disabled.")

        return {
            "name": self.name, "size": len(d),
            "md5": hashlib.md5(d).hexdigest(), "sha1": hashlib.sha1(d).hexdigest(),
            "sha256": hashlib.sha256(d).hexdigest(), "imphash": imphash,
            "entropy": round(entropy(d), 3),
            "arch": "x64" if self.is64 else ("x86" if self.is64 is False else f"0x{self.machine:X}"),
            "dll": bool(fh.Characteristics & 0x2000),
            "timestamp": fh.TimeDateStamp,
            "timestamp_utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(fh.TimeDateStamp)),
            "image_base": self.base, "entry": self.entry, "subsystem": oh.Subsystem,
            "linker": f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}",
            "aslr": bool(oh.DllCharacteristics & 0x40), "dep": bool(oh.DllCharacteristics & 0x100),
            "signed": bool(dd[4].Size), "pdb": pdb, "overlay": overlay,
            "sections": sections, "resources": resources, "exports": self.exports,
            "tls_callbacks": self.tls_callbacks, "packer": packer, "notes": notes,
            "constants": self.constants, "yara": self.yara_hits,
            "warnings": pe.get_warnings()[:20],
        }

    # -------------------- disassembly helpers --------------------

    def label(self, va):
        return self.user_names.get(va) or self.labels.get(va) or f"sub_{va:X}"

    def _refs(self, ins):
        out = []
        for op in ins.operands:
            if op.type == X86_OP_IMM:
                out.append(("imm", op.imm & self.mask))
            elif op.type == X86_OP_MEM:
                if op.mem.base == X86_REG_RIP:
                    out.append(("mem", (ins.address + ins.size + op.mem.disp) & self.mask))
                elif op.mem.base == 0 and op.mem.index == 0:
                    out.append(("mem", op.mem.disp & self.mask))
        return out

    def annotate(self, ins):
        """Return (comment, code_target, api, string_id) for one instruction."""
        comment, target, api, sid = [], None, None, None
        is_branch = ins.group(CS_GRP_CALL) or ins.group(CS_GRP_JUMP)
        for kind, a in self._refs(ins):
            if a in self.imports:
                api = self.imports[a]
                comment.append(api)
            elif a in self.str_by_va:
                sid = self.str_by_va[a]
                t = self.strings[sid]["text"]
                comment.append(repr(t[:80] + ("…" if len(t) > 80 else "")))
            elif kind == "imm" and is_branch and self.is_exec(a):
                target = a
                if a in self.labels or a in self.functions:
                    comment.append(self.label(a))
        return "; ".join(comment), target, api, sid

    # -------------------- auto-analysis --------------------

    def add_seed(self, va, name=None):
        if va is None or not self.is_exec(va) or va in self.queued:
            return
        if len(self.queued) >= MAX_FUNCTIONS:
            return
        self.queued.add(va)
        self.queue.append(va)
        if name:
            self.labels.setdefault(va, name)

    def run(self):
        st = self.status
        st["started"] = time.time()
        try:
            if self.md is None:
                st["phase"] = "skipped (unsupported architecture)"
                return
            st["phase"] = "recursive descent"
            self.add_seed(self.entry, "entry_point")
            for cb in self.tls_callbacks:
                self.add_seed(cb)
            for e in self.exports:
                self.add_seed(e["va"], e["name"])
            if hasattr(self.pe, "DIRECTORY_ENTRY_EXCEPTION"):
                for e in self.pe.DIRECTORY_ENTRY_EXCEPTION:
                    self.add_seed(self.base + e.struct.BeginAddress)
            self._drain()
            st["phase"] = "prologue scan"
            for va in self._prologue_seeds():
                self.add_seed(va)
            self._drain()
            if self.on_done:
                st["phase"] = "saving to database"
                self.on_done()
            st["phase"] = "done"
        except Exception as e:  # noqa: BLE001
            st["phase"], st["error"] = "error", f"{e}\n{traceback.format_exc()}"
        finally:
            st["finished"] = time.time()
            st["version"] += 1

    def _drain(self):
        st = self.status
        while self.queue:
            va = self.queue.popleft()
            if va not in self.functions and va not in self.owner:
                self.analyze_function(va)
            st["queue"] = len(self.queue)
            st["analyzed"] = len(self.functions)

    def _prologue_seeds(self):
        if self.is64:
            pats = [b"\x48\x89\x5c\x24", b"\x48\x83\xec", b"\x40\x53\x48\x83\xec",
                    b"\x48\x8b\xc4", b"\x40\x55", b"\x48\x89\x4c\x24", b"\x4c\x8b\xdc"]
        else:
            pats = [b"\x55\x8b\xec", b"\x55\x89\xe5"]
        found = set()
        for a, b in self.exec_ranges:
            blob = self.read(a, b - a)
            for pat in pats:
                i = blob.find(pat)
                while i >= 0:
                    va = a + i
                    prev = blob[i - 1] if i else 0xCC
                    if va not in self.owner and prev in (0xCC, 0x90, 0xC3) and (not self.is64 or va % 16 == 0):
                        found.add(va)
                    i = blob.find(pat, i + 1)
        return sorted(found)

    def analyze_function(self, start):
        md = self.md
        fn = {"start": start, "end": start, "insns": 0, "blocks": 0, "calls": set(),
              "apis": collections.Counter(), "strings": set(), "notes": collections.Counter(),
              "stack_strings": [], "xor_nonzero": 0}
        rot = collections.Counter()
        seen, work = set(), [start]
        bp_regs = (X86_REG_EBP, X86_REG_ESP, X86_REG_RBP, X86_REG_RSP)

        while work and len(seen) < MAX_FN_INSNS:
            addr = work.pop()
            if addr in seen or not self.is_exec(addr):
                continue
            if addr != start and addr in self.functions:      # tail-jump into known fn
                fn["calls"].add(addr)
                continue
            fn["blocks"] += 1
            cur, run = addr, []
            while True:
                code = self.read(cur, 0x1000)
                if not code:
                    break
                terminated, last = False, cur
                for ins in md.disasm(code, cur):
                    last = ins.address + ins.size
                    if ins.address in seen:
                        terminated = True
                        break
                    seen.add(ins.address)
                    mn = ins.mnemonic
                    _c, target, api, sid = self.annotate(ins)
                    if api:
                        fn["apis"][api] += 1
                    if sid is not None:
                        fn["strings"].add(sid)

                    # --- instruction-level heuristics
                    if mn.startswith("aes"):
                        fn["notes"]["AES-NI"] += 1
                    elif mn in ("rol", "ror") and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_IMM:
                        bits = ins.operands[0].size * 8
                        amt = ins.operands[1].imm % bits
                        rot[amt if mn == "rol" else (bits - amt) % bits] += 1
                    elif mn == "xor" and len(ins.operands) == 2 and ins.op_str.split(",")[0].strip() != ins.op_str.split(",")[-1].strip():
                        fn["xor_nonzero"] += 1
                    elif mn in ("syscall", "sysenter"):
                        fn["notes"]["direct syscall"] += 1
                    elif mn in ("rdtsc", "cpuid", "rdrand"):
                        fn["notes"][mn] += 1
                    elif mn == "int" and ins.op_str.strip() == "0x2d":
                        fn["notes"]["int 2d (anti-debug)"] += 1

                    # --- stack-string reconstruction
                    ops = ins.operands
                    if (mn == "mov" and len(ops) == 2 and ops[0].type == X86_OP_MEM
                            and ops[0].mem.base in bp_regs and ops[1].type == X86_OP_IMM
                            and ops[0].size in (1, 2, 4)):
                        sz = ops[0].size
                        run.append((ops[0].mem.disp, (ops[1].imm & ((1 << (sz * 8)) - 1)).to_bytes(sz, "little")))
                    else:
                        self._flush_stack_string(run, fn)
                        run = []

                    # --- control flow
                    if ins.group(CS_GRP_RET) or mn in ("int3", "hlt", "ud2"):
                        terminated = True
                        break
                    if ins.group(CS_GRP_CALL):
                        if target is not None:
                            fn["calls"].add(target)
                            self.add_seed(target)
                        continue
                    if ins.group(CS_GRP_JUMP):
                        if mn == "jmp":
                            if target is not None:
                                if target in self.queued and target != start:
                                    fn["calls"].add(target)       # tail call
                                else:
                                    work.append(target)
                            terminated = True
                            break
                        if target is not None:
                            work.append(target)
                if terminated or last <= cur or last < cur + len(code) - 16:
                    break     # finished block, or hit undecodable bytes
                cur = last    # chunk exhausted mid-block; keep going
            self._flush_stack_string(run, fn)

        # rotations -> ChaCha/Salsa fingerprints
        if sum(rot[k] for k in (16, 12, 8, 7)) >= 8 and all(rot[k] for k in (16, 12, 8, 7)):
            fn["notes"]["ChaCha rotations"] += 1
        if sum(rot[k] for k in (7, 9, 13, 18)) >= 8 and all(rot[k] for k in (7, 9, 13, 18)):
            fn["notes"]["Salsa20 rotations"] += 1
        if fn["xor_nonzero"] >= 8:
            fn["notes"]["xor-heavy"] += 1
        if fn["stack_strings"]:
            fn["notes"]["stack strings"] += len(fn["stack_strings"])

        fn["insns"] = len(seen)
        if seen:
            fn["end"] = max(seen)
        if len(seen) <= 2 and len(fn["apis"]) == 1 and not fn["calls"]:
            self.labels.setdefault(start, "j_" + next(iter(fn["apis"])).split("!")[-1])
        fn["score"], fn["tags"] = self._score(fn)

        with self.lock:
            self.functions[start] = fn
            for a in seen:
                self.owner.setdefault(a, start)
            for c in fn["calls"]:
                self.callers[c].add(start)
            for api in fn["apis"]:
                self.import_xrefs[api].add(start)
            for sid in fn["strings"]:
                self.string_xrefs[sid].add(start)
            self.status["version"] += 1

    def _flush_stack_string(self, run, fn):
        if len(run) < 3:
            return
        buf = b"".join(b for _, b in sorted(run))
        for enc in ("utf-16le", "ascii"):
            try:
                txt = buf.decode(enc).split("\x00")[0]
            except UnicodeDecodeError:
                continue
            if len(txt) >= 4 and all(32 <= ord(c) < 127 for c in txt):
                fn["stack_strings"].append(txt)
                return

    def _score(self, fn):
        score, tags = 0, set()
        cats = collections.Counter()
        for api in fn["apis"]:
            c = api_category(api.split("!")[-1])
            if c:
                cats[c] += 1
        for c in cats:
            score += API_WEIGHT.get(c, 1)
            tags.add(c)
        for n in fn["notes"]:
            score += NOTE_WEIGHT.get(n, 1)
            tags.add(n)
        for sid in fn["strings"]:
            for c in self.strings[sid]["cats"]:
                if c in STRING_WEIGHT:
                    score += STRING_WEIGHT[c]
                    tags.add("str:" + c)
        return score, sorted(tags)

    # -------------------- embedded executables --------------------

    def carve_embedded(self, limit=16):
        """Find complete PE files hidden inside this one (resources, overlay, data)."""
        d, out = self.data, []
        ov = self.overview["overlay"]["offset"] if self.overview["overlay"] else None
        i = d.find(b"MZ", 1)
        while i != -1 and len(out) < limit:
            nxt = i + 2
            try:
                lfa = struct.unpack_from("<I", d, i + 0x3C)[0]
                if 0x40 <= lfa < 0x1000 and d[i + lfa:i + lfa + 4] == b"PE\0\0":
                    fh = i + lfa + 4
                    nsec = struct.unpack_from("<H", d, fh + 2)[0]
                    opt_size = struct.unpack_from("<H", d, fh + 16)[0]
                    opt = fh + 20
                    magic = struct.unpack_from("<H", d, opt)[0]
                    if 1 <= nsec <= MAX_SECTIONS and magic in (0x10B, 0x20B):
                        end = struct.unpack_from("<I", d, opt + 60)[0]          # SizeOfHeaders
                        sec = opt + opt_size
                        for k in range(nsec):
                            rsize, rptr = struct.unpack_from("<II", d, sec + k * 40 + 16)
                            if rsize:
                                end = max(end, rptr + rsize)
                        dd = opt + (96 if magic == 0x10B else 112)
                        c_off, c_size = struct.unpack_from("<II", d, dd + 4 * 8)  # certificate
                        if c_size and end <= c_off <= end + 0x1000:
                            end = c_off + c_size
                        size = min(end, len(d) - i)
                        if size >= 0x200:
                            out.append({"offset": i, "size": size, "location": self._where(i, ov),
                                        "truncated": end > len(d) - i})
                            nxt = i + size
            except struct.error:
                pass
            i = d.find(b"MZ", nxt)
        return out

    def _where(self, off, overlay_off):
        if overlay_off is not None and off >= overlay_off:
            return "overlay"
        rsrc = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        for sec in self.pe.sections:
            if sec.PointerToRawData <= off < sec.PointerToRawData + sec.SizeOfRawData:
                name = safe_str(sec.Name.rstrip(b"\x00"))
                rva = self.pe.get_rva_from_offset(off)
                if rsrc.Size and rva is not None and rsrc.VirtualAddress <= rva < rsrc.VirtualAddress + rsrc.Size:
                    return f"resources ({name})"
                return f"section {name}"
        return "headers"

    # -------------------- rows for the database --------------------

    def indicators(self):
        rules = dict(STRING_RULES)
        out, seen = [], set()

        def add(kind, value, src, off):
            if value and (kind, value) not in seen:
                seen.add((kind, value))
                out.append((kind, value, src, off))

        if self.overview["pdb"]:
            add("pdb", self.overview["pdb"], "debug directory", None)
        for r in self.strings:
            src, t = f"string ({r['enc']})", r["text"]
            for c in r["cats"]:
                if c in IOC_EXTRACT:
                    for m in rules[c].findall(t):
                        add(c, m, src, r["off"])
                elif c in IOC_WHOLE:
                    add(c, t.strip()[:1000], src, r["off"])
                elif c == "ransom_note" and len(t) >= 60:
                    add("ransom_note_candidate", t[:4000], src, r["off"])
                elif c == "base64":
                    dec = try_b64(t)
                    if dec:
                        add("base64_decoded", dec[:2000], src, r["off"])
        with self.lock:
            fns = list(self.functions.items())
        for va, fn in fns:
            for ss in fn["stack_strings"]:
                add("stack_string", ss, f"function 0x{va:X}", None)
        for e in self.embedded:
            add("embedded_pe", f"{e['size']} bytes at 0x{e['offset']:X} in {e['location']}",
                "carver", e["offset"])
        return out

    def static_rows(self):
        o = self.overview
        return {
            "sections": [(x["name"], x["va"], x["vsize"], x["rsize"],
                          ("r" if x["r"] else "-") + ("w" if x["w"] else "-") + ("x" if x["x"] else "-"),
                          x["entropy"]) for x in o["sections"]],
            "resources": [(r["type"], r["name"], r["lang"], r["size"], r["entropy"], r["magic"],
                           int(r["embedded_pe"])) for r in o["resources"]],
            "imports": [(i["dll"], i["name"], i["va"], i["cat"], int(i["delayed"])) for i in self.import_list],
            "exports": [(e["name"], e["va"]) for e in self.exports],
            "strings": [(r["id"], r["off"], r["va"], r["enc"], r["text"], ",".join(r["cats"]))
                        for r in self.strings],
            "constants": [(c["name"], c["off"], c["va"]) for c in self.constants],
        }

    def analysis_rows(self):
        with self.lock:
            fns = list(self.functions.items())
        rows = {"functions": [], "calls": [], "api_calls": [], "string_refs": []}
        for va, fn in fns:
            rows["functions"].append((va, self.labels.get(va) or f"sub_{va:X}", fn["end"], fn["insns"],
                                      fn["blocks"], fn["score"], ",".join(fn["tags"]),
                                      json.dumps(dict(fn["notes"])), json.dumps(fn["stack_strings"])))
            rows["calls"] += [(va, c) for c in sorted(fn["calls"])]
            rows["api_calls"] += [(va, a, api_category(a.split("!")[-1]), n) for a, n in fn["apis"].items()]
            rows["string_refs"] += [(va, sid) for sid in sorted(fn["strings"])]
        return rows

    # -------------------- pseudo-C reconstruction --------------------

    def _neutral(self, ins):
        """Convert one capstone instruction to the lifter's neutral dict."""
        kind = tgt = None
        if ins.group(CS_GRP_CALL):
            kind = "call"
        elif ins.mnemonic == "jmp":
            kind = "jmp"
        elif ins.group(CS_GRP_JUMP):
            kind = "jcc"
        elif ins.group(CS_GRP_RET):
            kind = "ret"
        elif ins.mnemonic in ("int3", "hlt", "ud2") or (ins.mnemonic == "int" and ins.op_str.strip() == "0x29"):
            kind = "halt" if ins.mnemonic != "int" else None
        if kind in ("call", "jmp", "jcc"):
            for op in ins.operands:
                if op.type == X86_OP_IMM:
                    tgt = op.imm & self.mask
        ops = []
        for op in ins.operands:
            if op.type == X86_OP_REG:
                ops.append({"t": "reg", "reg": ins.reg_name(op.reg), "size": op.size})
            elif op.type == X86_OP_IMM:
                ops.append({"t": "imm", "v": op.imm & ((1 << (op.size * 8)) - 1) if op.size <= 8 else op.imm,
                            "size": op.size})
            else:
                m = op.mem
                abs_ = None
                if m.base == X86_REG_RIP:
                    abs_ = (ins.address + ins.size + m.disp) & self.mask
                elif m.base == 0 and m.index == 0:
                    abs_ = m.disp & self.mask
                ops.append({"t": "mem", "size": op.size, "disp": m.disp,
                            "base": ins.reg_name(m.base) if m.base else None,
                            "index": ins.reg_name(m.index) if m.index else None,
                            "scale": m.mem.scale if hasattr(m, "mem") else getattr(m, "scale", 1),
                            "abs": abs_})
        return {"a": ins.address, "n": ins.size, "m": ins.mnemonic, "text": ins.op_str,
                "kind": kind, "tgt": tgt, "ops": ops}

    def _lift_ctx(self):
        sample = self

        class LiftCtx:
            is64 = sample.is64

            def label(self, va):
                return sample.label(va)

            def import_name(self, va):
                name = sample.imports.get(va)
                return name.split("!")[-1] if name else None

            def string_at(self, va):
                sid = sample.str_by_va.get(va)
                if sid is None:
                    return None
                r = sample.strings[sid]
                return (r["text"], r["enc"])

            def is_func(self, va):
                return va in sample.functions or va in sample.labels

            def comment(self, va):
                return sample.user_comments.get(va)

        return LiftCtx()

    def decompile(self, start):
        """Disassemble a whole function body and lift it to pseudo-C."""
        if self.md is None:
            return None, "No disassembler for this architecture."
        with self.lock:
            fn = self.functions.get(start)
        if not fn:
            return None, "Function not analysed yet."
        end = fn["end"] + 16
        insns = {}
        with self.ui_lock:
            addr = start
            while addr <= end and len(insns) < MAX_FN_INSNS:
                code = self.read(addr, 0x400)
                if not code:
                    break
                progressed = False
                for ins in self.md_ui.disasm(code, addr):
                    if ins.address in insns:
                        progressed = True
                        break
                    insns[ins.address] = self._neutral(ins)
                    addr = ins.address + ins.size
                    progressed = True
                    if self.functions.get(ins.address) and ins.address != start:
                        break          # ran into the next function
                    if ins.group(CS_GRP_RET) and ins.address > fn["end"]:
                        break
                if not progressed:
                    addr += 1
        # keep only instructions that belong to this function's reachable body
        insns = {a: n for a, n in insns.items() if start <= a <= fn["end"] + 64}
        if not insns:
            return None, "Nothing to decompile."
        try:
            lines = Lifter(self._lift_ctx(), insns, start).run()
        except Exception as e:  # noqa: BLE001
            return None, f"Reconstruction failed: {e}\n{traceback.format_exc()}"
        return lines, None

    # -------------------- views for the API --------------------

    def fn_summary(self, va, fn):
        return {"va": va, "name": self.label(va), "score": fn["score"], "tags": fn["tags"],
                "insns": fn["insns"], "blocks": fn["blocks"]}

    def fn_detail(self, va):
        with self.lock:
            fn = self.functions.get(va)
            if not fn:
                return None
            callers = sorted(self.callers.get(va, ()))
        return {
            **self.fn_summary(va, fn),
            "end": fn["end"],
            "callers": [{"va": c, "name": self.label(c)} for c in callers],
            "callees": [{"va": c, "name": self.label(c)} for c in sorted(fn["calls"])],
            "apis": [{"name": a, "count": n, "cat": api_category(a.split("!")[-1])}
                     for a, n in fn["apis"].most_common()],
            "strings": [{"id": s, "text": self.strings[s]["text"][:200], "cats": self.strings[s]["cats"]}
                        for s in sorted(fn["strings"])],
            "stack_strings": fn["stack_strings"],
            "notes": dict(fn["notes"]),
        }

    def listing(self, va, count):
        out, cur, guard = [], va, 0
        with self.ui_lock:
            while len(out) < count and guard < count * 2:
                guard += 1
                code = self.read(cur, 0x800)
                if not code:
                    break
                progressed = False
                for ins in self.md_ui.disasm(code, cur):
                    comment, target, api, sid = self.annotate(ins)
                    row = {"va": ins.address, "bytes": ins.bytes.hex(), "mn": ins.mnemonic,
                           "ops": ins.op_str, "c": comment, "t": target, "api": bool(api),
                           "str": sid, "ret": bool(ins.group(CS_GRP_RET)),
                           "uc": self.user_comments.get(ins.address)}
                    if ins.address in self.functions or ins.address in self.labels:
                        row["fn"] = self.label(ins.address)
                        row["xrefs"] = len(self.callers.get(ins.address, ()))
                    out.append(row)
                    cur = ins.address + ins.size
                    progressed = True
                    if len(out) >= count:
                        break
                if not progressed:              # undecodable byte
                    out.append({"va": cur, "bytes": code[:1].hex(), "mn": "db",
                                "ops": f"0x{code[0]:02x}", "c": "", "t": None, "bad": True})
                    cur += 1
        return out, cur


# --------------------------------------------------------------------------
# Web app
# --------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024
STATE = {"sample": None, "rules": None, "db": None, "store_blob": True}


def load_sample(data, name, parent_id=None, parent_offset=None):
    """Parse, persist static results, register embedded PEs, start auto-analysis."""
    db = STATE["db"]
    s = Sample(data, name, STATE["rules"])
    s.db_id = db.upsert_sample(s, parent_id, parent_offset, STATE["store_blob"])
    db.save_static(s.db_id, s)
    s.user_names, s.user_comments = db.annotations(s.db_id)
    for e in s.embedded:
        child = dict(e)
        try:
            sub = Sample(data[e["offset"]:e["offset"] + e["size"]],
                         f"{name}@0x{e['offset']:X}.bin", STATE["rules"])
            child["id"] = db.upsert_sample(sub, s.db_id, e["offset"], STATE["store_blob"])
            db.save_static(child["id"], sub)
            child.update(sha256=sub.overview["sha256"], pdb=sub.overview["pdb"],
                         arch=sub.overview["arch"], signed=sub.overview["signed"],
                         dll=sub.overview["dll"])
        except Exception as ex:  # noqa: BLE001
            child["error"] = str(ex)
        s.children.append(child)
    s.on_done = lambda: db.save_analysis(s.db_id, s)
    STATE["sample"] = s
    threading.Thread(target=s.run, daemon=True).start()
    return s


def cur():
    return STATE["sample"]


def hexarg(name, default=None):
    v = request.args.get(name)
    if v is None:
        return default
    return int(v, 16)   # always hex; "0x" prefix optional


@app.route("/")
def index():
    return Response(PAGE, mimetype="text/html")


@app.post("/api/upload")
def upload():
    f = request.files.get("file")
    if not f:
        return jsonify(error="No file in request"), 400
    data = f.read()
    try:
        load_sample(data, os.path.basename(f.filename or "sample"))
    except pefile.PEFormatError as e:
        return jsonify(error=f"Not a valid PE file: {e}"), 400
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:  # noqa: BLE001  - never let a hostile file kill the server
        return jsonify(error=f"Parser failed on this file: {e}"), 400
    return jsonify(ok=True)


@app.get("/api/status")
def status():
    s = cur()
    if not s:
        return jsonify(loaded=False)
    return jsonify(loaded=True, **s.status, functions=len(s.functions))


@app.get("/api/overview")
def overview():
    s = cur()
    return jsonify(s.overview) if s else (jsonify(error="no sample"), 404)


@app.get("/api/functions")
def functions():
    s = cur()
    if not s:
        return jsonify([])
    with s.lock:
        items = list(s.functions.items())
    return jsonify([s.fn_summary(va, fn) for va, fn in items])


@app.get("/api/function")
def function():
    s = cur()
    d = s.fn_detail(hexarg("va")) if s else None
    return jsonify(d) if d else (jsonify(error="not analysed (yet)"), 404)


@app.get("/api/disasm")
def disasm():
    s = cur()
    if not s or not s.md_ui:
        return jsonify(error="no disassembler for this sample"), 400
    va = hexarg("va", s.entry)
    count = min(int(request.args.get("count", 200)), 2000)
    rows, nxt = s.listing(va, count)
    owner = s.owner.get(va)
    return jsonify(rows=rows, next=nxt, owner=owner,
                   owner_name=s.label(owner) if owner else None, exec=s.is_exec(va))


@app.get("/api/imports")
def imports():
    s = cur()
    if not s:
        return jsonify([])
    with s.lock:
        out = []
        for imp in s.import_list:
            key = f"{imp['dll']}!{imp['name']}"
            xr = sorted(s.import_xrefs.get(key, ()))
            out.append({**imp, "xrefs": [{"va": v, "name": s.label(v)} for v in xr[:50]]})
    return jsonify(out)


@app.get("/api/strings")
def strings():
    s = cur()
    if not s:
        return jsonify(total=0, rows=[])
    cat = request.args.get("cat") or ""
    q = (request.args.get("q") or "").lower()
    page = int(request.args.get("page", 0))
    size = 300
    rows = s.strings
    if cat == "_flagged":
        rows = [r for r in rows if r["cats"]]
    elif cat:
        rows = [r for r in rows if cat in r["cats"]]
    if q:
        rows = [r for r in rows if q in r["text"].lower()]
    total = len(rows)
    rows = rows[page * size:(page + 1) * size]
    with s.lock:
        res = [{**r, "xrefs": [{"va": v, "name": s.label(v)} for v in sorted(s.string_xrefs.get(r["id"], ()))[:20]]}
               for r in rows]
    counts = collections.Counter(c for r in s.strings for c in r["cats"])
    return jsonify(total=total, rows=res, page=page, size=size, counts=counts)


@app.get("/api/children")
def children():
    s = cur()
    return jsonify(s.children if s else [])


@app.get("/api/library")
def library():
    s = cur()
    return jsonify(samples=STATE["db"].list_samples(), current=s.db_id if s else None,
                   db=STATE["db"].path, fts=STATE["db"].fts)


@app.post("/api/open/<int:sid>")
def open_sample(sid):
    rec = STATE["db"].get_sample(sid)
    if not rec:
        return jsonify(error="No sample with that id"), 404
    if rec["data"] is None:
        return jsonify(error="This sample was stored without its file (--no-blob). Open the file again from disk."), 400
    try:
        load_sample(rec["data"], rec["name"], rec["parent_id"], rec["parent_offset"])
    except Exception as e:  # noqa: BLE001
        return jsonify(error=f"Could not open: {e}"), 400
    return jsonify(ok=True)


NAME_RX = re.compile(r"[A-Za-z_][\w@$?.:-]{0,120}")


@app.post("/api/annotate")
def annotate():
    s = cur()
    if not s:
        return jsonify(error="no sample"), 404
    j = request.get_json(force=True)
    va, kind, text = int(j["va"]), j.get("kind"), (j.get("text") or "").strip()[:500]
    if kind not in ("name", "comment"):
        return jsonify(error="kind must be name or comment"), 400
    if kind == "name" and text and not NAME_RX.fullmatch(text):
        return jsonify(error="Names can use letters, digits and _ @ $ ? . : - and must not start with a digit"), 400
    STATE["db"].set_annotation(s.db_id, va, kind, text)
    target = s.user_names if kind == "name" else s.user_comments
    if text:
        target[va] = text
    else:
        target.pop(va, None)
    s.status["version"] += 1
    return jsonify(ok=True)


@app.get("/api/iocs")
def iocs():
    s = cur()
    if not s:
        return jsonify([])
    return jsonify([{"kind": k, "value": v, "source": src, "offset": off}
                    for k, v, src, off in STATE["db"].iocs(s.db_id)])


@app.get("/api/iocs.csv")
def iocs_csv():
    s = cur()
    if not s:
        return jsonify(error="no sample"), 404
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["sha256", "kind", "value", "source", "file_offset"])
    for k, v, src, off in STATE["db"].iocs(s.db_id):
        w.writerow([s.overview["sha256"], k, v, src, f"0x{off:X}" if off is not None else ""])
    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": f"attachment; filename={s.overview['sha256'][:16]}_iocs.csv"})


@app.post("/api/sql")
def sql():
    q = (request.get_json(force=True).get("q") or "").strip()
    if not q:
        return jsonify(error="Write a query first"), 400
    params = None
    if ":sample" in q:
        s = cur()
        if not s:
            return jsonify(error=":sample needs an open sample"), 400
        params = {"sample": s.db_id}
    try:
        cols, rows, truncated = STATE["db"].query_readonly(q, params)
    except sqlite3.OperationalError as e:
        msg = "Query ran longer than 10 seconds and was stopped" if "interrupt" in str(e) else str(e)
        return jsonify(error=msg), 400
    except sqlite3.Error as e:
        return jsonify(error=str(e)), 400
    return jsonify(cols=cols, rows=rows, truncated=truncated)


@app.get("/api/pseudocode")
def pseudocode():
    s = cur()
    if not s:
        return jsonify(error="no sample"), 404
    va = hexarg("va")
    # optional: try angr for a much better result when the user asks and it's installed
    if request.args.get("engine") == "angr":
        out, err = angr_decompile(s, va)
        if out is not None:
            return jsonify(engine="angr", lines=None, text=out)
        return jsonify(error=err or "angr decompilation unavailable"), 400
    lines, err = s.decompile(va)
    if err:
        return jsonify(error=err), 400
    return jsonify(engine="builtin", lines=lines, text=to_text(lines),
                   name=s.label(va), va=va)


def angr_decompile(s, va):
    try:
        import angr  # noqa: F401
    except ImportError:
        return None, "angr is not installed. Install it with: pip install angr"
    try:
        import logging
        logging.getLogger("angr").setLevel(logging.ERROR)
        import angr
        proj = angr.Project(io.BytesIO(s.data), load_options={"auto_load_libs": False}, main_opts={"backend": "pe"})
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
        func = cfg.kb.functions.get_by_addr(va)
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        return (dec.codegen.text if dec.codegen else "// angr produced no output"), None
    except Exception as e:  # noqa: BLE001
        return None, f"angr failed on this function: {e}"


@app.get("/api/report")
def report():
    s = cur()
    if not s:
        return jsonify(error="no sample"), 404
    with s.lock:
        fns = sorted(s.functions.items(), key=lambda kv: -kv[1]["score"])
    top = [s.fn_detail(va) for va, fn in fns[:40] if fn["score"] > 0]
    flagged = [r for r in s.strings if r["cats"]]
    resp = jsonify(overview=s.overview, status=s.status, top_functions=top,
                   imports=s.import_list, flagged_strings=flagged[:5000])
    resp.headers["Content-Disposition"] = f"attachment; filename={s.overview['sha256'][:16]}_report.json"
    return resp


# --------------------------------------------------------------------------
# Front-end (single page, no external assets so it works offline in a VM)
# --------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PE Triage</title>
<style>
:root{
  --bg:#18202e; --panel:#1f2939; --raise:#273246; --line:#33405a;
  --text:#dde3ee; --muted:#8c98b0; --amber:#f0b44c; --red:#ee6b66;
  --teal:#5ccbd8; --violet:#b9a3e3; --green:#93d48f;
  --mono:"IBM Plex Mono","JetBrains Mono","Cascadia Code",Consolas,monospace;
  --sans:"IBM Plex Sans","Segoe UI",system-ui,sans-serif;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--text);font:14px/1.45 var(--sans);display:grid;
  grid-template-rows:auto 1fr;grid-template-columns:300px 1fr;grid-template-areas:"top top" "side main"}
button,input,select{font:inherit;color:inherit}
button{background:var(--raise);border:1px solid var(--line);border-radius:4px;padding:4px 10px;cursor:pointer}
button:hover{border-color:var(--teal)}
:focus-visible{outline:2px solid var(--teal);outline-offset:1px}
input,select{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:4px 8px}
a{color:var(--teal)}
header{grid-area:top;display:flex;gap:16px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{font-size:16px;margin:0;font-weight:600;letter-spacing:.01em}
#sname{font-family:var(--mono);color:var(--muted);font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:32ch}
#prog{flex:1;display:flex;align-items:center;gap:10px;color:var(--muted);font-size:13px}
#bar{flex:0 0 160px;height:6px;background:var(--bg);border-radius:3px;overflow:hidden}
#bar i{display:block;height:100%;width:0;background:var(--teal);transition:width .4s}
aside{grid-area:side;border-right:1px solid var(--line);display:flex;flex-direction:column;min-height:0}
aside .head{padding:10px;display:flex;gap:6px;border-bottom:1px solid var(--line)}
aside .head input{flex:1;min-width:0}
#fnlist{overflow:auto;flex:1}
.fn{display:grid;grid-template-columns:6px 1fr auto;gap:8px;align-items:center;padding:3px 10px 3px 0;cursor:pointer;font-family:var(--mono);font-size:12.5px}
.fn:hover,.fn.sel{background:var(--raise)}
.fn .heat{align-self:stretch}
.fn .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fn .sc{color:var(--muted);font-size:11.5px}
main{grid-area:main;display:flex;flex-direction:column;min-height:0;min-width:0}
nav{display:flex;gap:2px;padding:0 12px;border-bottom:1px solid var(--line)}
nav button{border:0;border-bottom:2px solid transparent;border-radius:0;background:none;padding:10px 12px;color:var(--muted)}
nav button.on{color:var(--text);border-bottom-color:var(--amber)}
.view{display:none;overflow:auto;padding:16px 20px;flex:1;min-height:0}
.view.on{display:block}
h2{font-size:15px;margin:22px 0 8px;font-weight:600}
h2:first-child{margin-top:0}
table{border-collapse:collapse;width:100%;font-size:13px}
td,th{text-align:left;padding:4px 10px 4px 0;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}
.mono{font-family:var(--mono);font-size:12.5px}
.kv td:first-child{color:var(--muted);width:150px}
.tag{display:inline-block;border:1px solid var(--line);border-radius:3px;padding:0 5px;margin:1px 3px 1px 0;font-size:11.5px;color:var(--muted)}
.tag.hot{color:var(--red);border-color:#6e3a40}
.tag.warm{color:var(--amber);border-color:#6b5531}
.flag{color:var(--amber)}
.ent{display:inline-block;width:80px;height:6px;background:var(--bg);border-radius:3px;vertical-align:middle;margin-right:6px}
.ent i{display:block;height:100%;border-radius:3px}
.empty{color:var(--muted);padding:40px 0;max-width:60ch}
.drop{border:1px dashed var(--line);border-radius:6px;padding:30px;text-align:center;margin-top:16px}
.drop.over{border-color:var(--teal)}
.lnk{color:var(--teal);cursor:pointer;font-family:var(--mono)}
.lnk:hover{text-decoration:underline}
/* disassembly */
#dview{display:none;flex:1;min-height:0}
#dview.on{display:grid;grid-template-columns:1fr 340px}
#dleft{display:flex;flex-direction:column;min-width:0;min-height:0}
#dbar{display:flex;gap:6px;align-items:center;padding:8px 14px;border-bottom:1px solid var(--line)}
#dbar input{width:18ch;font-family:var(--mono)}
#dloc{color:var(--muted);font-size:13px;margin-left:8px}
#listing{overflow:auto;flex:1;font-family:var(--mono);font-size:12.5px;padding:6px 0 40px}
.r{display:grid;grid-template-columns:15ch 20ch 9ch 1fr;gap:10px;padding:0 14px;white-space:pre}
.r:hover{background:var(--panel)}
.r .a{color:var(--muted)}
.r .b{color:#5d6a83;overflow:hidden;text-overflow:ellipsis}
.r .m{color:var(--text)}
.r .o{overflow:hidden;text-overflow:ellipsis}
.r .cm{color:var(--muted)}
.r.api .cm{color:var(--green)}
.r.s .cm{color:var(--violet)}
.r.bad{color:var(--red)}
.r.cur{background:#2a3550}
.r.sep{border-bottom:1px dashed var(--line);margin-bottom:6px;padding-bottom:4px}
.fh{padding:12px 14px 4px;color:var(--amber);font-weight:600}
.fh small{color:var(--muted);font-weight:400;margin-left:10px}
#side{border-left:1px solid var(--line);overflow:auto;padding:14px;font-size:13px}
#side h3{font-size:13px;margin:16px 0 6px;color:var(--muted);font-weight:500}
#side h3:first-child{margin-top:0}
#side .big{font-family:var(--mono);font-size:15px;color:var(--amber);word-break:break-all}
#side ul{list-style:none;margin:0;padding:0}
#side li{padding:2px 0;word-break:break-all}
#sentinel{height:1px}
.r .a{cursor:pointer}
.r .a:hover{color:var(--amber)}
.uc{color:var(--amber)}
.r.cmt{background:rgba(240,180,76,.06)}
textarea{width:100%;min-height:120px;background:var(--bg);color:var(--text);border:1px solid var(--line);border-radius:4px;padding:8px;font:12.5px/1.5 var(--mono);resize:vertical}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0}
.err{color:var(--red);white-space:pre-wrap}
.longtext{white-space:pre-wrap;word-break:break-word;max-width:90ch;font-family:var(--mono);font-size:12.5px}
.child td:first-child{padding-left:22px}
.muted{color:var(--muted)}
#sqlout{overflow:auto;margin-top:10px}
#pc{display:none;flex-direction:column;border-top:1px solid var(--line);min-height:0}
#pc.on{display:flex;flex:0 0 45%}
#pcbar{display:flex;gap:8px;align-items:center;padding:6px 14px;border-bottom:1px solid var(--line)}
#pcbar .muted{font-size:12px}
#pccode{overflow:auto;flex:1;margin:0;padding:10px 14px 30px;font-family:var(--mono);font-size:12.5px;line-height:1.5;white-space:pre}
#pccode .kw{color:var(--violet)}#pccode .fn{color:var(--teal)}#pccode .str{color:var(--green)}
#pccode .num{color:var(--amber)}#pccode .cm{color:var(--muted)}#pccode .lbl{color:var(--red)}
#dleft{position:relative}
.seg{display:flex;border:1px solid var(--line);border-radius:4px;overflow:hidden}
.seg button{border:0;border-radius:0;background:var(--bg);padding:3px 10px}
.seg button.on{background:var(--raise);color:var(--amber)}
@media (max-width:900px){body{grid-template-columns:1fr;grid-template-areas:"top" "main"}aside{display:none}#dview.on{grid-template-columns:1fr}#side{display:none}}
@media (prefers-reduced-motion:reduce){#bar i{transition:none}}
</style></head>
<body>
<header>
  <h1>PE Triage</h1><span id="sname">no sample loaded</span>
  <div id="prog"><div id="bar"><i></i></div><span id="ptxt"></span></div>
  <button type="button" onclick="document.getElementById('file').click()">Open sample</button>
  <input type="file" id="file" hidden>
  <a id="rep" href="/api/report" hidden>Export report</a>
</header>
<aside>
  <div class="head"><input id="ffilter" placeholder="Filter functions or tags"><select id="fsort"><option value="score">By score</option><option value="va">By address</option></select></div>
  <div id="fnlist"></div>
</aside>
<main>
  <nav id="tabs">
    <button data-v="ov" class="on">Overview</button><button data-v="ind">Indicators</button>
    <button data-v="imp">Imports</button><button data-v="str">Strings</button><button data-v="dis">Disassembly</button>
    <button data-v="iocs">IOCs</button><button data-v="lib">Library</button><button data-v="sql">SQL</button>
  </nav>
  <section class="view on" id="ov"><div class="empty">
    <p>Open a Windows PE sample to start. Analysis is static only: the file is parsed and disassembled in memory and is never run or written to disk.</p>
    <p>Work inside an isolated VM with networking off.</p>
    <div class="drop" id="drop">Drop a file here</div></div></section>
  <section class="view" id="ind"></section>
  <section class="view" id="imp"></section>
  <section class="view" id="str"></section>
  <section class="view" id="iocs"></section>
  <section class="view" id="lib"></section>
  <section class="view" id="sql"></section>
  <section id="dview">
    <div id="dleft">
      <div id="dbar"><button id="back" title="Back (Alt+Left)">Back</button>
        <input id="goto" placeholder="Address (hex)"><button id="gobtn">Go</button>
        <button id="goep">Entry point</button>
        <button id="pctoggle" title="Reconstruct pseudo-C for this function">Pseudocode</button>
        <span id="dloc"></span></div>
      <div id="listing"></div>
      <div id="pc"><div id="pcbar">
        <strong id="pcname" class="mono"></strong>
        <div class="seg"><button data-eng="builtin" class="on">Built-in</button><button data-eng="angr">angr</button></div>
        <span id="pcmeta" class="muted"></span><span style="flex:1"></span>
        <button id="pccopy">Copy</button><button id="pcclose">Close</button></div>
        <pre id="pccode"></pre></div>
    </div>
    <div id="side"><div class="empty">Select a function to see its callers, callees, API calls and strings.</div></div>
  </section>
</main>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hx=v=>v==null?'—':'0x'+Number(v).toString(16).toUpperCase();
const get=async p=>{const r=await fetch(p);return r.json()};
const HOT=new Set(['crypto','ransom_ops','AES-NI','ChaCha rotations','Salsa20 rotations','str:shadow_backup','str:ransom_note','str:onion']);
const WARM=new Set(['file_ops','share_enum','parallel_io','network','process','services','geo_check','com_wmi','str:crypto_ref','str:command','str:kill_list','direct syscall','stack strings','anti_analysis']);
const tag=t=>`<span class="tag ${HOT.has(t)?'hot':WARM.has(t)?'warm':''}">${esc(t)}</span>`;
let UC={},curAddr=null,FNS=[],OV=null,lastVer=-1,lastFnCount=-1,hist=[],dNext=null,dLoading=false,curFn=null,strPage=0;

/* tabs */
function show(v){
  document.querySelectorAll('#tabs button').forEach(b=>b.classList.toggle('on',b.dataset.v===v));
  document.querySelectorAll('.view').forEach(e=>e.classList.toggle('on',e.id===v));
  $('#dview').classList.toggle('on',v==='dis');
  if(v==='imp')loadImports(); if(v==='str')loadStrings(); if(v==='ind')renderInd();
  if(v==='iocs')loadIocs(); if(v==='lib')loadLib(); if(v==='sql')renderSql();
}
$('#tabs').onclick=e=>{if(e.target.dataset.v)show(e.target.dataset.v)};

/* upload */
async function upload(file){
  const fd=new FormData();fd.append('file',file);
  $('#ptxt').textContent='Parsing…';
  const r=await fetch('/api/upload',{method:'POST',body:fd});const j=await r.json();
  if(j.error){$('#ptxt').textContent=j.error;return}
  lastVer=-1;lastFnCount=-1;hist=[];await refreshAll();
}
$('#file').onchange=e=>e.target.files[0]&&upload(e.target.files[0]);
document.addEventListener('dragover',e=>{e.preventDefault();$('#drop')?.classList.add('over')});
document.addEventListener('dragleave',()=>$('#drop')?.classList.remove('over'));
document.addEventListener('drop',e=>{e.preventDefault();const f=e.dataTransfer.files[0];if(f)upload(f)});

async function refreshAll(){
  OV=await get('/api/overview'); if(OV.error)return;
  lastFnCount=-1;hist=[];dNext=null;curFn=null;strPage=0;UC={};
  $('#sname').textContent=OV.name; $('#rep').hidden=false;
  renderOverview(); poll(); openAt(OV.entry,false);
}

/* status polling */
async function poll(){
  const s=await get('/api/status'); if(!s.loaded)return;
  const total=s.functions+s.queue, pct=s.phase==='done'?100:total?Math.round(s.functions/total*100):0;
  $('#bar i').style.width=pct+'%';
  $('#ptxt').textContent=`${s.phase} · ${s.functions} functions`+(s.queue?` · ${s.queue} queued`:'')+(s.error?' · error, see console':'');
  if(s.error)console.error(s.error);
  if(s.functions!==lastFnCount){lastFnCount=s.functions;FNS=await get('/api/functions');renderFns()}
  if(s.phase!=='done'&&!s.phase.startsWith('error')&&!s.phase.startsWith('skipped'))setTimeout(poll,1500);
  else if(document.querySelector('#ind.on'))renderInd();
}

/* function sidebar */
function heatColor(sc){if(sc>=12)return'var(--red)';if(sc>=6)return'var(--amber)';if(sc>0)return'#6b7a96';return'transparent'}
function renderFns(){
  const q=$('#ffilter').value.toLowerCase(), by=$('#fsort').value;
  let l=FNS.filter(f=>!q||f.name.toLowerCase().includes(q)||f.tags.some(t=>t.toLowerCase().includes(q))||hx(f.va).toLowerCase().includes(q));
  l.sort(by==='score'?(a,b)=>b.score-a.score||a.va-b.va:(a,b)=>a.va-b.va);
  $('#fnlist').innerHTML=l.slice(0,3000).map(f=>`<div class="fn${f.va===curFn?' sel':''}" data-va="${f.va}" title="${esc(f.tags.join(', '))}"><span class="heat" style="background:${heatColor(f.score)}"></span><span class="nm">${esc(f.name)}</span><span class="sc">${f.score||''}</span></div>`).join('');
}
$('#ffilter').oninput=renderFns;$('#fsort').onchange=renderFns;
$('#fnlist').onclick=e=>{const d=e.target.closest('.fn');if(d){show('dis');openAt(+d.dataset.va)}};

/* overview */
function entBar(e){const c=e>7.2?'var(--red)':e>6.5?'var(--amber)':'var(--teal)';return`<span class="ent"><i style="width:${e/8*100}%;background:${c}"></i></span>${e}`}
function renderOverview(){
  const o=OV;
  const kv=[['SHA-256',o.sha256],['SHA-1',o.sha1],['MD5',o.md5],['Imphash',o.imphash],['Size',o.size.toLocaleString()+' bytes'],
    ['Architecture',o.arch+(o.dll?' DLL':' EXE')],['Compile time',o.timestamp_utc+' UTC'],['Linker',o.linker],
    ['Image base',hx(o.image_base)],['Entry point',`<span class="lnk" data-go="${o.entry}">${hx(o.entry)}</span>`],
    ['Overall entropy',entBar(o.entropy)],['Signed',o.signed?'Has certificate table (verify separately)':'No'],
    ['ASLR / DEP',`${o.aslr?'yes':'no'} / ${o.dep?'yes':'no'}`],['PDB path',o.pdb?`<span class="flag">${esc(o.pdb)}</span>`:'—'],
    ['Overlay',o.overlay?`${o.overlay.size.toLocaleString()} bytes at ${hx(o.overlay.offset)}, entropy ${o.overlay.entropy}`:'—'],
    ['TLS callbacks',o.tls_callbacks.length?o.tls_callbacks.map(v=>`<span class="lnk" data-go="${v}">${hx(v)}</span>`).join(' '):'—']];
  let h=`<h2>File</h2><table class="kv">${kv.map(([k,v])=>`<tr><td>${k}</td><td class="mono">${k==='Entry point'||k==='TLS callbacks'||k==='Overall entropy'||k==='PDB path'?v:esc(v)}</td></tr>`).join('')}</table>`;
  if(o.notes.length)h+=`<h2>Notes</h2>`+o.notes.map(n=>`<p class="flag">${esc(n)}</p>`).join('');
  h+=`<h2>Packing and obfuscation signals</h2>`+(o.packer.length?`<ul>${o.packer.map(p=>`<li class="flag">${esc(p)}</li>`).join('')}</ul>`:'<p>None of the heuristics fired. The code is likely readable as-is.</p>');
  h+=`<h2>Sections</h2><table><tr><th>Name</th><th>Address</th><th>Virtual size</th><th>Raw size</th><th>Flags</th><th>Entropy</th></tr>${o.sections.map(s=>`<tr class="mono"><td>${esc(s.name)}</td><td><span class="lnk" data-go="${s.va}">${hx(s.va)}</span></td><td>${hx(s.vsize)}</td><td>${hx(s.rsize)}</td><td>${s.r?'r':'-'}${s.w?'w':'-'}${s.x?'x':'-'}</td><td>${entBar(s.entropy)}</td></tr>`).join('')}</table>`;
  if(o.resources.length)h+=`<h2>Resources</h2><table><tr><th>Type</th><th>Name</th><th>Size</th><th>Magic</th><th>Entropy</th></tr>${o.resources.map(r=>`<tr class="mono"><td>${esc(r.type)}</td><td>${esc(r.name)}</td><td>${r.size.toLocaleString()}</td><td>${r.magic}${r.embedded_pe?' <span class="flag">embedded PE</span>':''}</td><td>${entBar(r.entropy)}</td></tr>`).join('')}</table>`;
  if(o.exports.length)h+=`<h2>Exports</h2><table>${o.exports.map(e=>`<tr class="mono"><td><span class="lnk" data-go="${e.va}">${hx(e.va)}</span></td><td>${esc(e.name)}</td></tr>`).join('')}</table>`;
  h+=`<div id="embedded"></div>`;
  if(o.warnings.length)h+=`<h2>Parser warnings</h2><ul class="mono">${o.warnings.map(w=>`<li>${esc(w)}</li>`).join('')}</ul>`;
  $('#ov').innerHTML=h;
  loadChildren();
}
async function loadChildren(){
  const ch=await get('/api/children'); if(!ch.length)return;
  $('#embedded').innerHTML=`<h2>Embedded executables</h2><p class="muted">Complete PE files found inside this sample. Each is saved to the library as a child sample.</p>
   <table><tr><th>Offset</th><th>Size</th><th>Where</th><th>Type</th><th>PDB path</th><th></th></tr>${ch.map(c=>`<tr class="mono"><td>${hx(c.offset)}</td><td>${c.size.toLocaleString()}${c.truncated?' <span class="flag">truncated</span>':''}</td><td>${esc(c.location)}</td><td>${c.error?`<span class="err">${esc(c.error)}</span>`:`${esc(c.arch)} ${c.dll?'DLL':'EXE'}${c.signed?', has certificate':''}`}</td><td>${esc(c.pdb||'—')}</td><td>${c.id?`<button data-open="${c.id}">Open</button>`:''}</td></tr>`).join('')}</table>`;
}

/* indicators */
async function renderInd(){
  if(!OV)return;
  const st=await get('/api/strings?cat=_flagged&page=0');
  const top=[...FNS].filter(f=>f.score>0).sort((a,b)=>b.score-a.score).slice(0,25);
  let h=`<h2>Functions worth reading first</h2>`;
  h+=top.length?`<table><tr><th>Function</th><th>Score</th><th>Why</th></tr>${top.map(f=>`<tr><td><span class="lnk" data-go="${f.va}">${esc(f.name)}</span></td><td>${f.score}</td><td>${f.tags.map(tag).join('')}</td></tr>`).join('')}</table>`:'<p class="empty">Nothing scored yet. Auto-analysis is still running, or the sample is packed (check the Overview).</p>';
  h+=`<h2>Crypto constants in the file</h2>`+(OV.constants.length?`<table><tr><th>Constant</th><th>File offset</th><th>Address</th></tr>${OV.constants.map(c=>`<tr class="mono"><td>${esc(c.name)}</td><td>${hx(c.off)}</td><td>${c.va?`<span class="lnk" data-go="${c.va}">${hx(c.va)}</span>`:'—'}</td></tr>`).join('')}</table>`:'<p>No known constants found.</p>');
  const cats=Object.entries(st.counts||{}).sort((a,b)=>b[1]-a[1]);
  h+=`<h2>String categories</h2><p>${cats.map(([c,n])=>`<span class="tag lnk" data-scat="${c}">${esc(c)} ${n}</span>`).join('')||'None.'}</p>`;
  if(OV.yara.length)h+=`<h2>YARA matches</h2><ul>${OV.yara.map(y=>`<li class="flag">${esc(y.rule)} ${y.tags.map(tag).join('')}</li>`).join('')}</ul>`;
  $('#ind').innerHTML=h;
}

/* imports */
async function loadImports(){
  const l=await get('/api/imports');
  l.sort((a,b)=>(b.cat?1:0)-(a.cat?1:0)||a.dll.localeCompare(b.dll)||a.name.localeCompare(b.name));
  $('#imp').innerHTML=`<p>${l.length} imports. Categorised ones are listed first; click a caller to jump to it.</p><table><tr><th>DLL</th><th>Function</th><th>Category</th><th>Called from</th></tr>${l.map(i=>`<tr><td class="mono">${esc(i.dll)}</td><td class="mono">${esc(i.name)}${i.delayed?' <span class="tag">delay</span>':''}</td><td>${i.cat?tag(i.cat):''}</td><td>${i.xrefs.map(x=>`<span class="lnk" data-go="${x.va}">${esc(x.name)}</span>`).join(' ')}</td></tr>`).join('')}</table>`;
}

/* strings */
let strCat='_flagged';
async function loadStrings(){
  const q=encodeURIComponent($('#sq')?.value||'');
  const j=await get(`/api/strings?cat=${strCat}&q=${q}&page=${strPage}`);
  const cats=Object.keys(j.counts).sort();
  const pages=Math.max(1,Math.ceil(j.total/j.size));
  const hadFocus=document.activeElement?.id==='sq', qv=$('#sq')?.value||'';
  $('#str').innerHTML=`<div style="display:flex;gap:8px;align-items:center;margin-bottom:10px">
    <select id="scat"><option value="_flagged">Flagged only</option><option value="">All strings</option>${cats.map(c=>`<option value="${c}">${esc(c)} (${j.counts[c]})</option>`).join('')}</select>
    <input id="sq" placeholder="Search text" value="${esc(qv)}"><span>${j.total.toLocaleString()} matches</span>
    <button id="sprev" ${strPage?'':'disabled'}>Previous</button><span>${strPage+1} / ${pages}</span><button id="snext" ${strPage+1<pages?'':'disabled'}>Next</button></div>
    <table><tr><th>Offset</th><th>Address</th><th>Enc</th><th>Categories</th><th>Text</th><th>Referenced by</th></tr>
    ${j.rows.map(r=>`<tr><td class="mono">${hx(r.off)}</td><td class="mono">${r.va?`<span class="lnk" data-go="${r.va}">${hx(r.va)}</span>`:'—'}</td><td>${r.enc}</td><td>${r.cats.map(c=>tag('str:'+c)).join('')}</td><td class="mono" style="word-break:break-all;max-width:70ch">${esc(r.text)}</td><td>${r.xrefs.map(x=>`<span class="lnk" data-go="${x.va}">${esc(x.name)}</span>`).join(' ')}</td></tr>`).join('')}</table>`;
  $('#scat').value=strCat;
  $('#scat').onchange=e=>{strCat=e.target.value;strPage=0;loadStrings()};
  let t;$('#sq').oninput=()=>{clearTimeout(t);t=setTimeout(()=>{strPage=0;loadStrings()},300)};
  if(hadFocus){$('#sq').focus();$('#sq').setSelectionRange(qv.length,qv.length)}
  $('#sprev').onclick=()=>{strPage--;loadStrings()};$('#snext').onclick=()=>{strPage++;loadStrings()};
}

/* pseudocode */
let pcEngine='builtin',pcVa=null;
function hl(code){
  const KW=/\b(if|else|while|do|for|return|goto|break|continue|void|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|__m128i|__m256i|unsigned|int)\b/g;
  return esc(code)
    .replace(/(\/\/[^\n]*)/g,'<span class="cm">$1</span>')
    .replace(/(L?&quot;(?:[^&]|&(?!quot;))*&quot;)/g,'<span class="str">$1</span>')
    .replace(KW,'<span class="kw">$1</span>')
    .replace(/\b(0x[0-9A-Fa-f]+)\b/g,'<span class="num">$1</span>')
    .replace(/^(L_[0-9A-F]+:)/gm,'<span class="lbl">$1</span>');
}
async function loadPC(){
  if(pcVa==null)return;
  $('#pc').classList.add('on'); $('#pctoggle').classList.add('on');
  $('#pcname').textContent=''; $('#pccode').innerHTML='Reconstructing…'; $('#pcmeta').textContent='';
  const t0=performance.now();
  const j=await get(`/api/pseudocode?va=${pcVa.toString(16)}&engine=${pcEngine}`);
  if(j.error){$('#pccode').innerHTML=`<span class="cm">// ${esc(j.error)}</span>`;return}
  $('#pcname').textContent=j.name||''; 
  $('#pcmeta').textContent=`${j.engine} · ${Math.round(performance.now()-t0)} ms`;
  $('#pccode').innerHTML=hl(j.text);
  $('#pccode').dataset.raw=j.text;
}
function openPC(va){pcVa=va;loadPC()}
document.querySelectorAll('#pcbar [data-eng]').forEach(b=>b.onclick=()=>{
  document.querySelectorAll('#pcbar [data-eng]').forEach(x=>x.classList.toggle('on',x===b));
  pcEngine=b.dataset.eng;loadPC();
});
$('#pctoggle').onclick=()=>{
  if($('#pc').classList.contains('on')){$('#pc').classList.remove('on');$('#pctoggle').classList.remove('on')}
  else openPC(curFn??curAddr);
};
$('#pcclose').onclick=()=>{$('#pc').classList.remove('on');$('#pctoggle').classList.remove('on')};
$('#pccopy').onclick=()=>navigator.clipboard?.writeText($('#pccode').dataset.raw||'');

/* IOCs */
async function loadIocs(){
  const l=await get('/api/iocs'); const kinds=[...new Set(l.map(i=>i.kind))];
  const pick=$('#iockind')?.value||'';
  const rows=pick?l.filter(i=>i.kind===pick):l;
  $('#iocs').innerHTML=`<div class="row"><select id="iockind"><option value="">All kinds (${l.length})</option>${kinds.map(k=>`<option value="${k}">${esc(k)} (${l.filter(i=>i.kind===k).length})</option>`).join('')}</select>
    <a href="/api/iocs.csv">Download CSV</a><span class="muted">Extracted from strings, stack strings, the debug directory and embedded files. Review before sharing: some will be false positives.</span></div>
    ${rows.length?`<table><tr><th>Kind</th><th>Value</th><th>Source</th><th>Offset</th></tr>${rows.map(i=>`<tr><td>${tag(i.kind)}</td><td class="longtext">${esc(i.value)}</td><td class="muted">${esc(i.source)}</td><td class="mono">${i.offset!=null?hx(i.offset):''}</td></tr>`).join('')}</table>`:'<p class="empty">No indicators yet. Stack strings are added when auto-analysis finishes.</p>'}`;
  $('#iockind').value=pick; $('#iockind').onchange=loadIocs;
}

/* library */
async function loadLib(){
  const j=await get('/api/library');
  $('#lib').innerHTML=`<p class="muted">Database: <span class="mono">${esc(j.db)}</span>. Open it with any SQLite tool, or use the SQL tab.</p>
   <table><tr><th>Name</th><th>Arch</th><th>Size</th><th>Functions</th><th>Top score</th><th>IOCs</th><th>PDB path</th><th>Added</th><th></th></tr>
   ${j.samples.map(x=>`<tr class="${x.parent_id?'child':''}"><td class="mono">${x.parent_id?'↳ ':''}${esc(x.name)}<div class="muted">${x.sha256.slice(0,16)}…</div></td><td>${esc(x.arch)} ${x.is_dll?'DLL':'EXE'}</td><td>${x.size.toLocaleString()}</td><td>${x.functions||'—'}</td><td>${x.top_score??'—'}</td><td>${x.iocs}</td><td class="mono">${esc(x.pdb||'—')}</td><td class="muted">${esc(x.added_at)}</td>
   <td>${x.id===j.current?'<span class="flag">Open now</span>':x.has_blob?`<button data-open="${x.id}">Open</button>`:'<span class="muted">No file stored</span>'}</td></tr>`).join('')}</table>`;
}

/* SQL console */
const EXAMPLES=[
 ['Top functions','SELECT addr, name, score, tags, stack_strings\nFROM v_functions WHERE sample_id = :sample\nORDER BY score DESC LIMIT 50'],
 ['Who calls crypto','SELECT func_name, func_addr, api, count\nFROM v_api_usage WHERE sample_id = :sample\n  AND category IN (\'crypto\', \'ransom_ops\')\nORDER BY func_name'],
 ['Strings used by code','SELECT func_name, func_addr, text, cats\nFROM v_string_xrefs WHERE sample_id = :sample AND cats <> \'\'\nORDER BY func_name'],
 ['Call graph','SELECT caller, callee FROM v_call_graph\nWHERE sample_id = :sample ORDER BY caller'],
 ['IOCs, all samples','SELECT s.name, i.kind, i.value\nFROM indicators i JOIN samples s ON s.id = i.sample_id\nORDER BY i.kind, i.value'],
 ['Shared strings','SELECT text, COUNT(DISTINCT sample_id) AS samples\nFROM strings GROUP BY text HAVING samples > 1\nORDER BY samples DESC, length(text) DESC LIMIT 200'],
 ['Full-text search','SELECT sid, text FROM strings_fts\nWHERE sample_id = :sample AND strings_fts MATCH \'decrypt OR ransom\''],
 ['Tables','SELECT type, name FROM sqlite_master\nWHERE type IN (\'table\', \'view\') ORDER BY type, name'],
];
function renderSql(){
  if($('#sqlq'))return;
  $('#sql').innerHTML=`<p class="muted">Read-only. <span class="mono">:sample</span> means the sample that is open now. Ctrl+Enter runs the query.</p>
   <div class="row">${EXAMPLES.map((x,i)=>`<button data-ex="${i}">${esc(x[0])}</button>`).join('')}</div>
   <textarea id="sqlq" spellcheck="false">${esc(EXAMPLES[0][1])}</textarea>
   <div class="row"><button id="sqlrun">Run query</button><span id="sqlmeta" class="muted"></span></div><div id="sqlout"></div>`;
  $('#sql').querySelectorAll('[data-ex]').forEach(b=>b.onclick=()=>{$('#sqlq').value=EXAMPLES[+b.dataset.ex][1];runSql()});
  $('#sqlrun').onclick=runSql;
  $('#sqlq').onkeydown=e=>{if(e.key==='Enter'&&(e.ctrlKey||e.metaKey)){e.preventDefault();runSql()}};
}
async function runSql(){
  const t0=performance.now(); const j=await post('/api/sql',{q:$('#sqlq').value});
  if(j.error){$('#sqlout').innerHTML=`<p class="err">${esc(j.error)}</p>`;$('#sqlmeta').textContent='';return}
  $('#sqlmeta').textContent=`${j.rows.length} rows${j.truncated?' (first 2000 shown)':''} in ${Math.round(performance.now()-t0)} ms`;
  $('#sqlout').innerHTML=`<table><tr>${j.cols.map(c=>`<th>${esc(c)}</th>`).join('')}</tr>${j.rows.map(r=>`<tr>${r.map(v=>`<td class="longtext">${esc(v??'NULL')}</td>`).join('')}</tr>`).join('')}</table>`;
}

/* global link handling */
async function post(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});return r.json()}
async function openSample(id){
  $('#ptxt').textContent='Opening…';
  const j=await post('/api/open/'+id); if(j.error){alert(j.error);$('#ptxt').textContent='';return}
  show('ov'); await refreshAll();
}
async function editComment(va){
  const t=prompt('Comment for '+hx(va)+' (leave empty to remove)',UC[va]||''); if(t===null)return;
  const j=await post('/api/annotate',{va,kind:'comment',text:t}); if(j.error){alert(j.error);return}
  UC[va]=t.trim(); const el=document.getElementById('a'+va); if(!el)return;
  el.querySelector('.uc')?.remove(); el.classList.toggle('cmt',!!UC[va]);
  if(UC[va])el.querySelector('.o').insertAdjacentHTML('beforeend',`<span class="uc">  // ${esc(UC[va])}</span>`);
}
async function rename(va,old){
  const t=prompt('New name for '+old+' (leave empty to restore the automatic name)',old); if(t===null)return;
  const j=await post('/api/annotate',{va,kind:'name',text:t}); if(j.error){alert(j.error);return}
  FNS=await get('/api/functions'); renderFns();
  const keep=$('#listing').scrollTop; await openAt(curAddr,false); $('#listing').scrollTop=keep;
  if($('#pc').classList.contains('on'))loadPC();
}
document.body.addEventListener('click',e=>{
  const g=e.target.closest('[data-go]'); if(g){show('dis');openAt(+g.dataset.go);return}
  const op=e.target.closest('[data-open]'); if(op){openSample(+op.dataset.open);return}
  const cm=e.target.closest('[data-cmt]'); if(cm){editComment(+cm.dataset.cmt);return}
  const rn=e.target.closest('[data-ren]'); if(rn){rename(+rn.dataset.ren,rn.dataset.old);return}
  const sc=e.target.closest('[data-scat]'); if(sc){strCat=sc.dataset.scat;strPage=0;show('str')}
});

/* disassembly */
function row(r){
  let h='';
  if(r.fn)h+=`<div class="fh">${esc(r.fn)}<small>${r.xrefs?r.xrefs+' caller'+(r.xrefs>1?'s':''):''}</small></div>`;
  const ops=r.t!=null?esc(r.ops).replace(/0x[0-9a-f]+/i,m=>`<span class="lnk" data-go="${r.t}">${m}</span>`):esc(r.ops);
  if(r.uc)UC[r.va]=r.uc;
  const cls=['r',r.api?'api':'',r.str!=null&&!r.api?'s':'',r.bad?'bad':'',r.ret?'sep':'',r.uc?'cmt':''].join(' ');
  return h+`<div class="${cls}" id="a${r.va}"><span class="a" data-cmt="${r.va}" title="Add or edit a comment">${r.va.toString(16).toUpperCase().padStart(8,'0')}</span><span class="b">${r.bytes}</span><span class="m">${esc(r.mn)}</span><span class="o">${ops}${r.c?`  <span class="cm">; ${esc(r.c)}</span>`:''}${r.uc?`<span class="uc">  // ${esc(r.uc)}</span>`:''}</span></div>`;
}
async function openAt(va,push=true){
  if(push&&dNext!==null&&hist.at(-1)!==curAddr)hist.push(curAddr);
  curAddr=va;$('#goto').value=va.toString(16).toUpperCase();
  const j=await get(`/api/disasm?va=${va.toString(16)}&count=250`);
  if(j.error){$('#listing').innerHTML=`<div class="empty">${esc(j.error)}</div>`;return}
  $('#listing').innerHTML=j.rows.map(row).join('')+'<div id="sentinel"></div>';
  $('#listing').scrollTop=0; dNext=j.next; observe();
  $('#dloc').textContent=(j.exec?'':'not in an executable section · ')+(j.owner_name?'in '+j.owner_name:'');
  $('#a'+va)?.classList.add('cur');
  const fva=j.owner??va; curFn=fva; renderFns(); loadSide(fva);
  if($('#pc').classList.contains('on')&&fva!=null&&fva!==pcVa)openPC(fva);
}
async function more(){
  if(dLoading||dNext==null)return;dLoading=true;
  const j=await get(`/api/disasm?va=${dNext.toString(16)}&count=250`);
  $('#sentinel').insertAdjacentHTML('beforebegin',j.rows.map(row).join(''));dNext=j.next;dLoading=false;
}
let io;function observe(){io?.disconnect();io=new IntersectionObserver(es=>{if(es[0].isIntersecting)more()},{root:$('#listing'),rootMargin:'600px'});io.observe($('#sentinel'))}
async function loadSide(va){
  const r=await fetch('/api/function?va='+va.toString(16));
  if(!r.ok){$('#side').innerHTML='<div class="empty">This address is not inside an analysed function yet. If auto-analysis is still running, select it again in a moment.</div>';return}
  const f=await r.json();
  const list=(a,fmt)=>a.length?`<ul>${a.map(fmt).join('')}</ul>`:'<p class="empty" style="padding:0">None</p>';
  $('#side').innerHTML=`<h3>Function</h3><div class="big">${esc(f.name)}</div>
   <div class="row"><button data-ren="${f.va}" data-old="${esc(f.name)}">Rename</button><span class="muted">Click any address to comment it.</span></div>
   <p class="mono">${hx(f.va)} – ${hx(f.end)} · ${f.insns} instructions · ${f.blocks} blocks · score ${f.score}</p>
   <div>${f.tags.map(tag).join('')}</div>
   ${Object.keys(f.notes).length?`<h3>Heuristics</h3>${list(Object.entries(f.notes),([k,v])=>`<li class="flag">${esc(k)} ×${v}</li>`)}`:''}
   <h3>API calls</h3>${list(f.apis,a=>`<li class="mono">${esc(a.name)} ×${a.count} ${a.cat?tag(a.cat):''}</li>`)}
   <h3>Strings referenced</h3>${list(f.strings,s=>`<li class="mono" style="color:var(--violet)">${esc(s.text)}</li>`)}
   ${f.stack_strings.length?`<h3>Stack strings rebuilt</h3>${list(f.stack_strings,s=>`<li class="mono flag">${esc(s)}</li>`)}`:''}
   <h3>Called by</h3>${list(f.callers,c=>`<li><span class="lnk" data-go="${c.va}">${esc(c.name)}</span></li>`)}
   <h3>Calls</h3>${list(f.callees,c=>`<li><span class="lnk" data-go="${c.va}">${esc(c.name)}</span></li>`)}`;
}
$('#back').onclick=()=>{if(hist.length)openAt(hist.pop(),false)};
document.addEventListener('keydown',e=>{if(e.altKey&&e.key==='ArrowLeft'&&hist.length){e.preventDefault();openAt(hist.pop(),false)}});
const go=()=>{const v=parseInt($('#goto').value.replace(/^0x/i,''),16);if(!isNaN(v))openAt(v)};
$('#gobtn').onclick=go;$('#goto').onkeydown=e=>{if(e.key==='Enter')go()};
$('#goep').onclick=()=>OV&&openAt(OV.entry);

get('/api/status').then(s=>{if(s.loaded)refreshAll()});
</script></body></html>
"""


def main():
    ap = argparse.ArgumentParser(description="Local static PE triage dashboard")
    ap.add_argument("--sample", help="path to a PE file to preload (read only, never executed)")
    ap.add_argument("--rules", help="YARA rule file or directory (optional, needs yara-python)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", default="triage.db", help="SQLite database path (default: triage.db)")
    ap.add_argument("--no-blob", action="store_true",
                    help="don't store the sample bytes in the database (results only)")
    args = ap.parse_args()

    STATE["db"] = TriageDB(args.db)
    STATE["store_blob"] = not args.no_blob
    print(f"[+] database: {STATE['db'].path}")

    if args.rules:
        if yara is None:
            print("[!] yara-python not installed; ignoring --rules")
        elif os.path.isdir(args.rules):
            files = {f: os.path.join(args.rules, f) for f in os.listdir(args.rules)
                     if f.lower().endswith((".yar", ".yara"))}
            STATE["rules"] = yara.compile(filepaths=files)
        else:
            STATE["rules"] = yara.compile(filepath=args.rules)

    if args.sample:
        with open(args.sample, "rb") as fh:
            load_sample(fh.read(), os.path.basename(args.sample))
        print(f"[+] loaded {args.sample}; auto-analysis running in background")

    print(f"[+] open http://127.0.0.1:{args.port}")
    app.run(host="127.0.0.1", port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
