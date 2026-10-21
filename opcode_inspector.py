#!/usr/bin/env python3
"""
Opcode Inspector for EQEmu-based servers.

Scans a server repo and shows, for every opcode the server sends or handles:
  - the wire opcode each registered client patch maps it to (patch_<Client>.conf)
  - whether the patch has an ENCODE / DECODE / EAT_ENCODE for it
  - where the server sends it and whether a handler exists
  - a status (OK / translated / passthrough / sent as 0x0000 / unreachable)
  - optionally, the value upstream EQEmu uses, plus a suggested fix

Usage:
  python opcode_inspector.py                      # GUI, asks for the repo folder
  python opcode_inspector.py C:\\path\\to\\Core     # GUI, scans that folder
  python opcode_inspector.py C:\\path\\to\\Core --no-gui --csv out.csv --html report.html
  add --upstream to fetch upstream EQEmu .conf files for comparison (needs internet)
  python opcode_inspector.py . --compare OP_Death --client RoF2   # ours vs upstream struct + encoder
  python opcode_inspector.py . --struct-report struct_diff.csv     # every shared struct, ours vs upstream

In the GUI, double-click a row (or "Compare with upstream") to see both layouts side by side.

Python 3.8+, standard library only (tkinter ships with the python.org Windows installer).
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

UPSTREAM_CONF_URL = "https://raw.githubusercontent.com/EQEmu/EQEmu/refs/heads/master/utils/patches/patch_{name}.conf"
CONF_DIRS: list = []  # set by --conf-dir; checked before anything else
SKIP_DIRS = {"chatserver", ".git", "build", "out", "bin", "obj", ".vs", "node_modules", "x64", "Debug", "Release"}

# Opcodes whose names changed upstream; used to suggest aliases (ours -> upstream name)
KNOWN_ALIASES = {
    "OP_GroupCancelInvite": "OP_CancelInvite",
    "OP_DzJoinExpeditionConfirm": "OP_DzExpeditionInvite",
    "OP_DzJoinExpeditionReply": "OP_DzExpeditionInviteResponse",
    "OP_DzExpeditionList": "OP_DzExpeditionLockoutTimers",
    "OP_DzMemberStatus": "OP_DzMemberListName",
    "OP_DzLeaderStatus": "OP_DzSetLeaderName",
}

# Encoders that intentionally re-send under a different opcode, so an unmapped value is fine
REROUTED = {"OP_RaidJoin": "encoder re-sends as OP_RaidUpdate"}


# ----------------------------------------------------------------------
# Fix playbook: what to actually do for opcodes that don't reach a client.
# Researched against upstream EQEmu (github.com/EQEmu/EQEmu, master) and this
# server's RoF2 patch. Keys are emu opcode names; "*" applies to every client,
# a client name overrides it. Actions:
#   MAP        add a .conf value (layout already matches)
#   REROUTE    translate to a different opcode the client does have (encoder below)
#   SERVER     change the server code for this client (code below)
#   PORT       feature needs upstream's newer implementation
#   NOT NEEDED client has no such packet; upstream also sends it unmapped and the
#              client ignores it. Skipping it for this client is hygiene, not a fix
#   CUSTOM     value only exists in your modified client
#   INVESTIGATE unclear purpose; look before changing
# ----------------------------------------------------------------------
_RANK_XLATE = """	switch (RANK_IN) { // old 0/1/2 ranks -> RoF2 ranks, same as ENCODE(OP_SetGuildRank)
	case 0: RANK_OUT = 5; break;  // member
	case 1: RANK_OUT = 3; break;  // officer
	case 2: RANK_OUT = 1; break;  // leader
	default: RANK_OUT = RANK_IN; break;
	}"""

PLAYBOOK = {
    "OP_GuildManageRemove": {"RoF2": {
        "action": "MAP",
        "summary": "RoF2 calls this OP_GuildMemberDelete (0x3141). Your GuildManageRemove_Struct "
                   "{uint32 guild_id; char name[64]} is byte-identical to upstream's GuildMemberDelete_Struct, "
                   "so mapping the opcode is enough.",
        "conf": ["OP_GuildManageRemove=0x3141    # RoF2 OP_GuildMemberDelete, same 68-byte layout"],
    }},
    "OP_GuildManageStatus": {"RoF2": {
        "action": "REROUTE",
        "summary": "Rank changes. RoF2 uses OP_SetGuildRank (0x0b9c, upstream's OP_GuildMemberRankAltBanker), "
                   "which your RoF2 patch already encodes. Translate GuildManageStatus into it.",
        "ops_h": ["E(OP_GuildManageStatus)"],
        "code": """ENCODE(OP_GuildManageStatus)
{
	ENCODE_LENGTH_EXACT(GuildManageStatus_Struct);
	SETUP_DIRECT_ENCODE(GuildManageStatus_Struct, structs::GuildSetRank_Struct);

	eq->GuildID = emu->guild_id;
""" + _RANK_XLATE.replace("RANK_IN", "emu->newrank").replace("RANK_OUT", "eq->Rank") + """
	strn0cpy(eq->MemberName, emu->name, sizeof(eq->MemberName));
	eq->Unknown76 = 1;              // same as ENCODE(OP_SetGuildRank)

	__packet->SetOpcode(OP_SetGuildRank);  // wire opcode comes from OP_SetGuildRank's .conf entry
	FINISH_ENCODE();
}""",
    }},
    "OP_GuildManageAdd": {"RoF2": {
        "action": "REROUTE",
        "summary": "Member joined. RoF2 uses OP_GuildMemberAdd (0x2925); upstream sends it with GuildMemberAdd_Struct. "
                   "Needs a new emu opcode, a .conf line, a wire struct and an encoder.",
        "conf": ["OP_GuildMemberAdd=0x2925    # upstream value"],
        "extra": "emu_oplist.h: add N(OP_GuildMemberAdd), at the END of the list so existing values don't shift.\n\n"
                 "rof2_structs.h (upstream layout):\n"
                 "struct GuildMemberAdd_Struct {\n"
                 "/*000*/ uint32 guild_id;\n/*004*/ uint32 unknown04;\n/*008*/ uint32 unknown08;\n"
                 "/*012*/ uint32 unknown12;\n/*016*/ uint32 level;\n/*020*/ uint32 class_;\n/*024*/ uint32 rank_;\n"
                 "/*028*/ uint32 guild_show;\n/*032*/ uint32 zone_id;\n/*036*/ uint32 last_on;\n"
                 "/*040*/ char   player_name[64];\n};",
        "ops_h": ["E(OP_GuildManageAdd)"],
        "code": """ENCODE(OP_GuildManageAdd)
{
	ENCODE_LENGTH_EXACT(GuildJoin_Struct);
	SETUP_DIRECT_ENCODE(GuildJoin_Struct, structs::GuildMemberAdd_Struct);

	eq->guild_id = emu->guild_id;
	eq->level    = emu->level;
	eq->class_   = emu->class_;
""" + _RANK_XLATE.replace("RANK_IN", "emu->rank").replace("RANK_OUT", "eq->rank_") + """
	eq->zone_id  = emu->zoneid;
	eq->last_on  = time(nullptr);
	strn0cpy(eq->player_name, emu->name, sizeof(eq->player_name));

	__packet->SetOpcode(OP_GuildMemberAdd);
	FINISH_ENCODE();
}""",
    }},
    "OP_ZoneGuildList": {"*": {
        "action": "SERVER",
        "summary": "Upstream removed this packet entirely. RoF2 gets the guild list from OP_GuildsList, which your "
                   "RoF2 patch already encodes. For RoF2 clients send (or rely on) OP_GuildsList instead; check what "
                   "the sender in guild.cpp is for before removing it.",
    }},
    "OP_MultiLineMsg": {"*": {
        "action": "SERVER",
        "summary": "No RoF2 opcode (upstream sends it unmapped, so RoF2 players never see these messages). "
                   "Deliver it as ordinary chat for RoF2.",
        "code": """// worldserver.cpp, ServerOP_MultiLineMsg handler, replace the OP_MultiLineMsg send:
if (client->ClientVersion() >= EQ::versions::ClientVersion::RoF2) {
	for (const auto &line : SplitString(mlm->message, '\\n'))   // check the actual line separator
		client->Message(Chat::White, line.c_str());
} else {
	// existing OP_MultiLineMsg packet
}""",
    }},
    "OP_ItemLinkText": {"*": {
        "action": "INVESTIGATE",
        "summary": "Upstream no longer has this packet. RoF2 shows item details via OP_ItemLinkResponse (encoded "
                   "by your patch). Check what the senders in client.cpp deliver and route it through "
                   "OP_ItemLinkResponse or a chat message with an item link.",
    }},
    "OP_LFGAppearance": {"*": {
        "action": "NOT NEEDED",
        "summary": "No RoF2 opcode; upstream sends it unmapped too. Other players see the LFG flag from spawn data "
                   "(the lfg field in OP_ZoneSpawns/OP_NewSpawn), not from this packet.",
        "eat": True,
    }},
    "OP_ZoneServerReady": {"*": {
        "action": "NOT NEEDED",
        "summary": "RoF2 finishes zone-in without it; upstream sends it unmapped on every zone-in.",
        "eat": True,
    }},
    "OP_PreLogoutReply": {"*": {
        "action": "NOT NEEDED",
        "summary": "No RoF2 opcode; upstream sends it unmapped. Camp/logout runs on OP_Camp and OP_Logout.",
        "eat": True,
    }},
    "OP_TargetReject": {"*": {
        "action": "NOT NEEDED",
        "summary": "No RoF2 opcode; upstream sends it unmapped. The player still gets the 'You cannot see your target' message.",
        "eat": True,
    }},
    "OP_GMEndTrainingResponse": {"*": {
        "action": "NOT NEEDED",
        "summary": "No RoF2 opcode; upstream sends it unmapped. The trainer window closes client-side.",
        "eat": True,
    }},
    "OP_PetitionUpdate": {"*": {
        "action": "NOT NEEDED",
        "summary": "RoF2 has no petition window opcodes (all 0 upstream). GMs use #petition commands.",
        "eat": True,
    }},
    "OP_PetitionCheckout": {"*": {
        "action": "NOT NEEDED",
        "summary": "RoF2 has no petition window opcodes (all 0 upstream). GMs use #petition commands.",
        "eat": True,
    }},
    "OP_TraderItemUpdate": {"*": {
        "action": "PORT",
        "summary": "Part of the old bazaar protocol. Upstream rewrote the bazaar around OP_TraderShop, "
                   "OP_BazaarSearch and OP_Trader actions; RoF2 trader updates only work after porting that.",
    }},
    "OP_Bazaar": {"*": {
        "action": "PORT",
        "summary": "Old bazaar protocol; no RoF2 opcode. See upstream's bazaar rewrite (OP_TraderShop / OP_BazaarSearch).",
    }},
    "OP_TraderBuy": {"*": {
        "action": "PORT",
        "summary": "RoF2 doesn't send OP_TraderBuy; purchases arrive as OP_TraderShop actions in upstream's bazaar. "
                   "Your D(OP_TraderBuy) can never run for RoF2.",
    }},
    "OP_ResetCampTimer": {
        "RoF2": {"action": "NOT NEEDED",
                 "summary": "Handle_OP_Camp already uses the server-side camp_timer for RoF2; this packet is for "
                            "your modified SoD client.", "eat": True},
        "SoD": {"action": "CUSTOM",
                "summary": "Only your modified SoD client knows this opcode. Add OP_ResetCampTimer=0x???? to "
                           "patch_SoD.conf with the value from that client."},
    },
    "OP_Diag": {"*": {
        "action": "CUSTOM",
        "summary": "Private anti-cheat diagnostics (PRODUCTION builds, libsoddiag). Only a modified client sends it; "
                   "it has no opcode in either .conf, so it never arrives. Leave it unless that client is in use.",
    }},
    "OP_0x0347": {"*": {
        "action": "INVESTIGATE",
        "summary": "Placeholder name with no value in any .conf. Find what the sender in client_packet.cpp was "
                   "meant to do; delete the send if it's leftover.",
    }},
    "OP_GroupCancelInvite": {"RoF2": {
        "action": "MAP",
        "summary": "RoF2 calls it OP_CancelInvite (0x2a50). Your patch_SoD.conf already maps both names to one value.",
        "conf": ["OP_GroupCancelInvite=0x2a50    # = OP_CancelInvite"],
    }},
}


OUT_RE = re.compile(r"EQApplicationPacket[ *(]*[A-Za-z_0-9]*\(?\s*(OP_[A-Za-z0-9_]+)|SetOpcode\(\s*(OP_[A-Za-z0-9_]+)")
IN_MAP_RE = re.compile(r"^\s*(Connected|Connecting)Opcodes\[(OP_[A-Za-z0-9_]+)\]")
IN_CASE_RE = re.compile(r"^\s*case\s+(OP_[A-Za-z0-9_]+)\s*:")
CONF_RE = re.compile(r"^\s*(OP_[A-Za-z0-9_]+)\s*=\s*0x([0-9A-Fa-f]+)")


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def strip_comments(s: str) -> str:
    # keeps newlines so positions still map to the original line numbers
    s = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), s, flags=re.S)
    return re.sub(r"//[^\n]*", "", s)


def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


UPSTREAM_BLOB = "https://github.com/EQEmu/EQEmu/blob/master/{path}#L{line}"


def gh_link(path, line):
    return UPSTREAM_BLOB.format(path=path, line=line) if path and line else ""


def _is_link(path: str) -> bool:
    # Windows junctions aren't reported by islink() on older Pythons
    if os.path.islink(path):
        return True
    isj = getattr(os.path, "isjunction", None)
    if isj and isj(path):
        return True
    return False


def walk(root: Path, exts):
    seen = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        real = os.path.realpath(dirpath)
        if real in seen:          # directory loop (junction/symlink back into the tree)
            dirnames[:] = []
            continue
        seen.add(real)
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not _is_link(os.path.join(dirpath, d))]
        for f in filenames:
            if f.lower().endswith(exts):
                yield Path(dirpath) / f


def find_file(root: Path, name: str, prefer: str = "") -> Path | None:
    # Fast path: the conventional EQEmu locations
    guesses = [root / "common" / name, root / "common" / "patches" / name]
    if name.endswith(".conf"):
        guesses = [d / name for d in CONF_DIRS] + [root / "utils" / "patches" / name,
                                                   root / "util" / "patches" / name, root / name]
    for guess in guesses:
        if guess.is_file():
            return guess
    hits = [p for p in walk(root, (Path(name).suffix,)) if p.name.lower() == name.lower()]
    if not hits:
        return None
    hits.sort(key=lambda p: len(p.parts))  # shallowest copy wins
    if prefer:
        pref = [p for p in hits if prefer in p.as_posix().lower()]
        if pref:
            return pref[0]
    return hits[0]


def parse_conf(p: Path | None) -> dict:
    d = {}
    if p:
        for line in read(p).splitlines():
            m = CONF_RE.match(line)
            if m:
                d[m.group(1)] = int(m.group(2), 16)
    return d


@dataclass
class Patch:
    name: str              # namespace, e.g. RoF2
    conf_name: str         # e.g. RoF2 -> patch_RoF2.conf
    conf_path: Path | None
    conf: dict
    encoders: set
    decoders: set
    eats: set
    upstream: dict = field(default_factory=dict)
    upstream_lines: dict = field(default_factory=dict)   # opcode -> line in upstream .conf


@dataclass
class Row:
    opcode: str
    sent_from: list
    handled_in: list
    per_client: dict = field(default_factory=dict)  # client -> dict
    struct_hints: list = field(default_factory=list)

    @property
    def direction(self):
        if self.sent_from and self.handled_in:
            return "Out+In"
        return "Out" if self.sent_from else "In"


class Scan:
    def __init__(self, root: Path, log=print):
        self.root = Path(root)
        self.log = log
        self.emu_ops: list = []
        self.patches: list = []
        self.rows: list = []
        self.unknown_conf_names: dict = {}

    # ---------- discovery ----------
    def run(self, fetch_upstream=False):
        r = self.root
        oplist = find_file(r, "emu_oplist.h", "common")
        if not oplist:
            raise FileNotFoundError("Couldn't find common/emu_oplist.h under " + str(r))
        ops = re.findall(r"N\((OP_[A-Za-z0-9_]+)\)", strip_comments(read(oplist)))
        mail = find_file(r, "mail_oplist.h", "common")
        if mail:
            ops += re.findall(r"N\((OP_[A-Za-z0-9_]+)\)", strip_comments(read(mail)))
        self.emu_ops = ops
        self.log(f"Emu opcodes: {len(ops)} (from {oplist})")

        patches_cpp = find_file(r, "patches.cpp", "patches")
        names = []
        if patches_cpp:
            body = strip_comments(read(patches_cpp))
            m = re.search(r"RegisterAllPatches\s*\([^)]*\)\s*\{(.*?)\}", body, re.S)
            names = re.findall(r"(\w+)::Register\s*\(", m.group(1) if m else body)
            pdir = patches_cpp.parent
        else:
            ops_h = find_file(r, "rof2_ops.h") or find_file(r, "sod_ops.h")
            pdir = ops_h.parent if ops_h else r / "common" / "patches"
        self.log(f"patches.cpp: {patches_cpp or 'not found'}")
        self.log(f"Registered patches: {', '.join(names) or 'none found'}")

        # Also offer any patch that has both <name>.cpp and <name>_ops.h, registered or not
        for opsh in sorted(pdir.glob("*_ops.h")):
            stem = opsh.stem[:-4]
            cpp = next((p for p in pdir.glob("*.cpp") if p.stem.lower() == stem.lower()), None)
            if not cpp or any(n.lower() == stem.lower() for n in names):
                continue
            m = re.search(r"namespace\s+(\w+)\s*\{", strip_comments(read(cpp)))
            ns = m.group(1) if m else stem
            names.append(ns)
            self.log(f"  found unregistered patch {ns} ({cpp.name}); listed anyway")

        for ns in names:
            cpp = next((p for p in pdir.glob("*.cpp") if p.stem.lower() == ns.lower()), None)
            opsh = next((p for p in pdir.glob("*_ops.h") if p.stem.lower() == ns.lower() + "_ops"), None)
            src = strip_comments(read(cpp)) if cpp else ""
            m = re.search(r'static\s+const\s+char\s*\*\s*name\s*=\s*"([^"]+)"', src)
            conf_name = m.group(1) if m else ns
            conf_path = find_file(r, f"patch_{conf_name}.conf")
            opstxt = strip_comments(read(opsh)) if opsh else ""
            enc = set(re.findall(r"\bE\((OP_[A-Za-z0-9_]+)\)", opstxt))
            dec = set(re.findall(r"\bD\((OP_[A-Za-z0-9_]+)\)", opstxt))
            eats = set(re.findall(r"EAT_ENCODE\((OP_[A-Za-z0-9_]+)\)", src))
            p = Patch(ns, conf_name, conf_path, parse_conf(conf_path), enc, dec, eats)
            if fetch_upstream:
                p.upstream, p.upstream_lines = self.fetch_upstream(conf_name)
            self.patches.append(p)
            if not conf_path:
                self.log(f"  WARNING: patch_{conf_name}.conf not found; use --conf-dir")
            self.log(f"  {ns}: conf={conf_path}, {len(enc)} encoders, {len(dec)} decoders, {len(eats)} eaten")
            emu = set(self.emu_ops)
            self.unknown_conf_names[ns] = {k: v for k, v in p.conf.items() if k not in emu and v}

        # ---------- server usage ----------
        sent, handled, hints = {}, {}, {}
        for d in ("zone", "world"):
            base = r / d
            if not base.is_dir():
                self.log(f"(no {d}/ folder)")
                continue
            for f in walk(base, (".cpp", ".h", ".hpp")):
                rel = f.relative_to(r).as_posix()
                for i, line in enumerate(read(f).splitlines(), 1):
                    code = line.split("//", 1)[0]
                    if not code.strip():
                        continue
                    for m in OUT_RE.finditer(code):
                        op = m.group(1) or m.group(2)
                        sent.setdefault(op, []).append(f"{rel}:{i}")
                        for sz in re.findall(r"sizeof\(\s*(\w+)\s*\)", code):
                            hints.setdefault(op, [])
                            if sz not in hints[op]:
                                hints[op].append(sz)
                    m = IN_MAP_RE.match(code)
                    if m:
                        handled.setdefault(m.group(2), []).append(f"{rel}:{i} ({m.group(1)})")
                    elif d == "world" and f.name.lower() == "client.cpp":
                        m = IN_CASE_RE.match(code)
                        if m:
                            handled.setdefault(m.group(1), []).append(f"{rel}:{i} (world)")
        self.log(f"Server sends {len(sent)} opcodes, handles {len(handled)}")

        emu = set(self.emu_ops)
        self.rows = []
        for op in sorted(set(sent) | set(handled)):
            if op not in emu and op != "OP_Unknown":
                pass  # still list it; status will flag it
            row = Row(op, sent.get(op, []), handled.get(op, []))
            row.struct_hints = hints.get(op, [])
            for p in self.patches:
                row.per_client[p.name] = self.classify(op, row, p, op in emu)
            self.rows.append(row)
        if fetch_upstream:
            self.add_upstream_evidence()
        return self

    def add_upstream_evidence(self):
        """Links to upstream sources and a layout verdict for every opcode upstream maps."""
        try:
            lc = LayoutCompare(self, log=self.log).load()
        except Exception as e:
            self.log(f"  layout check skipped: {e}")
            return
        self.layouts = lc
        for r in self.rows:
            for p in self.patches:
                v = r.per_client[p.name]
                links = []
                ln = p.upstream_lines.get(r.opcode)
                if ln:
                    links.append(("value", gh_link(f"utils/patches/patch_{p.conf_name}.conf", ln)))
                al = KNOWN_ALIASES.get(r.opcode)
                if al and p.upstream_lines.get(al):
                    links.append((f"value as {al}", gh_link(f"utils/patches/patch_{p.conf_name}.conf", p.upstream_lines[al])))
                if not p.upstream.get(r.opcode):
                    v["links"], v["layout"] = links, ""
                    continue
                res = lc.compare(r.opcode, p.name)
                for kind in ("ENCODE", "DECODE"):
                    loc = res.get(kind + "_up_loc")
                    if loc:
                        links.append((f"upstream {kind.lower()}r", gh_link(*loc)))
                w = res["wire"]
                if w.get("up_loc"):
                    links.append((f"upstream struct {w['up_name']}", gh_link(*w["up_loc"])))
                v["links"] = links
                v["layout"] = lc.verdict(res)
                fd = v.get("fix_detail") or {}
                if fd.get("action") == "MAP" and "upstream value" in " ".join(fd.get("conf", [])):
                    fd = dict(fd)
                    fd["summary"] = "Upstream EQEmu maps this opcode. " + v["layout"]
                    v["fix_detail"] = fd
                    v["fix"] = f"MAP: {fd['summary']}"

    def fetch_upstream(self, conf_name):
        cache = Path(__file__).with_name(f".upstream_patch_{conf_name}.conf")
        try:
            with urllib.request.urlopen(UPSTREAM_CONF_URL.format(name=conf_name), timeout=15) as resp:
                data = resp.read().decode("utf-8", "ignore")
            cache.write_text(data, encoding="utf-8")
            self.log(f"  fetched upstream patch_{conf_name}.conf")
        except Exception as e:  # offline: fall back to cache
            if cache.exists():
                data = cache.read_text(encoding="utf-8")
                self.log(f"  upstream fetch failed ({e}); using cached copy")
            else:
                self.log(f"  upstream fetch failed ({e})")
                return {}, {}
        d, lines = {}, {}
        for n, line in enumerate(data.splitlines(), 1):
            m = CONF_RE.match(line)
            if m:
                d[m.group(1)] = int(m.group(2), 16)
                lines[m.group(1)] = n
        return d, lines

    # ---------- status ----------
    @staticmethod
    def suggest(op, p, row, others, alias, alias_val, up_val, out_st):
        pb = PLAYBOOK.get(op, {})
        entry = pb.get(p.name) or pb.get("*")
        if entry:
            return dict(entry)
        if alias_val:
            return {"action": "MAP", "summary": f"Same packet as {alias} in this client.",
                    "conf": [f"{op}=0x{alias_val:04x}    # = {alias}"]}
        if up_val:
            return {"action": "MAP", "summary": "Upstream EQEmu has a value for this opcode. Check the struct "
                                                "layout matches before relying on it.",
                    "conf": [f"{op}=0x{up_val:04x}    # upstream value"]}
        other = [f"{o.name} 0x{o.conf[op]:04x}" for o in others if o is not p and o.conf.get(op)]
        sending = out_st.startswith("BROKEN")
        if other:
            return {"action": "INVESTIGATE",
                    "summary": f"Exists in {', '.join(other)} but has no {p.conf_name} value here"
                               + (" or upstream" if p.upstream else "") +
                               ". Find the equivalent RoF2-era packet (upstream rof2.cpp, ShowEQ) before eating it."}
        if p.upstream:  # upstream has it at 0 or doesn't list it at all
            return {"action": "NOT NEEDED",
                    "summary": f"Upstream also has no {p.conf_name} opcode for this"
                               + ("; the client ignores it." if sending else "; the client never sends it."),
                    "eat": sending}
        return {"action": "INVESTIGATE",
                "summary": "No value known. Tick 'Compare with upstream EQEmu' and rescan for more context."}

    def classify(self, op, row, p: Patch, known: bool):
        others = self.patches
        val = p.conf.get(op)
        unmapped = val is None or val == 0
        wire = "MISSING" if val is None else f"0x{val:04x}"
        tr = []
        if op in p.eats:
            tr.append("EAT")
        elif op in p.encoders:
            tr.append("ENCODE")
        if op in p.decoders:
            tr.append("DECODE")
        out_st = in_st = ""
        fixd = None
        up = p.upstream
        alias = KNOWN_ALIASES.get(op)
        alias_val = None
        if alias:
            alias_val = p.conf.get(alias) or up.get(alias)
        up_val = up.get(op) if up else None

        if not known:
            out_st = "BROKEN: not in emu opcode enum" if row.sent_from else ""
            in_st = "BROKEN: not in emu opcode enum" if row.handled_in else ""
        else:
            if row.sent_from:
                if op in p.eats:
                    out_st = "OK: eaten"
                elif op in REROUTED:
                    out_st = "OK: " + REROUTED[op]
                elif unmapped:
                    out_st = "BROKEN: sent as 0x0000"
                elif op in p.encoders:
                    out_st = "Translated: verify"
                else:
                    out_st = "Passthrough: verify layout"
            if row.handled_in:
                if unmapped:
                    in_st = "UNREACHABLE: no wire opcode"
                elif op in p.decoders:
                    in_st = "Translated: verify"
                else:
                    in_st = "Passthrough: verify layout"

            if unmapped and (out_st.startswith("BROKEN") or in_st.startswith("UNREACHABLE")):
                fixd = Scan.suggest(op, p, row, others, alias, alias_val, up_val, out_st)
            if val and up_val and val != up_val:
                fixd = fixd or {}
                fixd = dict(fixd, check=f"ours 0x{val:04x} vs upstream 0x{up_val:04x}: verify which is right")

        fix_txt = ""
        if fixd:
            fix_txt = (f"{fixd['action']}: {fixd['summary']}" if fixd.get("action") else "")
            if fixd.get("check"):
                fix_txt = (fix_txt + " | " if fix_txt else "") + "CHECK " + fixd["check"]
        return {
            "wire": wire,
            "upstream": ("" if not up else ("MISSING" if up_val is None else f"0x{up_val:04x}")),
            "translator": "+".join(tr) or "passthrough",
            "out": out_st,
            "in": in_st,
            "fix": fix_txt,
            "fix_detail": fixd or {},
            "links": [],
            "layout": "",
        }

    # ---------- exports ----------
    def flat(self):
        out = []
        for r in self.rows:
            d = {"Opcode": r.opcode, "Direction": r.direction,
                 "Sent from": "; ".join(r.sent_from), "Handled in": "; ".join(r.handled_in)}
            for c, v in r.per_client.items():
                d[f"{c} wire"] = v["wire"]
                d[f"{c} upstream"] = v["upstream"]
                d[f"{c} translator"] = v["translator"]
                d[f"{c} outbound"] = v["out"]
                d[f"{c} inbound"] = v["in"]
                d[f"{c} suggested fix"] = v["fix"]
                d[f"{c} fix lines"] = " / ".join(v.get("fix_detail", {}).get("conf", []))
                d[f"{c} layout vs upstream"] = v.get("layout", "")
                d[f"{c} upstream links"] = " ".join(u for _, u in v.get("links", []))
            out.append(d)
        return out

    def write_csv(self, path):
        rows = self.flat()
        if not rows:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    def fix_snippet(self, client):
        p = next(p for p in self.patches if p.name == client)
        groups = {}
        for r in self.rows:
            v = r.per_client.get(client)
            if not v or not v.get("fix_detail"):
                continue
            d = v["fix_detail"]
            groups.setdefault(d.get("action") or "CHECK", []).append((r, d))
        order = ["MAP", "REROUTE", "SERVER", "CUSTOM", "PORT", "INVESTIGATE", "NOT NEEDED", "CHECK"]
        titles = {
            "MAP": f"Add to patch_{p.conf_name}.conf (the packet layout already matches)",
            "REROUTE": f"Translate to an opcode {client} has (encoder in {client.lower()}.cpp)",
            "SERVER": f"Change the server code for {client} clients",
            "CUSTOM": "Needs a value from your modified client",
            "PORT": "Feature needs upstream's newer implementation",
            "INVESTIGATE": "Look at these before changing anything",
            "NOT NEEDED": f"{client} has no such packet (upstream sends these unmapped too). Optional cleanup",
            "CHECK": "Value differs from upstream",
        }
        out = [f"Suggested fixes for {client}  (repo: {self.root})", ""]
        conf_all, ops_all, eat_all = [], [], []
        for act in order:
            items = groups.get(act)
            if not items:
                continue
            out += ["=" * 78, f"{act}: {titles[act]}", "=" * 78]
            for r, d in items:
                out += ["", f"--- {r.opcode}"]
                if d.get("summary"):
                    out.append(f"    {d['summary']}")
                if d.get("check"):
                    out.append(f"    CHECK: {d['check']}")
                v = r.per_client.get(client, {})
                if v.get("layout") and v["layout"] not in d.get("summary", ""):
                    out.append(f"    {v['layout']}")
                for label, url in v.get("links", []):
                    out.append(f"    {label}: {url}")
                where = r.sent_from[:3] + r.handled_in[:2]
                if where:
                    out.append("    seen at: " + ", ".join(where))
                for c in d.get("conf", []):
                    out.append(f"    conf:  {c}")
                    conf_all.append(c)
                for e in d.get("ops_h", []):
                    out.append(f"    {client.lower()}_ops.h:  {e}")
                    ops_all.append(e)
                if d.get("extra"):
                    out += ["", *("    " + l for l in d["extra"].splitlines())]
                if d.get("code"):
                    out += ["", *("    " + l for l in d["code"].splitlines())]
                if d.get("eat"):
                    eat_all.append(r.opcode)
            out.append("")
        out += ["=" * 78, "Copy-paste summary", "=" * 78,
                f"# patch_{p.conf_name}.conf", *(conf_all or ["# (none)"]), "",
                f"// {client.lower()}_ops.h", *(ops_all + [f"E({o})" for o in eat_all] or ["// (none)"]), "",
                f"// {client.lower()}.cpp  (optional: silence packets {client} doesn't have)",
                *([f"EAT_ENCODE({o})" for o in eat_all] or ["// (none)"])]
        return "\n".join(out)

    def write_html(self, path):
        data = json.dumps(self.flat()).replace("</", "<\\/")
        clients = json.dumps([p.name for p in self.patches])
        Path(path).write_text(HTML_TEMPLATE.replace("__DATA__", data).replace("__CLIENTS__", clients)
                              .replace("__ROOT__", html.escape(str(self.root))), encoding="utf-8")


def category(status: str) -> str:
    if not status:
        return ""
    if status.startswith("BROKEN"):
        return "bad"
    if status.startswith("UNREACHABLE"):
        return "warn"
    if status.startswith("OK"):
        return "ok"
    return "info"


def worst(v: dict) -> str:
    cats = {category(v["out"]), category(v["in"])}
    for c in ("bad", "warn", "info", "ok"):
        if c in cats:
            return c
    return "ok"



# ======================================================================
# Struct layouts: ours vs upstream
# ======================================================================
import difflib

UPSTREAM_RAW = "https://raw.githubusercontent.com/EQEmu/EQEmu/refs/heads/{ref}/{path}"
UPSTREAM_STRUCT_FILES = [
    "common/eq_packet_structs.h", "common/textures.h", "common/emu_constants.h", "common/eq_constants.h",
    "common/eq_limits.h", "common/emu_versions.h",
]
PATCH_SOURCES = ["{lc}.cpp", "{lc}_structs.h", "{lc}_limits.h", "{lc}_constants.h", "{lc}_ops.h"]

BASE_SIZES = {
    "uint8": 1, "int8": 1, "uchar": 1, "char": 1, "bool": 1, "BYTE": 1, "byte": 1, "uint8_t": 1, "int8_t": 1,
    "unsigned char": 1, "signed char": 1,
    "uint16": 2, "int16": 2, "short": 2, "uint16_t": 2, "int16_t": 2, "unsigned short": 2, "WORD": 2,
    "uint32": 4, "int32": 4, "int": 4, "unsigned": 4, "unsigned int": 4, "float": 4, "DWORD": 4, "long": 4,
    "unsigned long": 4, "uint32_t": 4, "int32_t": 4, "signed int": 4,
    "uint64": 8, "int64": 8, "double": 8, "uint64_t": 8, "int64_t": 8, "long long": 8,
    "unsigned long long": 8, "time_t": 8, "size_t": 8,
}
NUM_RE = re.compile(r"\b(0x[0-9A-Fa-f]+|\d+)[uUlL]*\b")


class Consts:
    """Collects #define / const / enum values from header text and evaluates array sizes."""

    def __init__(self):
        self.raw = {}
        self.vals = {}

    def feed(self, text: str):
        for m in re.finditer(r"^\s*#\s*define\s+(\w+)\s+([^\n]+)", text, re.M):
            self.raw.setdefault(m.group(1), m.group(2).split("//")[0].strip())
        t = strip_comments(text)
        for m in re.finditer(r"\b(?:static\s+)?(?:const|constexpr)\s+[\w:<>\s]+?\b(\w+)\s*=\s*([^;{}]+);", t):
            self.raw.setdefault(m.group(1), m.group(2).strip())
        for m in re.finditer(r"\benum\b(?:\s+class)?(?:\s+\w+)?(?:\s*:\s*[\w:]+)?\s*\{([^}]*)\}", t):
            nxt = 0
            for item in m.group(1).split(","):
                item = item.strip()
                if not item:
                    continue
                if "=" in item:
                    k, v = item.split("=", 1)
                    k = k.strip()
                    val = self.eval(v.strip())
                    self.raw.setdefault(k, v.strip())
                    nxt = (val + 1) if isinstance(val, int) else nxt + 1
                else:
                    k = item.split()[0]
                    self.raw.setdefault(k, str(nxt))
                    nxt += 1

    def eval(self, expr: str, depth=0):
        if expr is None or depth > 12:
            return None
        e = re.sub(r"static_cast<[^>]+>", "", expr)
        e = re.sub(r"\b(?:[A-Za-z_]\w*::)+", "", e)          # drop namespaces
        e = NUM_RE.sub(lambda m: str(int(m.group(1), 0)), e)
        if re.search(r"sizeof|\?|\"|'", e):
            return None

        def sub(m):
            name = m.group(0)
            if name in self.vals:
                return str(self.vals[name])
            v = self.eval(self.raw.get(name), depth + 1) if name in self.raw else None
            if v is None:
                raise KeyError(name)
            self.vals[name] = v
            return str(v)

        try:
            e2 = re.sub(r"[A-Za-z_]\w*", sub, e)
            if not re.fullmatch(r"[\d\s+\-*/()%<>|&~^]+", e2):
                return None
            v = eval(e2, {"__builtins__": {}}, {})
            return int(v)
        except Exception:
            return None


@dataclass
class Field:
    off: object      # int or None
    size: object     # int or None
    type: str
    name: str
    note: str = ""


class StructDB:
    """Parses packed (#pragma pack(1)) C++ structs and computes field offsets."""

    def __init__(self, label: str):
        self.label = label
        self.bodies = {}     # name -> (base, body, source)
        self.locs = {}       # name -> (repo path, line)
        self.consts = Consts()
        self._cache = {}

    def feed(self, text: str, source: str, path: str = ""):
        self.consts.feed(text)
        t = strip_comments(text)
        for m in re.finditer(r"\b(struct|union)\s+(\w+)\s*(?::\s*(?:public\s+)?([\w:]+)[^{;]*)?\{", t):
            if m.group(2) not in self.locs:
                self.locs[m.group(2)] = (path, line_of(t, m.start()))
            start = m.end()
            depth, i = 1, start
            while i < len(t) and depth:
                c = t[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                i += 1
            name = m.group(2)
            if name not in self.bodies:
                self.bodies[name] = (m.group(3), t[start:i - 1], source, m.group(1) == "union")

    def has(self, name):
        return name in self.bodies

    def layout(self, name, _stack=()):
        name = name.split("::")[-1]
        if name in self._cache:
            return self._cache[name]
        if name not in self.bodies or name in _stack:
            return None
        base, body, src, is_union = self.bodies[name]
        fields = []
        off = 0
        if base:
            bl = self.layout(base, _stack + (name,))
            if bl:
                fields += [Field(f.off, f.size, f.type, f.name, f.note) for f in bl[0]]
                off = bl[1]
            else:
                off = None
                fields.append(Field(0, None, base, "(base)", "unknown base"))
        flist, size = self._parse_members(body, off, is_union, _stack + (name,))
        fields += flist
        res = (fields, size, src)
        self._cache[name] = res
        return res

    def _type_size(self, typ, stack):
        t = re.sub(r"\b(const|volatile|mutable|struct|class|union|enum)\b", "", typ).strip()
        t = re.sub(r"\s+", " ", t)
        if "*" in t:
            return 8, "pointer: size depends on build"
        if t in BASE_SIZES:
            return BASE_SIZES[t], ""
        short = t.split("::")[-1]
        if short in BASE_SIZES:
            return BASE_SIZES[short], ""
        if short in ("string", "vector", "list", "map") or "std::" in t or "<" in t:
            return None, "C++ container: not a wire type"
        sub = self.layout(short, stack)
        if sub:
            return sub[1], ""
        return None, f"unknown type {short}"

    def _split_members(self, body):
        """Yield ('decl', text) or ('agg', kind, inner, declarators) at depth 0."""
        i, n, buf = 0, len(body), ""
        while i < n:
            c = body[i]
            if c == "{":
                # find matching brace
                depth, j = 1, i + 1
                while j < n and depth:
                    depth += {"{": 1, "}": -1}.get(body[j], 0)
                    j += 1
                inner = body[i + 1:j - 1]
                head = buf.strip()
                if re.search(r"\)\s*(const)?\s*(noexcept)?\s*(override)?\s*$", head) or re.match(r"(template|enum)\b", head):
                    buf = ""          # inline function body / nested enum: skip
                    i = j
                    if i < n and body[i] == ";":
                        i += 1
                    continue
                m = re.match(r"(struct|union)\s*(\w+)?\s*$", head)
                if m:
                    k = body.find(";", j)
                    decl = body[j:k] if k >= 0 else ""
                    yield ("agg", m.group(1), inner, decl.strip(), m.group(2))
                    buf = ""
                    i = k + 1 if k >= 0 else n
                    continue
                buf += body[i:j]          # brace initializer, keep
                i = j
                continue
            if c == ";":
                if buf.strip():
                    yield ("decl", buf.strip())
                buf = ""
            else:
                buf += c
            i += 1

    def _parse_members(self, body, start_off, is_union, stack):
        fields = []
        off = start_off
        max_end = start_off if start_off is not None else 0
        bit_unit = None  # (type, unit_size, bits_used, unit_off)

        def place(size):
            nonlocal off, max_end
            o = (start_off if is_union else off)
            if not is_union and off is not None:
                off = None if size is None else off + size
            if o is not None and size is not None:
                max_end = max(max_end or 0, o + size)
            elif size is None and not is_union:
                pass
            return o

        for item in self._split_members(body):
            if item[0] == "agg":
                _, kind, inner, decl, tag = item
                sub_fields, sub_size = self._parse_members(inner, 0, kind == "union", stack)
                if tag and tag not in self.bodies:
                    self.bodies[tag] = (None, inner, "nested", kind == "union")
                names = [d.strip() for d in decl.split(",") if d.strip()] if decl else []
                if not names:  # anonymous: splice children
                    o = place(sub_size)
                    for f in sub_fields:
                        fields.append(Field(None if o is None or f.off is None else o + f.off, f.size, f.type, f.name, f.note))
                    bit_unit = None
                    continue
                for d in names:
                    dm = re.match(r"(\w+)\s*((?:\[[^\]]*\])*)", d)
                    count, unk = self._dims(dm.group(2))
                    total = None if sub_size is None or count is None else sub_size * count
                    o = place(total)
                    if dm.group(2):
                        fields.append(Field(o, total, f"{kind} {{...}}{dm.group(2)}", dm.group(1), unk))
                    else:
                        for f in sub_fields:
                            fields.append(Field(None if o is None or f.off is None else o + f.off, f.size, f.type,
                                                f"{dm.group(1)}.{f.name}", f.note))
                bit_unit = None
                continue

            text = item[1]
            text = re.sub(r"^\s*(public|private|protected)\s*:", "", text).strip()
            if not text or re.match(r"(static|using|typedef|friend|template|enum|virtual|explicit|operator|~)\b", text):
                continue
            if "(" in text and not re.search(r"\[[^\]]*\(", text):
                if re.match(r"[\w:<>,\s*&]+\(", text):
                    continue  # function declaration
            text = re.sub(r"\s*=\s*[^,]+", "", text)        # default initializers
            text = re.sub(r"\{[^}]*\}", "", text)
            m = re.match(r"((?:unsigned|signed|long|short|const|volatile|struct)\s+)*([\w:<>]+(?:\s*\*+)?)\s+(.*)$", text, re.S)
            if not m:
                continue
            typ = (m.group(1) or "") + m.group(2)
            typ = re.sub(r"\s+", " ", typ.replace("const ", "").replace("struct ", "")).strip()
            decls = m.group(3)
            for d in [x.strip() for x in decls.split(",") if x.strip()]:
                dm = re.match(r"(\**)\s*(\w+)\s*((?:\[[^\]]*\])*)\s*(?::\s*(.+))?$", d)
                if not dm:
                    continue
                ptr, name, dims, bits = dm.groups()
                ftype = typ + ("*" if ptr else "")
                esize, note = self._type_size(ftype, stack)
                if bits is not None:
                    nb = self.consts.eval(bits)
                    unit = esize or 4
                    if bit_unit and bit_unit[0] == ftype and nb is not None and bit_unit[2] + nb <= unit * 8:
                        o = bit_unit[3]
                        bit_unit = (ftype, unit, bit_unit[2] + nb, o)
                    else:
                        o = place(unit)
                        bit_unit = (ftype, unit, nb or 0, o)
                    fields.append(Field(o, unit, f"{ftype} :{bits}", name, "bitfield (layout approximate)"))
                    continue
                bit_unit = None
                count, unk = self._dims(dims)
                total = None if esize is None or count is None else esize * count
                o = place(total)
                fields.append(Field(o, total, ftype + dims, name, "; ".join(x for x in (note, unk) if x)))
        size = (max_end if is_union else off)
        return fields, size

    def _dims(self, dims):
        if not dims:
            return 1, ""
        count = 1
        for ex in re.findall(r"\[([^\]]*)\]", dims):
            if ex.strip() == "" or ex.strip() == "0":
                return 0, "flexible array (variable length)"
            v = self.consts.eval(ex)
            if v is None:
                return None, f"array size '{ex}' unknown"
            count *= v
        return count, ""


def extract_block(src: str, kind: str, op: str):
    """Return the text of ENCODE(op)/DECODE(op) from a patch .cpp."""
    m = re.search(r"\b%s\(\s*%s\s*\)" % (kind, re.escape(op)), src)
    if not m:
        m2 = re.search(r"EAT_ENCODE\(\s*%s\s*\)" % re.escape(op), src) if kind == "ENCODE" else None
        return m2.group(0) if m2 else None
    i = src.find("{", m.end())
    if i < 0:
        return None
    depth, j = 1, i + 1
    while j < len(src) and depth:
        depth += {"{": 1, "}": -1}.get(src[j], 0)
        j += 1
    return src[m.start():j]


SERIAL_RE = re.compile(
    r"(Write(?:UInt8|UInt16|UInt32|UInt64|SInt32|Float|Double|String)|VARSTRUCT_ENCODE_(?:TYPE|STRING)|"
    r"VARSTRUCT_DECODE_(?:TYPE|STRING)|ReadUInt\w+|OUT(?:_str|_array)?|IN)\s*\((.*)\)")


def serialization_steps(block: str):
    steps = []
    if not block:
        return steps
    for line in block.splitlines():
        line = line.split("//")[0].strip()
        m = SERIAL_RE.search(line)
        if m:
            op, arg = m.group(1), re.sub(r"\s+", " ", m.group(2)).strip()
            steps.append(f"{op}({arg})")
    return steps


def structs_in_block(block: str):
    """(emu struct, wire struct) from SETUP_* macros in an encoder/decoder."""
    if not block:
        return None, None
    m = re.search(r"SETUP_DIRECT_(?:EN|DE)CODE\(\s*([\w:]+)\s*,\s*([\w:]+)\s*\)", block)
    if m:
        a, b = m.group(1), m.group(2)
        if "DECODE" in m.group(0):
            return a.split("::")[-1], b.split("::")[-1]
        return a.split("::")[-1], b.split("::")[-1]
    emu = re.search(r"SETUP_VAR_ENCODE\(\s*([\w:]+)\s*\)", block) or re.search(r"\(\s*([A-Z]\w*_Struct)\s*\*\s*\)\s*__emu_buffer", block)
    wire = re.search(r"structs::(\w+)", block)
    return (emu.group(1).split("::")[-1] if emu else None), (wire.group(1) if wire else None)


def norm(n):
    return re.sub(r"[^a-z0-9.]", "", n.lower())


def align_fields(a, b):
    """Align two field lists by name; returns rows (fa, fb, status)."""
    an, bn = [norm(f.name) for f in a], [norm(f.name) for f in b]
    sm = difflib.SequenceMatcher(None, an, bn, autojunk=False)
    rows = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for fa, fb in zip(a[i1:i2], b[j1:j2]):
                if fa.off != fb.off and fa.size == fb.size:
                    st = "moved"
                elif fa.size != fb.size:
                    st = "size differs"
                elif fa.type.replace(" ", "") != fb.type.replace(" ", ""):
                    st = "type differs"
                else:
                    st = "same"
                rows.append((fa, fb, st))
        elif tag == "replace":
            la, lb = a[i1:i2], b[j1:j2]
            for k in range(max(len(la), len(lb))):
                fa = la[k] if k < len(la) else None
                fb = lb[k] if k < len(lb) else None
                if fa and fb:
                    st = "renamed" if fa.off == fb.off and fa.size == fb.size else "different"
                else:
                    st = "only ours" if fa else "only upstream"
                rows.append((fa, fb, st))
        elif tag == "delete":
            rows += [(f, None, "only ours") for f in a[i1:i2]]
        else:
            rows += [(None, f, "only upstream") for f in b[j1:j2]]
    return rows


def align_by_offset(a, b):
    """Pair fields that sit at the same byte offset (what the client actually parses)."""
    def key(f):
        return (f.off is None, f.off if f.off is not None else 0)
    a, b = sorted(a, key=key), sorted(b, key=key)
    i = j = 0
    rows = []
    while i < len(a) or j < len(b):
        fa = a[i] if i < len(a) else None
        fb = b[j] if j < len(b) else None
        if fa and fb and fa.off is not None and fa.off == fb.off:
            na, nb = norm(fa.name), norm(fb.name)
            if fa.size != fb.size:
                st = "size differs"
            elif na == nb:
                st = "same"
            elif na.startswith("unknown") or nb.startswith("unknown") or "unknown" in na or "unknown" in nb:
                st = "renamed"
            else:
                st = "different"
            rows.append((fa, fb, st))
            i += 1
            j += 1
        elif fb is None or (fa is not None and key(fa) < key(fb)):
            rows.append((fa, None, "only ours"))
            i += 1
        else:
            rows.append((None, fb, "only upstream"))
            j += 1
    return rows


class UpstreamSource:
    """Fetches upstream EQEmu files on demand, cached next to the script."""

    def __init__(self, ref="master", log=print):
        self.ref = ref
        self.log = log
        self.dir = Path(__file__).with_name(".upstream_cache") / ref
        self.dir.mkdir(parents=True, exist_ok=True)

    def get(self, path):
        local = self.dir / path.replace("/", "__")
        if local.exists():
            return local.read_text(encoding="utf-8", errors="ignore")
        try:
            with urllib.request.urlopen(UPSTREAM_RAW.format(ref=self.ref, path=path), timeout=20) as r:
                data = r.read().decode("utf-8", "ignore")
            local.write_text(data, encoding="utf-8")
            return data
        except Exception as e:
            self.log(f"  upstream {path}: {e}")
            return ""


class LayoutCompare:
    """Builds struct DBs for ours and upstream, per client patch."""

    def __init__(self, scan, ref="master", log=print):
        self.scan = scan
        self.log = log
        self.up = UpstreamSource(ref, log)
        self.ours_internal = StructDB("ours")
        self.up_internal = StructDB("upstream")
        self.ours_wire = {}
        self.up_wire = {}
        self.ours_src = {}
        self.up_src = {}
        self._loaded = False

    def load(self):
        if self._loaded:
            return self
        root = self.scan.root
        common = root / "common"
        for f in sorted(common.glob("*.h")):
            self.ours_internal.feed(read(f), f.name)
        for path in UPSTREAM_STRUCT_FILES:
            self.up_internal.feed(self.up.get(path), "upstream " + path, path)
        pdir = (root / "common" / "patches")
        for p in self.scan.patches:
            lc = p.name.lower()
            ow, uw = StructDB(f"ours {p.name}"), StructDB(f"upstream {p.name}")
            # constants from the shared headers help with array sizes in wire structs
            for f in sorted(common.glob("*.h")):
                ow.consts.feed(read(f))
            for path in UPSTREAM_STRUCT_FILES:
                uw.consts.feed(self.up.get(path))
            src_o, src_u = "", ""
            for pat in PATCH_SOURCES:
                name = pat.format(lc=lc)
                f = next((x for x in pdir.glob("*") if x.name.lower() == name), None)
                if f:
                    txt = read(f)
                    ow.feed(txt, f.name)
                    if name.endswith(".cpp"):
                        src_o = txt
                utxt = self.up.get(f"common/patches/{name}")
                if utxt:
                    uw.feed(utxt, "upstream " + name, f"common/patches/{name}")
                    if name.endswith(".cpp"):
                        src_u = utxt
            self.ours_wire[p.name], self.up_wire[p.name] = ow, uw
            self.ours_src[p.name] = src_o
            self.up_src[p.name] = src_u
        self._loaded = True
        return self

    def compare(self, op, client):
        """Everything known about how ours and upstream build this opcode for `client`."""
        self.load()
        row = next((r for r in self.scan.rows if r.opcode == op), None)
        res = {"opcode": op, "client": client}
        for kind in ("ENCODE", "DECODE"):
            ob = extract_block(self.ours_src.get(client, ""), kind, op)
            ub = extract_block(self.up_src.get(client, ""), kind, op)
            res[kind] = (ob, ub)
            usrc = self.up_src.get(client, "")
            if ub and usrc:
                pos = usrc.find(ub)
                if pos >= 0:
                    res[kind + "_up_loc"] = (f"common/patches/{client.lower()}.cpp", line_of(usrc, pos))
        oe, ow = structs_in_block(res["ENCODE"][0] or res["DECODE"][0])
        ue, uw = structs_in_block(res["ENCODE"][1] or res["DECODE"][1])
        hint = list(row.struct_hints) if row else []
        guess = op[3:] + "_Struct"
        if self.ours_internal.has(guess) and guess not in hint:
            hint.append(guess)
        hint = [h for h in hint if self.ours_internal.has(h)] or hint
        oe = oe or (hint[0] if hint else None)
        res["candidates"] = hint
        ue = ue or oe
        passthrough = not res["ENCODE"][0] and not res["DECODE"][0]
        if passthrough:
            # Nothing translates it: the client gets our server struct byte-for-byte.
            uw = uw or (oe if oe and self.up_wire[client].has(oe) else None)
            up_db = self.up_wire[client]
            if not uw and not res["ENCODE"][1] and not res["DECODE"][1] and oe and self.up_internal.has(oe):
                # upstream also sends it untranslated, so its server struct is what the client gets
                uw, up_db = oe, self.up_internal
            res["wire"] = self._pair(self.ours_internal, oe, up_db, uw, by_offset=True)
            if res["wire"]["ours_name"]:
                res["wire"]["ours_name"] += " (server struct, sent as-is)"
        else:
            ow = ow or (oe if oe and self.ours_wire[client].has(oe) else None)
            uw = uw or ow
            res["wire"] = self._pair(self.ours_wire[client], ow, self.up_wire[client], uw, by_offset=True)
        res["internal"] = self._pair(self.ours_internal, oe, self.up_internal, ue)
        res["serial"] = (serialization_steps(res["ENCODE"][0] or res["DECODE"][0]),
                         serialization_steps(res["ENCODE"][1] or res["DECODE"][1]))
        res["passthrough"] = passthrough
        return res

    @staticmethod
    def _pair(db_a, name_a, db_b, name_b, by_offset=False):
        la = db_a.layout(name_a) if name_a else None
        lb = db_b.layout(name_b) if name_b else None
        fa, fb = (la[0] if la else []), (lb[0] if lb else [])
        return {"ours_name": name_a, "up_name": name_b, "ours": la, "up": lb,
                "up_loc": db_b.locs.get((name_b or "").split("::")[-1]),
                "rows": align_by_offset(fa, fb) if by_offset else align_fields(fa, fb)}

    @staticmethod
    def verdict(res):
        """One-line answer: does what we send match what upstream sends this client?"""
        w = res["wire"]
        client = res["client"]
        on, un = w["ours_name"], w["up_name"]
        if res["passthrough"] and res["ENCODE"][1]:
            extra = " Upstream has an encoder for it; we don't."
        elif not res["passthrough"] and not res["ENCODE"][1] and not res["DECODE"][1]:
            extra = " We translate it; upstream sends it as-is."
        else:
            extra = ""
        if not w["ours"] or not w["up"]:
            if w["ours"] is None and w["up"] is None:
                return "Layout: no fixed struct found on either side (variable-length or built by hand); compare the encoders." + extra
            missing = "ours" if not w["ours"] else "upstream"
            return f"Layout: couldn't find the {missing} struct ({on if missing == 'ours' else un}) to compare." + extra
        so, su = w["ours"][1], w["up"][1]
        bad = [(fa, fb, st) for fa, fb, st in w["rows"] if st not in ("same", "renamed")]
        if not bad and so == su:
            return f"Layout MATCHES: {on.split(' (')[0]} and upstream {un} are both {so} bytes with the same fields." + extra
        first = []
        for fa, fb, st in bad[:3]:
            off = fa.off if fa else fb.off
            if st == "size differs":
                first.append(f"@{off}: {fa.name} is {fmt(fa.size)} bytes, upstream {fb.name} is {fmt(fb.size)}")
            elif fa and fb:
                first.append(f"@{off}: ours {fa.name}, upstream {fb.name}")
            else:
                first.append(f"@{off}: {'ours only ' + fa.name if fa else 'upstream only ' + fb.name}")
        return (f"Layout DIFFERS: ours {so} bytes vs upstream {su} bytes, {len(bad)} field difference(s) ("
                + "; ".join(first) + (" ..." if len(bad) > 3 else "") + "). Use Compare with upstream for details." + extra)

    def report_text(self, res):
        out = [f"{res['opcode']}  ({res['client']})", "=" * 100]
        if res["passthrough"]:
            out.append(f"No {res['client']} encoder/decoder in our patch: the server struct is sent as-is.")
        if len(res.get("candidates", [])) > 1:
            out.append("Other structs used with this opcode: " + ", ".join(res["candidates"][1:]))
        for key, title in (("wire", f"{res['client']} wire format, aligned by byte offset (what the client parses)"),
                           ("internal", "Server-side struct (eq_packet_structs.h), aligned by field name")):
            pr = res[key]
            out += ["", title, "-" * 100]
            os_ = f"{pr['ours_name']} = {pr['ours'][1]} bytes" if pr["ours"] else f"{pr['ours_name'] or '?'}: not found"
            us_ = f"{pr['up_name']} = {pr['up'][1]} bytes" if pr["up"] else f"{pr['up_name'] or '?'}: not found"
            out.append(f"  ours: {os_}    upstream: {us_}")
            out.append(f"  {'off':>5} {'size':>5}  {'ours':<38} {'status':<14} {'off':>5} {'size':>5}  upstream")
            for fa, fb, st in pr["rows"]:
                a = (f"{fmt(fa.off):>5} {fmt(fa.size):>5}  {(fa.type + ' ' + fa.name)[:38]:<38}") if fa else " " * 51
                b = (f"{fmt(fb.off):>5} {fmt(fb.size):>5}  {fb.type} {fb.name}") if fb else ""
                out.append(f"  {a} {st:<14} {b}")
        so, su = res["serial"]
        if so or su:
            out += ["", "Serialization order (encoder/decoder write/read calls)", "-" * 100]
            for line in difflib.unified_diff(su, so, "upstream", "ours", lineterm="", n=2):
                out.append("  " + line)
        for kind in ("ENCODE", "DECODE"):
            ob, ub = res[kind]
            if ob or ub:
                out += ["", f"{kind}({res['opcode']}) diff (upstream -> ours)", "-" * 100]
                if not ub:
                    out.append("  (upstream has none)")
                if not ob:
                    out.append("  (ours has none)")
                if ob and ub:
                    d = list(difflib.unified_diff(ub.splitlines(), ob.splitlines(), "upstream", "ours", lineterm="", n=3))
                    out += ["  " + l for l in d] or ["  identical"]
        return "\n".join(out)

    def struct_report(self, client):
        """Size comparison for every struct name present in both trees."""
        self.load()
        rows = []
        for label, a, b in (("server", self.ours_internal, self.up_internal),
                            (client, self.ours_wire[client], self.up_wire[client])):
            for name in sorted(set(a.bodies) & set(b.bodies)):
                la, lb = a.layout(name), b.layout(name)
                sa = la[1] if la else None
                sb = lb[1] if lb else None
                if sa != sb or not la or not lb:
                    diffs = [st for _, _, st in align_fields(la[0] if la else [], lb[0] if lb else []) if st != "same"]
                else:
                    diffs = [st for _, _, st in align_fields(la[0], lb[0]) if st != "same"]
                rows.append({"layer": label, "struct": name, "ours_size": sa, "upstream_size": sb,
                             "field_differences": len(diffs),
                             "status": "same" if sa == sb and not diffs else ("SIZE DIFFERS" if sa != sb else "layout differs")})
        return rows


def fmt(v):
    return "?" if v is None else str(v)


# ======================================================================
# GUI
# ======================================================================
def run_gui(initial_root: str | None, fetch_upstream: bool):
    import threading
    import webbrowser
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    BG, PANEL, FG, MUTED, ACCENT = "#14191a", "#1c2324", "#e2e8e6", "#8fa09b", "#5fbfa3"
    COLORS = {"bad": "#ff7a6e", "warn": "#f0c060", "info": "#9db8ea", "ok": "#86d19b"}

    root = tk.Tk()
    root.title("Opcode Inspector")
    root.geometry("1400x820")
    root.configure(bg=BG)
    st = ttk.Style(root)
    st.theme_use("clam")
    st.configure(".", background=BG, foreground=FG, fieldbackground=PANEL, font=("Segoe UI", 10))
    st.configure("TFrame", background=BG)
    st.configure("TLabel", background=BG, foreground=FG)
    st.configure("Muted.TLabel", foreground=MUTED)
    st.configure("Title.TLabel", font=("Segoe UI Semibold", 15))
    st.configure("TButton", background=PANEL, foreground=FG, borderwidth=1, padding=(10, 4))
    st.map("TButton", background=[("active", "#26302f")])
    st.configure("Accent.TButton", background=ACCENT, foreground="#0c1412")
    st.map("Accent.TButton", background=[("active", "#7fd6bc")])
    st.configure("TEntry", fieldbackground=PANEL, foreground=FG, insertcolor=FG)
    st.configure("TCombobox", fieldbackground=PANEL, foreground=FG, background=PANEL, arrowcolor=FG)
    st.map("TCombobox", fieldbackground=[("readonly", PANEL)], foreground=[("readonly", FG)])
    st.configure("TCheckbutton", background=BG, foreground=FG)
    st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, rowheight=24,
                 font=("Consolas", 10), borderwidth=0)
    st.configure("Treeview.Heading", background="#232c2d", foreground=MUTED, font=("Segoe UI Semibold", 9),
                 relief="flat")
    st.map("Treeview", background=[("selected", "#2d4a43")])
    st.configure("Chip.TButton", padding=(10, 6))
    st.configure("TNotebook", background=BG, borderwidth=0)
    st.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(12, 5))
    st.map("TNotebook.Tab", background=[("selected", "#2d4a43")], foreground=[("selected", FG)])

    state = {"scan": None, "cat": ""}

    # --- top bar
    top = ttk.Frame(root, padding=(14, 12, 14, 4))
    top.pack(fill="x")
    ttk.Label(top, text="Opcode Inspector", style="Title.TLabel").pack(side="left")
    path_var = tk.StringVar(value=initial_root or "")
    ttk.Entry(top, textvariable=path_var, width=70).pack(side="left", padx=(18, 6))

    def browse():
        d = filedialog.askdirectory(title="Choose your server repo root (the folder with common/, zone/, world/)")
        if d:
            path_var.set(d)

    ttk.Button(top, text="Browse…", command=browse).pack(side="left")
    up_var = tk.BooleanVar(value=fetch_upstream)
    ttk.Checkbutton(top, text="Compare with upstream EQEmu", variable=up_var).pack(side="left", padx=12)
    scan_btn = ttk.Button(top, text="Scan", style="Accent.TButton")
    scan_btn.pack(side="left")

    # --- filters
    bar = ttk.Frame(root, padding=(14, 6))
    bar.pack(fill="x")
    ttk.Label(bar, text="Client", style="Muted.TLabel").pack(side="left")
    client_var = tk.StringVar()
    client_cb = ttk.Combobox(bar, textvariable=client_var, state="readonly", width=10)
    client_cb.pack(side="left", padx=(6, 16))
    ttk.Label(bar, text="Direction", style="Muted.TLabel").pack(side="left")
    dir_var = tk.StringVar(value="All")
    ttk.Combobox(bar, textvariable=dir_var, state="readonly", width=12,
                 values=["All", "Server sends", "Server handles"]).pack(side="left", padx=(6, 16))
    ttk.Label(bar, text="Search", style="Muted.TLabel").pack(side="left")
    q_var = tk.StringVar()
    ttk.Entry(bar, textvariable=q_var, width=30).pack(side="left", padx=6)
    count_lbl = ttk.Label(bar, text="", style="Muted.TLabel")
    count_lbl.pack(side="right")

    chips = ttk.Frame(root, padding=(14, 2, 14, 8))
    chips.pack(fill="x")
    chip_btns = {}
    labels = {"bad": "Broken", "warn": "Unreachable", "info": "Wired, verify", "ok": "OK"}
    for k in ("bad", "warn", "info", "ok"):
        b = tk.Button(chips, text=labels[k], bg=PANEL, fg=COLORS[k], activebackground="#26302f",
                      activeforeground=COLORS[k], relief="flat", bd=0, padx=14, pady=6,
                      font=("Segoe UI Semibold", 10), cursor="hand2")
        b.pack(side="left", padx=(0, 8))
        chip_btns[k] = b

    # --- table + detail
    pane = ttk.PanedWindow(root, orient="vertical")
    pane.pack(fill="both", expand=True, padx=14, pady=(0, 8))
    tf = ttk.Frame(pane)
    cols = ("opcode", "dir", "wire", "upstream", "translator", "out", "inn", "fix")
    heads = ("Opcode", "Dir", "Wire", "Upstream", "Translator", "Outbound", "Inbound", "Suggested fix")
    widths = (260, 70, 80, 85, 120, 230, 220, 330)
    tree = ttk.Treeview(tf, columns=cols, show="headings", selectmode="browse")
    for c, h, w in zip(cols, heads, widths):
        tree.heading(c, text=h, command=lambda c=c: sort_by(c))
        tree.column(c, width=w, anchor="w", stretch=c in ("fix", "out"))
    for k, col in COLORS.items():
        tree.tag_configure(k, foreground=col)
    vs = ttk.Scrollbar(tf, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vs.set)
    tree.pack(side="left", fill="both", expand=True)
    vs.pack(side="right", fill="y")
    pane.add(tf, weight=4)

    detail = tk.Text(pane, height=10, bg=PANEL, fg=FG, insertbackground=FG, relief="flat",
                     font=("Consolas", 10), wrap="word", padx=10, pady=8)
    pane.add(detail, weight=1)

    # --- bottom buttons
    bot = ttk.Frame(root, padding=(14, 0, 14, 12))
    bot.pack(fill="x")
    status_lbl = ttk.Label(bot, text="Choose your repo folder and press Scan.", style="Muted.TLabel")
    status_lbl.pack(side="left")

    sort_state = {"col": None, "rev": False}

    def sort_by(c):
        sort_state["rev"] = not sort_state["rev"] if sort_state["col"] == c else False
        sort_state["col"] = c
        refresh()

    def refresh(*_):
        tree.delete(*tree.get_children())
        sc = state["scan"]
        if not sc:
            return
        cl = client_var.get()
        q = q_var.get().strip().lower()
        d = dir_var.get()
        counts = {k: 0 for k in COLORS}
        items = []
        for r in sc.rows:
            v = r.per_client.get(cl)
            if not v:
                continue
            w = worst(v)
            counts[w] += 1
            if d == "Server sends" and not r.sent_from:
                continue
            if d == "Server handles" and not r.handled_in:
                continue
            if state["cat"] and w != state["cat"]:
                continue
            blob = " ".join([r.opcode, *r.sent_from, *r.handled_in, *(x for x in v.values() if isinstance(x, str))]).lower()
            if q and q not in blob:
                continue
            items.append((r, v, w))
        order = {"bad": 0, "warn": 1, "info": 2, "ok": 3}
        keymap = {"opcode": lambda t: t[0].opcode, "dir": lambda t: t[0].direction,
                  "wire": lambda t: t[1]["wire"], "upstream": lambda t: t[1]["upstream"],
                  "translator": lambda t: t[1]["translator"], "out": lambda t: t[1]["out"],
                  "inn": lambda t: t[1]["in"], "fix": lambda t: t[1]["fix"]}
        if sort_state["col"]:
            items.sort(key=keymap[sort_state["col"]], reverse=sort_state["rev"])
        else:
            items.sort(key=lambda t: (order[t[2]], t[0].opcode))
        for r, v, w in items:
            tree.insert("", "end", iid=r.opcode, tags=(w,),
                        values=(r.opcode, r.direction, v["wire"], v["upstream"], v["translator"],
                                v["out"], v["in"], v["fix"]))
        for k, b in chip_btns.items():
            b.configure(text=f"{counts[k]}  {labels[k]}", bg="#2d4a43" if state["cat"] == k else PANEL)
        count_lbl.configure(text=f"{len(items)} of {sum(counts.values())} opcodes")

    def show_detail(_=None):
        sel = tree.selection()
        detail.delete("1.0", "end")
        if not sel:
            return
        sc = state["scan"]
        r = next(x for x in sc.rows if x.opcode == sel[0])
        lines = [r.opcode, ""]
        for c, v in r.per_client.items():
            lines.append(f"[{c}] wire={v['wire']}  upstream={v['upstream'] or 'n/a'}  translator={v['translator']}")
            if v["out"]:
                lines.append(f"    outbound: {v['out']}")
            if v["in"]:
                lines.append(f"    inbound:  {v['in']}")
            if v["fix"]:
                lines.append(f"    fix:      {v['fix']}")
            fd = v.get("fix_detail") or {}
            for cl in fd.get("conf", []):
                lines.append(f"    conf:     {cl}")
            if v.get("layout"):
                lines.append(f"    layout:   {v['layout']}")
            for label, url in v.get("links", []):
                lines.append(f"    {label + ':':<10}{url}")
            if fd.get("code"):
                lines += ["", *("      " + l for l in fd["code"].splitlines()), ""]
        lines += ["", f"Sent from ({len(r.sent_from)}):"] + [f"    {s}" for s in r.sent_from]
        lines += ["", f"Handled in ({len(r.handled_in)}):"] + [f"    {s}" for s in r.handled_in]
        detail.insert("1.0", "\n".join(lines))
        # make GitHub URLs clickable
        for i, line in enumerate(lines, 1):
            for m in re.finditer(r"https://\S+", line):
                tag = f"url{i}_{m.start()}"
                detail.tag_add(tag, f"{i}.{m.start()}", f"{i}.{m.end()}")
                detail.tag_configure(tag, foreground=ACCENT, underline=True)
                detail.tag_bind(tag, "<Button-1>", lambda e, u=m.group(0): webbrowser.open(u))
                detail.tag_bind(tag, "<Enter>", lambda e: detail.configure(cursor="hand2"))
                detail.tag_bind(tag, "<Leave>", lambda e: detail.configure(cursor=""))

    def set_cat(k):
        state["cat"] = "" if state["cat"] == k else k
        refresh()

    for k, b in chip_btns.items():
        b.configure(command=lambda k=k: set_cat(k))

    def do_scan():
        p = path_var.get().strip()
        if not p or not Path(p).is_dir():
            messagebox.showerror("Opcode Inspector", "Pick the repo root folder first (it contains common/, zone/ and world/).")
            return
        scan_btn.configure(state="disabled")
        status_lbl.configure(text="Scanning…")
        msgs = []

        def work():
            try:
                sc = Scan(Path(p), log=msgs.append).run(fetch_upstream=up_var.get())
                root.after(0, lambda: done(sc, msgs, None))
            except Exception as e:
                root.after(0, lambda: done(None, msgs, e))

        threading.Thread(target=work, daemon=True).start()

    def done(sc, msgs, err):
        scan_btn.configure(state="normal")
        if err:
            status_lbl.configure(text="Scan failed")
            messagebox.showerror("Opcode Inspector", str(err))
            return
        state["scan"] = sc
        names = [p.name for p in sc.patches]
        client_cb.configure(values=names)
        if names and client_var.get() not in names:
            client_var.set(names[-1] if "RoF2" not in names else "RoF2")
        sent = sum(1 for r in sc.rows if r.sent_from)
        handled = sum(1 for r in sc.rows if r.handled_in)
        status_lbl.configure(text=f"Scanned {sc.root.name}: {len(sc.emu_ops)} emu opcodes, server sends {sent} "
                                  f"and handles {handled}; patches: {', '.join(names)}. Click a row for details.")
        refresh()

    def export_csv():
        if not state["scan"]:
            return
        f = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="opcode_matrix.csv",
                                         filetypes=[("CSV", "*.csv")])
        if f:
            state["scan"].write_csv(f)
            status_lbl.configure(text=f"Saved {f}")

    def export_html():
        if not state["scan"]:
            return
        f = filedialog.asksaveasfilename(defaultextension=".html", initialfile="opcode_report.html",
                                         filetypes=[("HTML", "*.html")])
        if f:
            state["scan"].write_html(f)
            status_lbl.configure(text=f"Saved {f} (open it in any browser, or send it to the team)")

    def show_fixes():
        sc = state["scan"]
        if not sc or not client_var.get():
            return
        txt = sc.fix_snippet(client_var.get())
        win = tk.Toplevel(root)
        win.title(f"Suggested fixes: {client_var.get()}")
        win.configure(bg=BG)
        t = tk.Text(win, bg=PANEL, fg=FG, insertbackground=FG, font=("Consolas", 10), width=100, height=34,
                    relief="flat", padx=10, pady=8)
        t.insert("1.0", txt)
        t.pack(fill="both", expand=True, padx=10, pady=10)

        def copy():
            root.clipboard_clear()
            root.clipboard_append(txt)

        ttk.Button(win, text="Copy to clipboard", command=copy).pack(pady=(0, 10))

    STATUS_COLORS = {"same": FG, "moved": COLORS["bad"], "size differs": COLORS["bad"], "type differs": COLORS["warn"],
                     "renamed": MUTED, "different": COLORS["bad"], "only ours": COLORS["warn"],
                     "only upstream": COLORS["info"]}

    def get_layouts(cb):
        sc = state["scan"]
        if not sc:
            return
        lc = state.get("layouts")
        if lc and lc.scan is sc and lc._loaded:
            cb(lc)
            return
        status_lbl.configure(text="Loading struct definitions (first time fetches upstream EQEmu files)…")

        def work():
            try:
                lc2 = LayoutCompare(sc, log=lambda *a: None).load()
                state["layouts"] = lc2
                root.after(0, lambda: (status_lbl.configure(text="Struct definitions loaded."), cb(lc2)))
            except Exception as e:
                root.after(0, lambda: messagebox.showerror("Opcode Inspector", f"Couldn't load structs: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def layout_tab(nb, title, pr, client):
        frm = ttk.Frame(nb, padding=8)
        nb.add(frm, text=title)
        o = pr["ours"]
        u = pr["up"]
        head = (f"Ours: {pr['ours_name'] or '?'}  ({o[1] if o else 'not found'} bytes)        "
                f"Upstream: {pr['up_name'] or '?'}  ({u[1] if u else 'not found'} bytes)")
        how = "Aligned by byte offset: each row is what sits at that position on the wire." if title.endswith("format") \
            else "Aligned by field name: shows fields added, removed or reordered on our side."
        ttk.Label(frm, text=head, style="Muted.TLabel").pack(anchor="w")
        ttk.Label(frm, text=how, style="Muted.TLabel").pack(anchor="w", pady=(0, 6))
        cols = ("ao", "as", "at", "an", "st", "bo", "bs", "bt", "bn")
        hd = ("Off", "Size", "Ours type", "Ours field", "Status", "Off", "Size", "Upstream type", "Upstream field")
        wd = (55, 55, 150, 200, 110, 55, 55, 150, 200)
        tv = ttk.Treeview(frm, columns=cols, show="headings")
        for c, h, w in zip(cols, hd, wd):
            tv.heading(c, text=h)
            tv.column(c, width=w, anchor="w", stretch=c in ("an", "bn"))
        for k, col in STATUS_COLORS.items():
            tv.tag_configure(k, foreground=col)
        sb = ttk.Scrollbar(frm, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        for fa, fb, st in pr["rows"]:
            tv.insert("", "end", tags=(st,), values=(
                fmt(fa.off) if fa else "", fmt(fa.size) if fa else "", fa.type if fa else "", fa.name if fa else "",
                st,
                fmt(fb.off) if fb else "", fmt(fb.size) if fb else "", fb.type if fb else "", fb.name if fb else ""))
        if not pr["rows"]:
            tv.insert("", "end", values=("", "", "", "(no struct found)", "", "", "", "", ""))

    def text_tab(nb, title, txt):
        frm = ttk.Frame(nb, padding=8)
        nb.add(frm, text=title)
        t = tk.Text(frm, bg=PANEL, fg=FG, insertbackground=FG, font=("Consolas", 10), relief="flat", wrap="none",
                    padx=8, pady=6)
        t.tag_configure("add", foreground=COLORS["ok"])
        t.tag_configure("del", foreground=COLORS["bad"])
        t.tag_configure("hdr", foreground=COLORS["info"])
        for line in txt.splitlines():
            tag = "add" if line.startswith("+") else "del" if line.startswith("-") else "hdr" if line.startswith("@@") else ""
            t.insert("end", line + "\n", tag)
        sy = ttk.Scrollbar(frm, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sy.set)
        t.pack(side="left", fill="both", expand=True)
        sy.pack(side="right", fill="y")

    def compare_layouts(_=None):
        sel = tree.selection()
        if not sel or not client_var.get():
            messagebox.showinfo("Opcode Inspector", "Select an opcode row first.")
            return
        op, client = sel[0], client_var.get()

        def show(lc):
            res = lc.compare(op, client)
            win = tk.Toplevel(root)
            win.title(f"{op}: ours vs upstream ({client})")
            win.geometry("1300x720")
            win.configure(bg=BG)
            note = ("Not translated by our patch: the client receives our server struct as-is, so the first tab "
                    "compares it to upstream's RoF2 wire struct." if res["passthrough"] else
                    "Translated by our patch: compare our encoder's wire struct and code with upstream's.")
            if len(res.get("candidates", [])) > 1:
                note += "  Other structs seen with this opcode: " + ", ".join(res["candidates"][1:])
            ttk.Label(win, text=note, style="Muted.TLabel", wraplength=1250).pack(anchor="w", padx=12, pady=(10, 4))
            nb = ttk.Notebook(win)
            nb.pack(fill="both", expand=True, padx=10, pady=6)
            layout_tab(nb, f"{client} wire format", res["wire"], client)
            layout_tab(nb, "Server struct", res["internal"], client)
            so, su = res["serial"]
            if so or su:
                d = "\n".join(difflib.unified_diff(su, so, "upstream", "ours", lineterm="", n=2)) or "identical"
                text_tab(nb, "Serialization order",
                         "Write/read calls in order (calls inside loops are listed once).\n"
                         "'-' = upstream only, '+' = ours only\n\n" + d)
            for kind in ("ENCODE", "DECODE"):
                ob, ub = res[kind]
                if not ob and not ub:
                    continue
                if ob and ub:
                    d = "\n".join(difflib.unified_diff(ub.splitlines(), ob.splitlines(), "upstream", "ours",
                                                       lineterm="", n=3)) or "identical"
                else:
                    d = ("Upstream has no " if ob else "We have no ") + f"{kind}({op}) for {client}.\n\n" + (ob or ub)
                text_tab(nb, f"{kind.title()} diff", d)
            report = lc.report_text(res)
            bar2 = ttk.Frame(win, padding=(10, 0, 10, 10))
            bar2.pack(fill="x")

            def copy():
                root.clipboard_clear()
                root.clipboard_append(report)

            def save():
                f = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"{op}_{client}_compare.txt")
                if f:
                    Path(f).write_text(report, encoding="utf-8")

            ttk.Button(bar2, text="Save as text", command=save).pack(side="right", padx=(6, 0))
            ttk.Button(bar2, text="Copy as text", command=copy).pack(side="right")

        get_layouts(show)

    def struct_report():
        if not state["scan"] or not client_var.get():
            return
        client = client_var.get()

        def go(lc):
            f = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"struct_diff_{client}.csv")
            if not f:
                return
            rows = lc.struct_report(client)
            with open(f, "w", newline="", encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                w.writeheader()
                w.writerows(rows)
            bad = sum(1 for r in rows if r["status"] != "same")
            status_lbl.configure(text=f"Saved {f}: {bad} of {len(rows)} shared structs differ from upstream")

        get_layouts(go)

    for text, cmd in (("Export HTML report", export_html), ("Export CSV", export_csv),
                      ("Struct diff report", struct_report), ("Suggested fixes", show_fixes),
                      ("Compare with upstream", compare_layouts)):
        ttk.Button(bot, text=text, command=cmd).pack(side="right", padx=(6, 0))

    scan_btn.configure(command=do_scan)
    client_var.trace_add("write", refresh)
    dir_var.trace_add("write", refresh)
    q_var.trace_add("write", refresh)
    tree.bind("<<TreeviewSelect>>", show_detail)
    tree.bind("<Double-1>", compare_layouts)

    if initial_root:
        root.after(200, do_scan)
    root.mainloop()


HTML_TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Opcode Report</title>
<style>
:root{--bg:#f6f7f5;--panel:#fff;--fg:#1c2421;--muted:#5d6b66;--line:#dfe4e1;--accent:#2f6f5e;
--bad:#b3261e;--badbg:#fbe9e7;--warn:#8a5a00;--warnbg:#fdf3dc;--ok:#2e6b3a;--okbg:#e6f2e8;--info:#3a5a8c;--infobg:#e8eef8}
@media (prefers-color-scheme:dark){:root{--bg:#121715;--panel:#1a211e;--fg:#e3e9e6;--muted:#9aa8a2;--line:#2c3632;--accent:#7cc4ad;
--bad:#ff8a80;--badbg:#3a1b19;--warn:#f0c060;--warnbg:#36290f;--ok:#8fd19e;--okbg:#17301d;--info:#9cb8e8;--infobg:#1b2638;color-scheme:dark}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px system-ui,"Segoe UI",sans-serif}
.wrap{padding:24px 16px 40px;max-width:1600px;margin:0 auto;display:flex;flex-direction:column;gap:14px}
h1{margin:0;font-size:22px}.sub{color:var(--muted);margin:2px 0 0}
.bar{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
select,input{font:inherit;background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:5px;padding:6px 8px}
.count{color:var(--muted);margin-left:auto}
.sum{display:flex;flex-wrap:wrap;gap:8px}
.chip{border:1px solid var(--line);background:var(--panel);border-radius:6px;padding:7px 12px;cursor:pointer;font:inherit;color:inherit}
.chip[aria-pressed=true]{outline:2px solid var(--accent)}
.tbl{overflow:auto;border:1px solid var(--line);border-radius:6px;background:var(--panel);max-height:75vh}
table{border-collapse:collapse;width:100%;min-width:1100px}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line)}
th{position:sticky;top:0;background:var(--panel);font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
a{color:var(--accent)}td.m{font-family:Consolas,ui-monospace,monospace;font-size:12.5px}td.s{font-size:12.5px;color:var(--muted);max-width:360px}
.st{display:inline-block;border-radius:4px;padding:2px 7px;font-size:12px;white-space:nowrap}
.bad{background:var(--badbg);color:var(--bad)}.warn{background:var(--warnbg);color:var(--warn)}.ok{background:var(--okbg);color:var(--ok)}.info{background:var(--infobg);color:var(--info)}
</style></head><body><div class="wrap">
<div><h1>Opcode Report</h1><p class="sub">Generated by opcode_inspector.py from __ROOT__</p></div>
<div class="bar"><label>Client <select id="c"></select></label>
<label>Direction <select id="d"><option value="">All</option><option value="Out">Server sends</option><option value="In">Server handles</option></select></label>
<label>Search <input id="q" type="search"></label><span class="count" id="n"></span></div>
<div class="sum" id="sum"></div>
<div class="tbl"><table><thead><tr><th>Opcode</th><th>Dir</th><th>Wire</th><th>Upstream</th><th>Translator</th><th>Outbound</th><th>Inbound</th><th>Suggested fix</th><th>Layout vs upstream</th><th>Sent from</th></tr></thead><tbody id="b"></tbody></table></div>
</div><script>
const D=__DATA__,C=__CLIENTS__,$=s=>document.querySelector(s);let cat='';
C.forEach(c=>$('#c').insertAdjacentHTML('beforeend',`<option>${c}</option>`));if(C.includes('RoF2'))$('#c').value='RoF2';
const cls=s=>!s?'':s.startsWith('BROKEN')?'bad':s.startsWith('UNREACH')?'warn':s.startsWith('OK')?'ok':'info';
const esc=t=>String(t??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const worst=(r,c)=>{const g=[cls(r[c+' outbound']),cls(r[c+' inbound'])];return['bad','warn','info','ok'].find(k=>g.includes(k))||'ok'};
function render(){const c=$('#c').value,d=$('#d').value,q=$('#q').value.toLowerCase(),n={bad:0,warn:0,info:0,ok:0};
D.forEach(r=>n[worst(r,c)]++);const L={bad:'Broken',warn:'Unreachable',info:'Wired, verify',ok:'OK'};
$('#sum').innerHTML=Object.keys(L).map(k=>`<button class="chip" aria-pressed="${cat===k}" data-k="${k}"><b>${n[k]}</b> <span class="st ${k}">${L[k]}</span></button>`).join('');
document.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{cat=cat===b.dataset.k?'':b.dataset.k;render()});
const o={bad:0,warn:1,info:2,ok:3};let rs=D.filter(r=>(!d||r.Direction.includes(d))&&(!cat||worst(r,c)===cat)&&(!q||JSON.stringify(r).toLowerCase().includes(q)));
rs.sort((a,b)=>o[worst(a,c)]-o[worst(b,c)]||a.Opcode.localeCompare(b.Opcode));$('#n').textContent=rs.length+' of '+D.length+' opcodes';
$('#b').innerHTML=rs.map(r=>`<tr><td class="m">${esc(r.Opcode)}</td><td>${r.Direction}</td><td class="m">${esc(r[c+' wire'])}</td><td class="m">${esc(r[c+' upstream'])}</td><td class="m">${esc(r[c+' translator'])}</td>
<td>${r[c+' outbound']?`<span class="st ${cls(r[c+' outbound'])}">${esc(r[c+' outbound'])}</span>`:''}</td><td>${r[c+' inbound']?`<span class="st ${cls(r[c+' inbound'])}">${esc(r[c+' inbound'])}</span>`:''}</td>
<td class="m">${esc(r[c+' suggested fix'])}</td><td class="s">${esc(r[c+' layout vs upstream']||'')}${(r[c+' upstream links']||'').split(' ').filter(Boolean).map((u,k)=>` <a href="${esc(u)}" target="_blank" rel="noopener">[${['value','code','struct','src'][k]||'link'}]</a>`).join('')}</td><td class="s m">${esc(r['Sent from'].split('; ').slice(0,3).join('; '))}</td></tr>`).join('')}
['#c','#d'].forEach(s=>$(s).onchange=render);$('#q').oninput=render;render();
</script></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Map server opcodes against client patches.")
    ap.add_argument("repo", nargs="?", help="Repo root (folder containing common/, zone/, world/)")
    ap.add_argument("--no-gui", action="store_true", help="Run without the GUI")
    ap.add_argument("--csv", help="Write a CSV here")
    ap.add_argument("--html", help="Write a shareable HTML report here")
    ap.add_argument("--fixes", help="Client name: print suggested .conf / EAT_ENCODE lines for it")
    ap.add_argument("--conf-dir", action="append", default=[],
                    help="Folder holding the patch_*.conf files your server loads (repeatable)")
    ap.add_argument("--compare", metavar="OPCODE", help="Print ours-vs-upstream struct/encoder comparison for an opcode")
    ap.add_argument("--client", default="RoF2", help="Client for --compare / --struct-report (default RoF2)")
    ap.add_argument("--struct-report", metavar="CSV", help="Write size/layout differences for every shared struct")
    ap.add_argument("--upstream", action="store_true", help="Compare with upstream EQEmu .conf files (internet)")
    a = ap.parse_args()
    CONF_DIRS.extend(Path(d) for d in a.conf_dir)

    if a.no_gui or a.csv or a.html or a.fixes or a.compare or a.struct_report:
        if not a.repo:
            ap.error("repo path is required with --no-gui/--csv/--html/--fixes")
        sc = Scan(Path(a.repo)).run(fetch_upstream=a.upstream)
        for p in sc.patches:
            tally = {}
            for r in sc.rows:
                k = worst(r.per_client[p.name])
                tally[k] = tally.get(k, 0) + 1
            print(f"{p.name}: broken={tally.get('bad', 0)} unreachable={tally.get('warn', 0)} "
                  f"verify={tally.get('info', 0)} ok={tally.get('ok', 0)}")
            if sc.unknown_conf_names.get(p.name):
                print(f"  {len(sc.unknown_conf_names[p.name])} names in patch_{p.conf_name}.conf aren't in the emu enum "
                      f"(ignored at load), e.g. {', '.join(list(sc.unknown_conf_names[p.name])[:6])}")
        if a.csv:
            sc.write_csv(a.csv)
            print("Wrote", a.csv)
        if a.html:
            sc.write_html(a.html)
            print("Wrote", a.html)
        if a.fixes:
            print(sc.fix_snippet(a.fixes))
        if a.compare or a.struct_report:
            lc = LayoutCompare(sc).load()
            if a.compare:
                print(lc.report_text(lc.compare(a.compare, a.client)))
            if a.struct_report:
                rows = lc.struct_report(a.client)
                with open(a.struct_report, "w", newline="", encoding="utf-8") as fh:
                    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                    w.writeheader()
                    w.writerows(rows)
                print("Wrote", a.struct_report, "-", sum(1 for r in rows if r["status"] != "same"), "structs differ")
        return
    run_gui(a.repo, a.upstream)


if __name__ == "__main__":
    main()
