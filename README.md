# Opcode Inspector

A tool for EQEmu-based servers that shows how every opcode the server sends or handles is wired up for each client patch (RoF2, SoD, …). It finds packets that never reach the client and compares your packet layouts with upstream EQEmu.

It reads your repo directly, so it stays accurate as the code changes. Rescan after every fix.

## What it tells you

For every opcode used in `zone/` and `world/`:

- **Wire opcode** for each registered client, from `patch_<Client>.conf`.
- **Translator**: whether the client patch has an `ENCODE`, a `DECODE` or an `EAT_ENCODE` for it, or sends the server struct as-is (passthrough).
- **Status**:
  - **Broken: sent as 0x0000**. The server sends it, but the client has no opcode for it.
  - **Unreachable: no wire opcode**. A handler exists, but the client can never send it.
  - **Translated / Passthrough: verify**. It's wired up, but not yet proven correct.
  - **OK**. Eaten, or rerouted to another opcode by the encoder.
- **Where it's sent from and handled**, as file and line.
- **Upstream comparison** (optional):
  - Upstream EQEmu's value for the opcode.
  - Links to the exact lines on GitHub (the `.conf` value, upstream's encoder and upstream's struct).
  - A verdict on whether the layout your server sends matches upstream's.
- **Suggested fixes**, grouped by what to do: map it, reroute it, change server code, port an upstream feature, needs your custom client, investigate, or not needed.

## Requirements

- Python 3.8 or newer. The python.org Windows installer includes everything the tool needs, the GUI included.
- No other packages.
- Internet access for the upstream comparison only. Upstream files are cached after the first download.

## Files

| File | What it is |
|---|---|
| `opcode_inspector.py` | The tool |
| `opcode_playbook.json` | Notes on specific opcodes, editable by the team (see [The playbook](#the-playbook)) |
| `.upstream_cache/`, `.upstream_patch_*.conf` | Downloaded upstream files, created automatically. Delete them to force a fresh download. |

Keep `opcode_inspector.py` and `opcode_playbook.json` in the same folder.

## Running it

Run it from your repo root (the folder that contains `common/`, `zone/` and `world/`).

### GUI

```powershell
python opcode_inspector.py .
```

Or run it with no arguments and use **Browse…** to pick the repo folder.

1. Tick **Compare with upstream EQEmu** if you want upstream values, links and layout checks, then press **Scan**.
2. Pick a **Client** (RoF2 or SoD).
3. Filter with the colored chips (Broken / Unreachable / Wired, verify / OK), the **Direction** list or **Search**.
4. Click a row to see its details: the status for every client, the suggested fix, the layout verdict, clickable GitHub links, and every place it's sent or handled.
5. **Double-click** a row, or press **Compare with upstream**, to see your struct and upstream's side by side:
   - **Wire format**: aligned by byte offset, showing what the client actually parses at each position.
   - **Server struct**: your `eq_packet_structs.h` against upstream's, aligned by field name.
   - **Serialization order**: the write and read calls in each encoder, as a diff. This matters for packets built field by field, like PlayerProfile.
   - **Encode diff / Decode diff**: your encoder or decoder against upstream's.

Buttons along the bottom:

| Button | Does |
|---|---|
| **Suggested fixes** | Fixes for the selected client, grouped by action, with `.conf` lines and encoder code you can copy |
| **Compare with upstream** | Opens the side-by-side layout and code comparison for the selected opcode |
| **Struct diff report** | Saves a CSV listing every struct defined both in your repo and upstream: sizes and the number of differing fields |
| **Export CSV** | The full opcode table, for spreadsheets or trackers |
| **Export HTML report** | One self-contained, filterable page you can send to anyone |

### Command line

```powershell
# Summary only
python opcode_inspector.py . --no-gui

# Shareable reports, compared with upstream
python opcode_inspector.py . --upstream --html opcode_report.html --csv opcode_matrix.csv

# Suggested fixes for one client
python opcode_inspector.py . --upstream --fixes RoF2

# Ours vs upstream for one opcode (struct layout, serialization order, encoder diff)
python opcode_inspector.py . --compare OP_NewZone --client RoF2

# Every shared struct, ours vs upstream
python opcode_inspector.py . --struct-report struct_diff.csv --client RoF2
```

| Option | Meaning |
|---|---|
| `--no-gui` | Print a summary instead of opening the GUI |
| `--upstream` | Fetch upstream EQEmu `.conf` files, structs and patches for comparison |
| `--csv FILE` / `--html FILE` | Write the opcode table |
| `--fixes CLIENT` | Print suggested fixes for that client |
| `--compare OPCODE` | Print the ours-vs-upstream comparison for one opcode |
| `--client CLIENT` | Client for `--compare` and `--struct-report` (default `RoF2`) |
| `--struct-report FILE` | Write size and layout differences for every shared struct |
| `--conf-dir DIR` | Read `patch_*.conf` from this folder first (repeatable) |
| `--playbook FILE` | Use a different playbook file |

### Which `.conf` files does it use?

It looks in `util\patches`, `utils\patches`, the repo root, and then the rest of the repo. The server, though, loads `.conf` files from the folder world and zone **run from**. If the deployed files differ from the repo copies, point the tool at the deployed folder:

```powershell
python opcode_inspector.py . --conf-dir "D:\server\running\folder"
```

## How it finds things

| What | Where it looks |
|---|---|
| Emu opcode list | `common/emu_oplist.h` (+ `mail_oplist.h`) |
| Registered clients | `RegisterAllPatches()` in `common/patches/patches.cpp`, plus any patch with both `<name>.cpp` and `<name>_ops.h` |
| Encoders / decoders | `E(...)` / `D(...)` in `<client>_ops.h`, and `EAT_ENCODE(...)` in `<client>.cpp` |
| Packets the server sends | `EQApplicationPacket(OP_x…)` and `SetOpcode(OP_x)` anywhere under `zone/` and `world/` |
| Packets the server handles | `ConnectedOpcodes[OP_x]`, `ConnectingOpcodes[OP_x]`, and `case OP_x:` in `world/client.cpp` |
| Struct layouts | `common/*.h` and `common/patches/<client>_structs.h`, parsed as packed (`#pragma pack(1)`) structs |
| Upstream | `github.com/EQEmu/EQEmu`, `master` branch |

It skips `.git`, build output folders and the old `chatserver/` tree, and it won't loop through Windows junctions or symlinks.

## The playbook

`opcode_playbook.json` holds what people know about specific opcodes, the things that can't be worked out from the code alone. Examples: "RoF2 calls this packet OP_GuildMemberDelete", or "RoF2 has no such packet, so skip it".

Entries are keyed by emu opcode name. Inside each one, `"*"` applies to every client, and a client name overrides it:

```json
"OP_GuildManageRemove": {
  "RoF2": {
    "action": "MAP",
    "map_to": "OP_GuildMemberDelete",
    "same_layout": ["GuildManageRemove_Struct", "GuildMemberDelete_Struct"],
    "summary": "{client} calls this {map_to} ({map_value}). ..."
  }
}
```

**Never put hex values in the playbook.** Refer to opcodes by name; the tool looks up each value in your `.conf` first, then upstream's.

| Field | Meaning |
|---|---|
| `action` | `MAP`, `REROUTE`, `SERVER`, `PORT`, `NOT NEEDED`, `CUSTOM` or `INVESTIGATE` |
| `summary` | Shown to the reader. Placeholders: `{client}`, `{map_to}`, `{map_value}`, `{value:OP_Name}` |
| `map_to` | Same packet under another name. Suggests `<opcode>=<value of map_to>` |
| `new_opcode` | Suggests adding this opcode with its upstream value (needs a new emu opcode) |
| `same_layout` | `[our struct, upstream struct]`: compared when upstream data is loaded |
| `expect_upstream_unmapped` | The advice assumes upstream has no value; you're warned if that changes |
| `requires_encoder` | The advice relies on your patch encoding this opcode; you're warned if it doesn't |
| `ops_h`, `code`, `extra` | Lines and code to show in Suggested fixes |
| `eat` | Include it in the optional `EAT_ENCODE` list |

When an entry's assumptions stop being true, the fix shows a **WARNING** explaining why, so outdated advice gets noticed.

Opcodes with no playbook entry still get a suggestion, worked out from the evidence: a renamed opcode, an upstream value, a value another client has, or "upstream has none either".

## Reading the results

- **A packet sent as `0x0000` is usually harmless.** Upstream does the same for packets RoF2 doesn't have, and the client ignores them. It's worth cleaning up, but it's rarely what breaks a client.
- **Wrong layouts are what break clients.** Look for:
  - "Layout DIFFERS" on passthrough opcodes, where your server struct is sent byte-for-byte.
  - RoF2 wire structs that are a different size from upstream's.
  - Encoder diffs that write different fields.
- **Upstream is a strong reference, not proof.** Its RoF2 support has years of packet-capture fixes, but a difference means "check this", not automatically "ours is wrong". Confirm surprises with a packet capture.
- **Your custom data** shows up in the Server struct tab as fields only on your side. That's expected. What matters is that the wire format matches the client.

## Limitations

- **Sizes come from reading the headers, not compiling them.** Anything the parser can't resolve (an unknown constant, a C++ container, a type defined elsewhere) shows as `?`. Bitfield layouts are approximate.
- **Some opcodes are missed.** It finds sends that name the opcode directly (`EQApplicationPacket(OP_x…)`, `SetOpcode(OP_x)`); packets whose opcode is passed in a variable aren't seen.
- **Only one struct per opcode is checked.** If an opcode is sent with several structs, the verdict checks the first; the comparison window lists the others.
- **Serialization order lists a write inside a loop once.**
- **Suggested encoder code is untested.** Compile it and test on a real client before merging.

## Troubleshooting

| Problem | Fix |
|---|---|
| A client is missing from the dropdown | Run `--no-gui` and check the `patches.cpp:` and `Emu opcodes:` lines point at your `common/` folder, not another copy |
| `patch_X.conf not found` | Use `--conf-dir` with the folder holding your `.conf` files |
| Upstream values are blank | Tick **Compare with upstream EQEmu** (or pass `--upstream`) and check your internet connection |
| Upstream data looks stale | Delete `.upstream_cache/` and `.upstream_patch_*.conf` next to the script |
| A playbook entry shows a WARNING | Its assumption no longer holds. Check the opcode, then update or remove the entry |
