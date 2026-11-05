# YimMenuV2 (Fixed Fork)

Experimental menu for GTA 5: Enhanced, with standalone BattlEye/FSL bypass and session stability fixes.

## What's different in this fork

- **No FSL/Lawnchair required**: works standalone without the external WINMM.dll proxy. Local saves are enabled automatically when FSL is absent
- **No `-nobattleye` required**: when BattlEye is loaded normally (no launch flag), the menu suspends BE's scanner threads and patches its Init export, preventing detection while the game thinks BE is active. All BE server commands are handled with fake responses
- **Broken BattlEye handling**: if BE is present but in a broken state (e.g. account migration issues, BE detecting FSL), the menu detects this and falls back to standalone mode instead of crashing
- **Session Guard**: auto-enabled in standalone mode, prevents mid-gameplay disconnects by blocking scripted bail events, suppressing BE restart/ban flags, and disabling idle kicks
- **Extended BE protocol**: handles all known BattlEye command opcodes (0, 1, 2, 4, 5, 7, 9 + fallback) with fake responses so the server never drops you for a missing heartbeat
- **Kick protection**: blocks KickPlayer, RequestKickFromHost, and LostConnectionToHost messages in standalone/broken-BE mode
- **Stronger Arxan filtering**: more aggressive anti-tamper callback blocking when BE is broken
- **Non-fatal version mismatch**: if the game updates past the patch version (1158.16), the menu still loads and network protections still work. Only the Arxan restoration patches are skipped
- **Lua scripting**: fully integrated (LuaJIT + 14 library bindings), works out of the box

## How to use

1. Download or build YimMenuV2.dll from this fork
2. Download an injector, such as [Xenos](https://www.unknowncheats.me/forum/general-programming-and-reversing/124013-xenos-injector-v2-3-2-a.html)
3. Launch GTA V normally (no `-nobattleye` needed, no Social Club toggle needed)
4. Inject YimMenuV2.dll at the main menu

Neither FSL nor `-nobattleye` is required. The menu automatically neuters BattlEye's scanner threads at injection time, then handles all BE server communication with fake responses.

## How to open the menu

Press `INSERT` or `Ctrl+\`

## Bypass modes

The menu auto-detects which mode to use at startup:

| Mode | Condition | What happens |
|------|-----------|--------------|
| **FSL** | Lawnchair DLL loaded with valid exports | Uses FSL for local saves and BE bypass |
| **Neutered BattlEye** | BE loaded normally, no FSL | BE scanner threads suspended, Init patched to no-op, fake BE responses, standalone patches applied |
| **Standalone** | No BE module, no FSL | Standalone local saves, binary patches applied, fake BE responses |
| **Standalone (BE broken)** | BE module present but broken (restart reason != 0) | Same as standalone, plus aggressive Arxan filtering and kick blocking |

Check the log for "Anticheat bypass mode: ..." to see which mode is active.

## Session Guard

Found in **Network > Enhancements > Session Guard**. Auto-enables in standalone/broken-BE mode. Does three things:

1. Blocks `NETWORK_BAIL` and `NETWORK_BAIL_TRANSITION` script calls that cause random disconnects
2. Continuously suppresses BE restart/ban status flags
3. Disables all idle kick timers

Can be toggled manually from the menu.

## Building from source

Requires Visual Studio 2022 Build Tools (MSVC 14.x) and Windows SDK 10.0.22621+.

```bash
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build .
```

Output: `build/YimMenuV2.dll`

## Common issues

### BE rejects when FSL is installed

This fork handles it. The menu detects the broken BE state and falls back to standalone mode automatically. You'll see "Standalone (BE broken)" in the logs.

### Game updated past 1158.16

Network-level protections (SessionGuard, BE protocol handling, kick blocking) are version-independent and still work. Only the Arxan binary restoration patches are version-locked. The menu logs a warning and continues.

### Desynced from sessions

Enable Session Guard (auto-enabled in standalone mode). If still disconnecting, check the logs for which message type caused the disconnect.

### Progress disappeared after removing FSL

FSL reroutes save data to disk. Progress made with FSL only shows with FSL enabled. This fork's standalone local saves are separate from FSL's.

### Game won't start after removing FSL

Delete `Documents/GTAV Enhanced/Profiles` to fix.
