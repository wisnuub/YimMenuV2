# Shepherd — early-chain BE bypass

Injects YimMenuV2.dll into GTA5_Enhanced.exe by hooking the Rockstar launch chain
*before* BattlEye's kernel driver (BEDaisy) is loaded.

## Why it works

BEDaisy is a Manual-start driver. It's loaded by BEService, which is launched by
BELauncher. There's a window — roughly the first 1-2 seconds of the launch chain
— when no BE kernel component is active. External handles opened during that
window keep their full rights even after BEDaisy loads later.

```
Timeline (approx):

   t=0ms     Steam spawns PlayGTAV.exe             ← Shepherd injects here (external)
   t=~200ms  PlayGTAV spawns GTA5_Enhanced_BE      ← Shepherd's CreateProcess hook catches it
   t=~800ms  BELauncher starts BEService
   t=~1200ms BEService loads BEDaisy.sys           ← BE kernel block becomes active
   t=~2000ms BELauncher spawns GTA5_Enhanced.exe   ← Caught via BELauncher's own handle
                                                      (rights not strippable retroactively)
   t=~2500ms GTA starts, YimMenuV2.dll already in
```

Once inside GTA, the menu's `NeuterBEImmediate()` suspends BE's scanner threads
before they can report anything.

## Components

- `shepherd.dll` — once injected, hooks `CreateProcessW` in the host process.
  Every child that host spawns gets shepherd re-injected into it (walks the
  chain) and, if the child is `GTA5_Enhanced.exe`, the YimMenuV2 payload too.
  Uses IAT hooking on every loaded module, so works regardless of which import
  library the host uses (`kernel32`, `kernelbase`, api-ms-win shims).

- `watcher.exe` — a tiny console app that polls for `PlayGTAV.exe` every 50ms
  and injects `shepherd.dll` into it the moment it appears. Must be started
  *before* the user clicks Play in Steam.

- Registry: `HKCU\Software\YimMenuV2Shepherd\PayloadPath` stores the path to
  `YimMenuV2.dll` so shepherd knows what to inject into GTA when it catches
  that spawn later in the chain.

## Usage

Build everything first (see "Build" below). Then:

1. Make sure GTA, PlayGTAV, and BELauncher are **not running**. Close them.
2. Open a terminal and run the watcher:
   ```
   watcher.exe E:\GitHub\YimMenuV2\tools\shepherd\build\shepherd.dll ^
               E:\GitHub\YimMenuV2\build\YimMenuV2.dll
   ```
3. The watcher logs `Watching for PlayGTAV.exe (50ms poll). Click Play in Steam now.`
4. **Click Play on GTA V Enhanced in Steam.**
5. Watcher detects PlayGTAV, injects shepherd, exits.
6. Game continues launching normally through the Rockstar chain. The
   shepherd's CreateProcess hook catches each subsequent spawn, re-injecting
   shepherd into it and (for GTA5_Enhanced.exe) also injecting YimMenuV2.dll.
7. GTA reaches the main menu with the menu already loaded and BE neutered.

## Diagnostic log

Shepherd writes a log to `%LOCALAPPDATA%\YimMenuV2Shepherd.log` with the chain
of spawns it saw and whether each injection succeeded. Check this if the menu
doesn't show up.

## What can still go wrong

1. **BELauncher detects the IAT hook** by checksumming its own import table
   after startup. If so we'd move to inline trampoline hooks on kernel32's
   `CreateProcessW` export.
2. **PlayGTAV uses `CreateProcessA` instead of W**. We only hook W. Can be
   extended to hook A if needed.
3. **BELauncher re-reads its exports from disk** (fresh unhooked kernel32).
   Rare but possible.
4. **BEDaisy loads faster than we expect** and catches us during the chain
   before we can inject via the fresh child-process handle. Would need to
   measure and possibly launch watcher as a persistent service to inject
   faster.

Any of these = the log tells us exactly where the chain broke.

## Build

```bash
cd tools/shepherd
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

Output: `build/shepherd.dll` (~16 KB), `build/watcher.exe` (~16 KB).
