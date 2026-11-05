# VERSION.dll proxy loader

A tiny DLL that masquerades as `VERSION.dll` so Windows's loader picks it up before
the real one when the game starts. It forwards every version.dll export to the
real system DLL at runtime and, as a side effect of `DllMain`, loads `YimMenuV2.dll`
into the process.

Replaces `-nobattleye` and FSL as the bootstrap mechanism. The menu's own BattlEye
neutering handles the rest once it's resident.

## Why this works where external injection fails

BattlEye's kernel driver (`BEDaisy.sys`) uses `ObRegisterCallbacks` to strip
dangerous handle rights from every external process that opens `GTA5_Enhanced.exe`.
Xenos, Process Hacker, Cheat Engine, and every other userspace injector get
denied `PROCESS_VM_WRITE`/`PROCESS_CREATE_THREAD` and fail.

The kernel callback runs when a process *opens a handle* to GTA. It does nothing
to DLLs resolved by the normal Windows loader during the game's initial startup,
which happens before BE's driver activates. By placing a file named `version.dll`
in the application directory, Windows finds it via the standard DLL search order
and loads it as a dependency of the game. By the time BE wakes up, we're already
in the process.

## Install

1. Build it (see below), or grab `version.dll` from a release.
2. Place `version.dll` next to `GTA5_Enhanced.exe`, e.g.
   `C:\Program Files (x86)\Steam\steamapps\common\Grand Theft Auto V Enhanced\version.dll`
3. Place `YimMenuV2.dll` in the same folder, or set the `YIMMENUV2_PATH`
   environment variable to its full path.
4. Launch GTA normally. No `-nobattleye`, no Social Club toggle.

## Build

Requires VS 2022 Build Tools (MSVC 14.x) and a Windows SDK.

```bash
cd tools/proxy_loader
mkdir build && cd build
cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

Output: `build/version.dll` (~16 KB).

## Signatures and detection

BattlEye maintains hashes of known cheat loaders. This proxy isn't on that list
today, but it will be once it's seen in the wild. To delay detection:

- Don't publish compiled binaries, let users build their own.
- If a build gets flagged, change a few cosmetic things (a comment, a string
  constant, build flags) to change the file hash, then rebuild.
- Use `YIMMENUV2_PATH` to keep the payload DLL somewhere other than the game
  folder, so BE can't correlate the proxy with a sibling cheat DLL.

## What this does NOT do

- Does not bypass BE. The menu still has to neuter BE's scanner threads after
  loading. This proxy only gets the menu into the process.
- Does not bypass Arxan. The menu's existing Arxan filtering handles that.
- Does not survive a game update that changes the import table. If a future
  patch drops `VERSION.dll` from the imports, this stops working and we'd pick
  another target (DSOUND.dll, WININET.dll, etc.).
