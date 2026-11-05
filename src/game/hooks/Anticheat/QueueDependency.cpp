#include "core/hooking/DetourHook.hpp"
#include "game/hooks/Hooks.hpp"
#include "game/pointers/Pointers.hpp"
#include "game/backend/AnticheatBypass.hpp"
#include "core/memory/ModuleMgr.hpp"
#include "core/memory/PointerCalculator.hpp"
#include "core/util/Joaat.hpp"

#include <intrin.h>

namespace YimMenu::Hooks
{
	static bool IsAddressInGameMemory(void* addr)
	{
		auto as_int = reinterpret_cast<uintptr_t>(addr);
		static auto module = ModuleMgr.Get("GTA5_Enhanced.exe"_J);

		return as_int >= module->Base() && as_int <= module->End();
	}

	static bool IsPotentialArxanCallback(void* addr)
	{
		if (!addr || !IsAddressInGameMemory(addr))
			return false;

		auto as_bytes = reinterpret_cast<std::uint8_t*>(addr);

		if (as_bytes[0] != 0xE9)
			return false;

		auto jmp_addr = PointerCalculator(addr).Add(1).Rip().As<void*>();

		if (!IsAddressInGameMemory(jmp_addr))
			return false;

		return true;
	}

	void Anticheat::QueueDependency(__int64 a1)
	{
		auto f1 = *reinterpret_cast<void**>(a1 + 0x60);
		auto f2 = *reinterpret_cast<void**>(a1 + 0x100);
		auto f3 = *reinterpret_cast<void**>(a1 + 0x1A0);

		if (!f1)
			return BaseHook::Get<Anticheat::QueueDependency, DetourHook<decltype(&Anticheat::QueueDependency)>>()->Original()(a1);

		if (f1 == Pointers.SigScanMemory)
		{
			LOGF(WARNING, "QueueDependency: Blocked the sig scanner dependency from being queued");
			return;
		}

		if (Pointers.Nullsub && (f1 == Pointers.Nullsub || f2 == Pointers.Nullsub || f3 == Pointers.Nullsub))
			return;

		int arx_score = (int)IsPotentialArxanCallback(f1) + (int)IsPotentialArxanCallback(f2) + (int)IsPotentialArxanCallback(f3);

		if (arx_score >= 2)
			return;

		if (AnticheatBypass::IsBattlEyeBroken() && arx_score >= 1)
			return;

		BaseHook::Get<Anticheat::QueueDependency, DetourHook<decltype(&Anticheat::QueueDependency)>>()->Original()(a1);
	}
}