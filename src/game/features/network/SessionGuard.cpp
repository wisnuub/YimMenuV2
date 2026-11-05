#include "core/commands/LoopedCommand.hpp"
#include "core/commands/Commands.hpp"
#include "core/util/Joaat.hpp"
#include "game/backend/AnticheatBypass.hpp"
#include "game/backend/NativeHooks.hpp"
#include "game/backend/Tunables.hpp"
#include "game/gta/Natives.hpp"
#include "game/pointers/Pointers.hpp"

namespace YimMenu::Features
{
	class SessionGuard : public LoopedCommand
	{
		using LoopedCommand::LoopedCommand;

		std::array<Tunable, 8> m_IdleTunables = std::to_array({
		    Tunable("IDLEKICK_WARNING1"_J),
		    Tunable("IDLEKICK_WARNING2"_J),
		    Tunable("IDLEKICK_WARNING3"_J),
		    Tunable("IDLEKICK_KICK"_J),
		    Tunable("ConstrainedKick_Warning1"_J),
		    Tunable("ConstrainedKick_Warning2"_J),
		    Tunable("ConstrainedKick_Warning3"_J),
		    Tunable("ConstrainedKick_Kick"_J),
		});

		bool m_HookedBail = false;

		static void BailHook(rage::scrNativeCallContext* ctx)
		{
			if (AnticheatBypass::IsBattlEyeBroken() || AnticheatBypass::IsUsingStandaloneLocalSaves())
			{
				LOGF(WARNING, "SessionGuard: blocked NETWORK_BAIL (reason: {}, {}, {})",
				    ctx->GetArg<int>(0), ctx->GetArg<int>(1), ctx->GetArg<int>(2));
				return;
			}
			NativeInvoker::GetNativeHandler(NativeIndex::NETWORK_BAIL)(ctx);
		}

		static void BailTransitionHook(rage::scrNativeCallContext* ctx)
		{
			if (AnticheatBypass::IsBattlEyeBroken() || AnticheatBypass::IsUsingStandaloneLocalSaves())
			{
				LOGF(WARNING, "SessionGuard: blocked NETWORK_BAIL_TRANSITION (reason: {}, {}, {})",
				    ctx->GetArg<int>(0), ctx->GetArg<int>(1), ctx->GetArg<int>(2));
				return;
			}
			NativeInvoker::GetNativeHandler(NativeIndex::NETWORK_BAIL_TRANSITION)(ctx);
		}

		virtual void OnEnable() override
		{
			if (!m_HookedBail)
			{
				NativeHooks::AddHook(NativeHooks::ALL_SCRIPTS, NativeIndex::NETWORK_BAIL, &BailHook);
				NativeHooks::AddHook(NativeHooks::ALL_SCRIPTS, NativeIndex::NETWORK_BAIL_TRANSITION, &BailTransitionHook);
				m_HookedBail = true;
			}
		}

		virtual void OnTick() override
		{
			for (auto& tunable : m_IdleTunables)
			{
				if (tunable.IsReady())
					tunable.Set(INT_MAX);
			}

			if (Pointers.BERestartStatus)
				*Pointers.BERestartStatus = 0;
			if (Pointers.NeedsBERestart)
				*Pointers.NeedsBERestart = false;
			if (Pointers.IsBEBanned)
				*Pointers.IsBEBanned = false;
		}

		virtual void OnDisable() override
		{
		}
	};

	static SessionGuard _SessionGuard{"sessionguard", "Session Guard", "Prevents session disconnects from BE issues, idle kicks, and scripted bail events. Auto-enabled in standalone mode."};

	void InitSessionGuard()
	{
		if (AnticheatBypass::IsBattlEyeBroken() || AnticheatBypass::IsUsingStandaloneLocalSaves())
		{
			auto cmd = Commands::GetCommand<BoolCommand>("sessionguard"_J);
			if (cmd && !cmd->GetState())
			{
				cmd->SetState(true);
				LOGF(INFO, "SessionGuard auto-enabled for standalone/broken-BE mode");
			}
		}
	}
}
