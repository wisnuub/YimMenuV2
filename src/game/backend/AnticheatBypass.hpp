#pragma once

namespace YimMenu
{
	class AnticheatBypass
	{
	private:
		static AnticheatBypass& GetInstance()
		{
			static AnticheatBypass instance;
			return instance;
		}

		void RunOnStartupImpl();
		void RunScriptImpl();
		void NeuterBEImmediateImpl();

		bool m_IsFSLLoaded = false;
		bool m_BattlEyeRunning = false;
		int m_FSLVersion = -1;
		bool m_FSLProvidesLocalSaves = false;
		bool m_FSLProvidesBEBypass = false;
		bool m_StandaloneLocalSaves = false;
		bool m_BattlEyeBroken = false;
		bool m_BattlEyeNeutered = false;
		int m_BESuspendedThreads = 0;

	public:
		static void NeuterBEImmediate()
		{
			GetInstance().NeuterBEImmediateImpl();
		}

		static void RunOnStartup()
		{
			GetInstance().RunOnStartupImpl();
		}

		static void RunScript()
		{
			GetInstance().RunScriptImpl();
		}

		static bool IsFSLLoaded()
		{
			return GetInstance().m_IsFSLLoaded;
		}

		// actual battleye, as opposed to the FSL shim
		static bool IsBattlEyeRunning()
		{
			return GetInstance().m_BattlEyeRunning;
		}

		static int GetFSLVersion()
		{
			return GetInstance().m_FSLVersion;
		}

		static bool IsFSLProvidingLocalSaves()
		{
			return GetInstance().m_FSLProvidesLocalSaves;
		}

		static bool IsFSLProvidingBattlEyeBypass()
		{
			return GetInstance().m_FSLProvidesBEBypass;
		}

		static bool IsUsingStandaloneLocalSaves()
		{
			return GetInstance().m_StandaloneLocalSaves;
		}

		static bool IsBattlEyeBroken()
		{
			return GetInstance().m_BattlEyeBroken;
		}

		static bool IsBattlEyeNeutered()
		{
			return GetInstance().m_BattlEyeNeutered;
		}
	};
}