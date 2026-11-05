#include "core/commands/Command.hpp"
#include "core/filemgr/FileMgr.hpp"
#include "core/frontend/Notifications.hpp"
#include <fstream>

namespace YimMenu::Features
{
	class DumpBEClient : public Command
	{
		using Command::Command;

		virtual void OnCall() override
		{
			auto base = reinterpret_cast<uint8_t*>(GetModuleHandleA("BEClient_x64.dll"));
			if (!base)
			{
				Notifications::Show("Dump BEClient", "BEClient_x64.dll not loaded in this process", NotificationType::Error);
				LOG(WARNING) << "DumpBEClient: BEClient_x64.dll not loaded";
				return;
			}

			auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
			auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
			DWORD size = nt->OptionalHeader.SizeOfImage;

			auto buffer = std::make_unique<uint8_t[]>(size);
			memcpy(buffer.get(), base, size);

			// Rewrite section headers so each section's RawData matches its VirtualData,
			// making the file layout mirror the in-memory layout.
			auto new_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(buffer.get() + dos->e_lfanew);
			auto sections = IMAGE_FIRST_SECTION(new_nt);
			for (int i = 0; i < new_nt->FileHeader.NumberOfSections; i++)
			{
				sections[i].SizeOfRawData = sections[i].Misc.VirtualSize;
				sections[i].PointerToRawData = sections[i].VirtualAddress;
			}

			auto path = FileMgr::GetProjectFile("./BEClient_x64_dumped.dll").Path();
			std::ofstream out(path, std::ios::binary | std::ios::trunc);
			if (!out)
			{
				Notifications::Show("Dump BEClient", "Could not open output file", NotificationType::Error);
				LOGF(WARNING, "DumpBEClient: failed to open {}", path.string());
				return;
			}
			out.write(reinterpret_cast<const char*>(buffer.get()), size);
			out.close();

			LOGF(INFO, "DumpBEClient: wrote {} bytes to {}", size, path.string());
			Notifications::Show("Dump BEClient", "Dumped to appdata/YimMenuV2/", NotificationType::Success);
		}
	};

	static DumpBEClient _DumpBEClient{"dumpbeclient", "Dump BEClient", "Dumps the live decrypted BEClient_x64.dll from process memory to appdata/YimMenuV2/BEClient_x64_dumped.dll"};
}
