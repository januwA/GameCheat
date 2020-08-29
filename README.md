## GameCheat 内部作弊常用的函数

```
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include "GameCheat.h"

using namespace std;

DWORD WINAPI MyThread(HMODULE hModule)
{
	GameCheat gc{ "PlantsVsZombies.exe" };
	FILE* f;
	gc.openConsole(&f);
	printf("INJECT OK\n");

	BYTE* addr = (BYTE*)(gc.mi.lpBaseOfDll) + 0x33F86;

	// ---------- INJECTING HERE ----------
	// "PlantsVsZombies.exe" + 33F86: 89 B7 78 55 00 00 - mov[edi + 00005578], esi
	// ---------- DONE INJECTING  ----------
	vector<BYTE> codes = {
		0x81, 0xC6, 0xE8, 0x03, 0x00, 0x00, // add esi,000003E8
		0x89, 0xB7, 0x78, 0x55, 0x00, 0x00 // mov [edi+00005578],esi
	};
	SetHookStruct setHookStruct;
	bool pSuccess = gc.moduleScan("89 B7 78 55 00 00", codes, &setHookStruct);
	while (true)
	{
		if (GetAsyncKeyState(VK_F4) & 1)
		{
			if (pSuccess)
			{
				setHookStruct.toggle();
				if (setHookStruct.bEnable)
				{
					printf("开启\n");
				}
				else {
					printf("关闭\n");
				}
			}
		}

		if (GetAsyncKeyState(VK_F12) & 1)
		{
			break;
		}

		Sleep(20);
	}

	gc.closeConsole(f);
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MyThread, hModule, 0, 0));
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
```