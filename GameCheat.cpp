#include "pch.h"
#include "GameCheat.h"

GameCheat::GameCheat(string gameName)
{
	this->gameName = gameName;
	pid = GetPID(gameName);
	if (!pid) return;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess) return;

	mi = GetModuleInfo(gameName, hProcess);
}

GameCheat::~GameCheat()
{
	if (hProcess)
	{
		CloseHandle(hProcess);
	}
}

bool GameCheat::setNop(uintptr_t addr, size_t size, SetNopStruct* setNopStruct)
{
	vector<BYTE> origenBytes = {};
	for (size_t i = 0; i < size; i++)
	{
		origenBytes.push_back(*(BYTE*)(addr + i));
	}
	setNopStruct->origenBytes = origenBytes;
	setNopStruct->addr = addr;
	setNopStruct->size = size;
	return true;
}

bool GameCheat::setHook(BYTE* addr, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct)
{
	if (size < 5)
	{
		printf("setHook 设置Hook最少需要5字节\n");
		return false;
	}
	// 1. 拷贝原始字节集，保存起来
	vector<BYTE> origenBytes = {};

	for (size_t i = 0; i < size; i++)
	{
		origenBytes.push_back(*(addr + i));
	}

	//2. 申请虚拟空间存hook代码
	BYTE* returnAddr = addr + size;
	size_t codeSize = hookBytes.size() + 100;

#ifdef _WIN64

	if (registerHookAddrBase == 0) registerHookAddrBase = (BYTE*)mi.lpBaseOfDll;
	BYTE* lpAddress = registerHookAddrBase - 0x10000/* 2-4GB */;
#else
	BYTE* lpAddress = 0;
#endif // _WIN64


	BYTE* newmem = (BYTE*)VirtualAlloc(lpAddress, codeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!newmem)
	{
		printf("setHook 分配虚拟内存失败。addr: %p\n", addr);
		return false;
	}

#ifdef _WIN64
	registerHookAddrBase = newmem;
#endif // _WIN64

	memcpy_s(newmem, codeSize, hookBytes.data(), codeSize);

	// 3. 从hook jmp回addr的字节集
	BYTE* newmemJmpReturnAddr = newmem + hookBytes.size();
	DWORD returnBytes = (DWORD)(returnAddr - newmemJmpReturnAddr - 5);
	*(newmemJmpReturnAddr) = 0xE9; // jmp
	*(DWORD*)(newmemJmpReturnAddr + 1) = returnBytes;

	// 4. 挂钩/enable
	// 5. 脱钩/disable

	DWORD jmpHookBytes = newmem - addr - 5;
	setHookStruct->origenBytes = origenBytes;
	setHookStruct->addr = addr;
	setHookStruct->size = size;
	setHookStruct->hookAddr = newmem;
	setHookStruct->jmpHookBytes = jmpHookBytes;
	return true;
}

bool GameCheat::moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct, string mask)
{
	BYTE* base = (BYTE*)mi.lpBaseOfDll;
	uintptr_t imageSize = mi.SizeOfImage;
	size_t bytesSize = bytes.size();

	BYTE* addr = 0;
	mask = string_trim(mask);
	vector<string> maskList = string_split(mask, regex("\\s+"));
	if (maskList.size() != bytes.size())
	{
		printf("%s\n", "mask与bytes长度不相等.");
		return false;
	}

	// 遍历镜像，可能会找到很多，默认第一次找到的位置
	for (size_t i = 0; i < imageSize - bytesSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < bytesSize; j++)
		{
			if (bytes[j] != *(base + i + j) && maskList[j] != "?" && maskList[j] != "*")
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			addr = base + i + offset;
			break;
		}
	}
	if (!addr)
	{
		printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
		return false;
	}

	return setHook(addr, size, hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct)
{
	BYTE* base = (BYTE*)mi.lpBaseOfDll;
	uintptr_t imageSize = mi.SizeOfImage;
	size_t bytesSize = bytes.size();

	BYTE* addr = 0;

	// 遍历镜像，可能会找到很多，默认第一次找到的位置
	for (size_t i = 0; i < imageSize - bytesSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < bytesSize; j++)
		{
			if (bytes[j] != *(base + i + j))
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			addr = base + i + offset;
			break;
		}
	}
	if (!addr)
	{
		printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
		return false;
	}

	return setHook(addr, size, hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct, string mask)
{
	BYTE* base = (BYTE*)mi.lpBaseOfDll;
	uintptr_t imageSize = mi.SizeOfImage;
	size_t bytesSize = bytes.size();

	BYTE* addr = 0;
	mask = string_trim(mask);
	vector<string> maskList = string_split(mask, regex("\\s+"));
	if (maskList.size() != bytes.size())
	{
		printf("%s\n", "mask与bytes长度不相等.");
		return false;
	}

	// 遍历镜像，可能会找到很多，默认第一次找到的位置
	for (size_t i = 0; i < imageSize - bytesSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < bytesSize; j++)
		{
			if (bytes[j] != *(base + i + j) && maskList[j] != "?" && maskList[j] != "*")
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			addr = base + i;
			break;
		}
	}
	if (!addr)
	{
		printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
		return false;
	}
	return setHook(addr, bytes.size(), hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct)
{
	BYTE* base = (BYTE*)mi.lpBaseOfDll;
	uintptr_t imageSize = mi.SizeOfImage;
	size_t bytesSize = bytes.size();

	BYTE* addr = 0;
	// 遍历镜像，可能会找到很多，默认第一次找到的位置
	for (size_t i = 0; i < imageSize - bytesSize; i++)
	{
		bool found = true;
		for (size_t j = 0; j < bytesSize; j++)
		{
			if (bytes[j] != *(base + i + j))
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			addr = base + i;
			break;
		}
	}
	if (!addr)
	{
		printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
		return false;
	}
	return setHook(addr, bytes.size(), hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct, string mask)
{
	return moduleScan(byteStr2Bytes(bytes), offset, size, hookBytes, setHookStruct, mask);
}

bool GameCheat::moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct)
{
	return moduleScan(byteStr2Bytes(bytes), offset, size, hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(string bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct, string mask)
{
	return moduleScan(byteStr2Bytes(bytes), hookBytes, setHookStruct, mask);
}

bool GameCheat::moduleScan(string bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct)
{
	return moduleScan(byteStr2Bytes(bytes), hookBytes, setHookStruct);
}

void GameCheat::openConsole(FILE** f)
{
	AllocConsole();
	freopen_s(f, "CONOUT$", "w", stdout);
}

void GameCheat::closeConsole(FILE* f)
{
	fclose(f);
	FreeConsole();
}
