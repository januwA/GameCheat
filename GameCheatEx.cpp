#include "GameCheatEx.h"

GameCheatEx::Regs GameCheatEx::GC::getRegs(uintptr_t lpRegs)
{
  GameCheatEx::Regs regs;
#ifdef _WIN64
  regs.rax = (lpRegs + sizeof(uintptr_t) * 0);
  regs.rbx = (lpRegs + sizeof(uintptr_t) * 1);
  regs.rcx = (lpRegs + sizeof(uintptr_t) * 2);
  regs.rdx = (lpRegs + sizeof(uintptr_t) * 3);
  regs.rsi = (lpRegs + sizeof(uintptr_t) * 4);
  regs.rdi = (lpRegs + sizeof(uintptr_t) * 5);
  regs.rbp = (lpRegs + sizeof(uintptr_t) * 6);
  regs.rsp = (lpRegs + sizeof(uintptr_t) * 7);
  regs.r8 = (lpRegs + sizeof(uintptr_t) * 8);
  regs.r9 = (lpRegs + sizeof(uintptr_t) * 9);
  regs.r10 = (lpRegs + sizeof(uintptr_t) * 10);
  regs.r11 = (lpRegs + sizeof(uintptr_t) * 11);
  regs.r12 = (lpRegs + sizeof(uintptr_t) * 12);
  regs.r13 = (lpRegs + sizeof(uintptr_t) * 13);
  regs.r14 = (lpRegs + sizeof(uintptr_t) * 14);
  regs.r15 = (lpRegs + sizeof(uintptr_t) * 15);
  regs.xmm0 = (lpRegs + sizeof(uintptr_t) * 16);
  regs.xmm1 = (lpRegs + sizeof(uintptr_t) * 17);
  regs.xmm2 = (lpRegs + sizeof(uintptr_t) * 18);
  regs.xmm3 = (lpRegs + sizeof(uintptr_t) * 19);
  regs.xmm4 = (lpRegs + sizeof(uintptr_t) * 20);
  regs.xmm5 = (lpRegs + sizeof(uintptr_t) * 21);
  regs.xmm6 = (lpRegs + sizeof(uintptr_t) * 22);
  regs.xmm7 = (lpRegs + sizeof(uintptr_t) * 23);
  regs.xmm8 = (lpRegs + sizeof(uintptr_t) * 24);
  regs.xmm9 = (lpRegs + sizeof(uintptr_t) * 25);
  regs.xmm10 = (lpRegs + sizeof(uintptr_t) * 26);
  regs.xmm11 = (lpRegs + sizeof(uintptr_t) * 27);
  regs.xmm12 = (lpRegs + sizeof(uintptr_t) * 28);
  regs.xmm13 = (lpRegs + sizeof(uintptr_t) * 29);
  regs.xmm14 = (lpRegs + sizeof(uintptr_t) * 30);
  regs.xmm15 = (lpRegs + sizeof(uintptr_t) * 31);
#else
  regs.eax = (lpRegs + sizeof(uintptr_t) * 0);
  regs.ebx = (lpRegs + sizeof(uintptr_t) * 1);
  regs.ecx = (lpRegs + sizeof(uintptr_t) * 2);
  regs.edx = (lpRegs + sizeof(uintptr_t) * 3);
  regs.esi = (lpRegs + sizeof(uintptr_t) * 4);
  regs.edi = (lpRegs + sizeof(uintptr_t) * 5);
  regs.ebp = (lpRegs + sizeof(uintptr_t) * 6);
  regs.esp = (lpRegs + sizeof(uintptr_t) * 7);
#endif // _WIN64
  return regs;

}

BYTE* GameCheatEx::GC::createCallLocalFunction(HANDLE hProcess, uintptr_t lplocalFun)
{
  uintptr_t pCreateRemoteThread = GameCheatEx::GC::GetProcAddressEx(hProcess, "kernel32.dll", "CreateRemoteThread");
  uintptr_t pOpenProcess = GameCheatEx::GC::GetProcAddressEx(hProcess, "kernel32.dll", "OpenProcess");
  uintptr_t pCloseHandle = GameCheatEx::GC::GetProcAddressEx(hProcess, "kernel32.dll", "CloseHandle");
  uintptr_t pWaitForSingleObject = GameCheatEx::GC::GetProcAddressEx(hProcess, "kernel32.dll", "WaitForSingleObject");

#ifdef _WIN64
  /*
0000- 55                    - push rbp
0001- 48 8B EC              - mov rbp,rsp
0004- 48 83 EC 18           - sub rsp,18
0008- 48 89 4D F8           - mov [rbp-08],rcx // save regs param

// get local hProcess
000C- 48 83 EC 20           - sub rsp,20
0010- 48 B8 A0A10675F87F0000 - mov rax,KERNEL32.OpenProcess
001A- 48 B9 FFFF1F0000000000 - mov rcx,00000000001FFFFF // PROCESS_ALL_ACCESS
0024- 48 31 D2              - xor rdx,rdx
0027- 49 B8 DC48000000000000 - mov r8,00000000000048DC // lcoal pid
0031- FF D0                 - call rax
0033- 48 89 45 F0           - mov [rbp-10],rax // save local hProcess
0037- 48 83 C4 20           - add rsp,20

// call CreateRemoteThread
003B- 48 83 EC 38           - sub rsp,38
003F- 48 8B C8              - mov rcx,rax
0042- 48 31 D2              - xor rdx,rdx
0045- 4D 31 C0              - xor r8,r8
0048- 49 B9 80102E86F67F0000 - mov r9,00007FF6862E1080 // lpLocalFun
0052- 48 8B 45 F8           - mov rax,[rbp-08]
0056- 48 89 44 24 20        - mov [rsp+20],rax // lpParam
005B- C7 44 24 28 00000000  - mov [rsp+28],00000000
0063- C7 44 24 30 00000000  - mov [rsp+30],00000000
006B- 48 B8 70590875F87F0000 - mov rax,KERNEL32.CreateRemoteThread
0075- FF D0                 - call rax
0077- 48 89 45 E8           - mov [rbp-18],rax // save pThread
007B- 48 83 C4 38           - add rsp,38

// call WaitForSingleObject
007F- 48 83 EC 20           - sub rsp,20
0083- 48 B8 00200775F87F0000 - mov rax,KERNEL32.WaitForSingleObject
008D- 48 8B 4D E8           - mov rcx,[rbp-18]
0091- 48 BA FFFFFFFF00000000 - mov rdx,00000000FFFFFFFF // INFINITE
009B- FF D0                 - call rax
009D- 48 83 C4 20           - add rsp,20

// close hThread and hProcess
00A1- 48 83 EC 20           - sub rsp,20
00A5- 49 BC 101E0775F87F0000 - mov r12,KERNEL32.CloseHandle
00AF- 48 8B 4D E8           - mov rcx,[rbp-18]
00B3- 41 FF D4              - call r12
00B6- 48 8B 4D F0           - mov rcx,[rbp-10]
00BA- 41 FF D4              - call r12
00BD- 48 83 C4 20           - add rsp,20

// end
00C1- 48 83 C4 18           - add rsp,18
00C5- 48 8B E5              - mov rsp,rbp
00C8- 5D                    - pop rbp
00C9- C3                    - ret
  */
  vector<BYTE> funcode = GameCheatEx::GC::byteStr2Bytes("55 48 8B EC 48 83 EC 18 48 89 4D F8 48 83 EC 20 48 B8 A0 A1 06 75 F8 7F 00 00 48 B9 FF FF 1F 00 00 00 00 00 48 31 D2 49 B8 DC 48 00 00 00 00 00 00 FF D0 48 89 45 F0 48 83 C4 20 48 83 EC 38 48 8B C8 48 31 D2 4D 31 C0 49 B9 80 10 2E 86 F6 7F 00 00 48 8B 45 F8 48 89 44 24 20 C7 44 24 28 00 00 00 00 C7 44 24 30 00 00 00 00 48 B8 70 59 08 75 F8 7F 00 00 FF D0 48 89 45 E8 48 83 C4 38 48 83 EC 20 48 B8 00 20 07 75 F8 7F 00 00 48 8B 4D E8 48 BA FF FF FF FF 00 00 00 00 FF D0 48 83 C4 20 48 83 EC 20 49 BC 10 1E 07 75 F8 7F 00 00 48 8B 4D E8 41 FF D4 48 8B 4D F0 41 FF D4 48 83 C4 20 48 83 C4 18 48 8B E5 5D C3");

  *(uintptr_t*)(funcode.data() + 0x12) = (uintptr_t)pOpenProcess; // OpenProcess
  *(uintptr_t*)(funcode.data() + 0x29) = (uintptr_t)GetCurrentProcessId(); // local pid
  *(uintptr_t*)(funcode.data() + 0x4A) = lplocalFun; // lpLocalFun
  *(uintptr_t*)(funcode.data() + 0x6D) = (uintptr_t)pCreateRemoteThread; // CreateRemoteThread
  *(uintptr_t*)(funcode.data() + 0x85) = (uintptr_t)pWaitForSingleObject; // WaitForSingleObject
  *(uintptr_t*)(funcode.data() + 0xA7) = (uintptr_t)pCloseHandle; // CloseHandle

#else
  /*
  0000- 55                    - push ebp
  0001- 8B EC                 - mov ebp,esp
  0003- 83 EC 08              - sub esp,08

  // get local hProcess
  0006- 68 7C230000           - push 0000237C { local pid }
  000B- 6A 00                 - push 00
  000D- 68 FFFF1F00           - push 001FFFFF { PROCESS_ALL_ACCESS  }
  0012- B8 0089C776           - mov eax,KERNEL32.OpenProcess
  0017- FF D0                 - call eax
  0019- 89 45 FC              - mov [ebp-04],eax

  // call CreateRemoteThread
  001C- 6A 00                 - push 00
  001E- 6A 00                 - push 00
  0020- FF 75 08              - push [ebp+08] { localfun param }
  0023- 68 50102100           - push 00211050 { local funAddr }
  0028- 6A 00                 - push 00
  002A- 6A 00                 - push 00
  002C- FF 75 FC              - push [ebp-04]
  002F- B8 0041C976           - mov eax,KERNEL32.CreateRemoteThread
  0034- FF D0                 - call eax
  0036- 89 45 F8              - mov [ebp-08],eax

  // call WaitForSingleObject
  0039- B8 403EC876           - mov eax,KERNEL32.WaitForSingleObject
  003E- 68 FFFFFFFF           - push FFFFFFFF { INFINITE }
  0043- FF 75 F8              - push [ebp-08]
  0046- FF D0                 - call eax

  // close hThread and hProcess
  0048- BB 503CC876           - mov ebx,KERNEL32.CloseHandle
  004D- FF 75 F8              - push [ebp-08]
  0050- FF D3                 - call ebx
  0052- FF 75 FC              - push [ebp-04]
  0055- FF D3                 - call ebx

  0057- 83 C4 08              - add esp,08
  005A- 8B E5                 - mov esp,ebp
  005C- 5D                    - pop ebp
  005D- C2 0400               - ret 0004
  */

  vector<BYTE> funcode = GameCheatEx::GC::byteStr2Bytes("55 8B EC 83 EC 08 68 7C 23 00 00 6A 00 68 FF FF 1F 00 B8 00 89 C7 76 FF D0 89 45 FC 6A 00 6A 00 FF 75 08 68 50 10 21 00 6A 00 6A 00 FF 75 FC B8 00 41 C9 76 FF D0 89 45 F8 B8 40 3E C8 76 68 FF FF FF FF FF 75 F8 FF D0 BB 50 3C C8 76 FF 75 F8 FF D3 FF 75 FC FF D3 83 C4 08 8B E5 5D C2 04 00");

  *(DWORD*)(funcode.data() + 0x07) = (DWORD)GetCurrentProcessId(); // local pid
  *(DWORD*)(funcode.data() + 0x13) = (DWORD)pOpenProcess; // OpenProcess
  *(DWORD*)(funcode.data() + 0x24) = lplocalFun; // lpLocalFun
  *(DWORD*)(funcode.data() + 0x30) = (DWORD)pCreateRemoteThread; // CreateRemoteThread
  *(DWORD*)(funcode.data() + 0x3A) = (DWORD)pWaitForSingleObject; // WaitForSingleObject
  *(DWORD*)(funcode.data() + 0x49) = (DWORD)pCloseHandle; // CloseHandle
#endif // _WIN64

  BYTE* newmem = (BYTE*)VirtualAllocEx(hProcess, 0, funcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProcess, newmem, funcode.data(), funcode.size(), 0);
  return newmem;

}

uintptr_t GameCheatEx::GC::GetProcAddressEx(HANDLE hProcess, string modName, string exportFunName)
{

  MODULEINFO mi = GameCheatEx::GC::GetModuleBase(modName, GetProcessId(hProcess));
  uintptr_t moduleBaseAddr = (uintptr_t)mi.lpBaseOfDll;

  // is PE FILE ?
  WORD e_magic = 0;
  ReadProcessMemory(hProcess, (LPCVOID)moduleBaseAddr, &e_magic, sizeof(WORD), 0);
  if (e_magic != 0x5A4D)
  {
    printf("not PE file.\n");
    return 0;
  }

  // get ntHeader offset
  DWORD e_lfanew = 0;
  ReadProcessMemory(hProcess, (LPCVOID)(moduleBaseAddr + 0x3C), &e_lfanew, sizeof(DWORD), 0);

  uintptr_t ntHeaderAddr = moduleBaseAddr + e_lfanew;
  uintptr_t fileHeaderAddr = ntHeaderAddr + sizeof(DWORD);

  // x86 is 0xE0, x64 is 0xF0
  WORD optHeaderSize = 0;
  ReadProcessMemory(hProcess, (LPCVOID)(fileHeaderAddr + 0x10), &optHeaderSize, sizeof(WORD), 0);

  // tables
  uintptr_t DataDirectoryAddr = fileHeaderAddr + sizeof(IMAGE_FILE_HEADER) + optHeaderSize - sizeof(IMAGE_DATA_DIRECTORY) * 16;

  // tables[0] is export table
  IMAGE_DATA_DIRECTORY exportEntry;
  ReadProcessMemory(hProcess, (LPCVOID)DataDirectoryAddr, &exportEntry, sizeof(IMAGE_DATA_DIRECTORY), 0);
  if (!exportEntry.Size)
  {
    printf("not export table. \n");
    return 0;
  }
  auto RVA2VA = [&](uintptr_t rva) -> uintptr_t
  {
    return moduleBaseAddr + rva;
  };

  uintptr_t exportDirDataAddr = RVA2VA(exportEntry.VirtualAddress);

  // the number of use name export function
  DWORD NumberOfNames = 0;
  ReadProcessMemory(hProcess, (LPCVOID)(exportDirDataAddr + 0x18), &NumberOfNames, sizeof(DWORD), 0);

  DWORD AddressOfFunctions = 0;
  ReadProcessMemory(hProcess, (LPCVOID)(exportDirDataAddr + 0x1C), &AddressOfFunctions, sizeof(DWORD), 0);
  DWORD* AddressOfFunctionsVA = (DWORD*)RVA2VA(AddressOfFunctions);

  // function name table
  DWORD AddressOfNames = 0;
  ReadProcessMemory(hProcess, (LPCVOID)(exportDirDataAddr + 0x20), &AddressOfNames, sizeof(DWORD), 0);
  DWORD* AddressOfNamesVA = (DWORD*)RVA2VA(AddressOfNames);

  DWORD AddressOfNameOrdinals = 0;
  ReadProcessMemory(hProcess, (LPCVOID)(exportDirDataAddr + 0x24), &AddressOfNameOrdinals, sizeof(DWORD), 0);
  WORD* AddressOfNameOrdinalsVA = (WORD*)RVA2VA(AddressOfNameOrdinals);

  auto readASCII = [&](uintptr_t addr, char* name) -> void
  {
    size_t i = 0;
    char c;
    while (true)
    {
      ReadProcessMemory(hProcess, (LPCVOID)(addr + i), &c, sizeof(BYTE), 0);
      name[i] = c;
      if (!c) break;
      i++;
    }
  };

  DWORD itRVA = 0;
  char funName[1024];
  size_t funNameIndex = 0;
  for (; funNameIndex < NumberOfNames; funNameIndex++)
  {
    ReadProcessMemory(hProcess, AddressOfNamesVA + funNameIndex, &itRVA, sizeof(DWORD), 0);
    readASCII(moduleBaseAddr + itRVA, funName);
    if (!strcmp(funName, exportFunName.c_str()))
      break;
  }

  if (strlen(funName) == 0)
  {
    return 0;
  }

  // get function address index
  WORD AddressOfFunctionsIndex = 0;
  ReadProcessMemory(hProcess, AddressOfNameOrdinalsVA + funNameIndex, &AddressOfFunctionsIndex, sizeof(WORD), 0);

  // get function address
  DWORD funAddrRVA = 0;
  ReadProcessMemory(hProcess, AddressOfFunctionsVA + AddressOfFunctionsIndex, &funAddrRVA, sizeof(DWORD), 0);
  return RVA2VA(funAddrRVA);

}

BYTE* GameCheatEx::GC::memsetEx(HANDLE hProcess, BYTE* targetAddr, BYTE val, size_t size)
{
  for (size_t i = 0; i < size; i++)
  {
    WriteProcessMemory(hProcess, targetAddr + i, &val, sizeof(BYTE), 0);
  }
  return targetAddr;

}

wstring GameCheatEx::GC::toWstring(string str)
{
  return wstring(str.begin(), str.end());
}

DWORD GameCheatEx::GC::GetPID(string gameName)
{
  DWORD pid = 0;
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnap != INVALID_HANDLE_VALUE)
  {
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe))
    {
      do
      {
        if (!_wcsicmp(pe.szExeFile, toWstring(gameName).c_str()))
        {
          pid = pe.th32ProcessID;
          break;
        }
      } while (Process32Next(hSnap, &pe));
    }
  }

  CloseHandle(hSnap);
  return pid;

}

MODULEINFO GameCheatEx::GC::GetModuleInfo(string moduleName, HANDLE hProcess)
{
  MODULEINFO mi{ 0 };
  HMODULE hModule = GetModuleHandleW(toWstring(moduleName).c_str());
  if (hModule == 0) return mi;
  // 在MODULEINFO结构中检索有关指定模块的信息
  GetModuleInformation(hProcess, hModule, &mi, sizeof(MODULEINFO));
  CloseHandle(hModule);
  return mi;

}

MODULEINFO GameCheatEx::GC::GetModuleBase(string moduleName, DWORD pid)
{
  MODULEINFO mi{ 0 };
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

  if (hSnap != INVALID_HANDLE_VALUE)
  {
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    if (Module32First(hSnap, &me))
    {
      do {
        if (!_wcsicmp(me.szModule, toWstring(moduleName).c_str()))
        {
          mi.lpBaseOfDll = me.modBaseAddr;
          mi.SizeOfImage = me.modBaseSize;
          break;
        }
      } while (Module32Next(hSnap, &me));
    }
  }
  CloseHandle(hSnap);
  return mi;

}

string GameCheatEx::GC::string_trim(string str)
{
  string r = regex_replace(str, regex("^\\s+"), "");
  r = regex_replace(r, regex("\\s+$"), "");
  return r;
}

vector<string> GameCheatEx::GC::string_split(string str, regex reg)
{
  smatch m;
  string::const_iterator iterStart = str.begin();
  string::const_iterator iterEnd = str.end();

  vector<string> resultSplitList = {};

  while (regex_search(iterStart, iterEnd, m, reg))
  {
    resultSplitList.emplace_back(iterStart, m[0].first);
    iterStart = m[0].second;
  }
  resultSplitList.emplace_back(iterStart, iterEnd);
  return resultSplitList;
}

vector<BYTE> GameCheatEx::GC::byteStr2Bytes(string byteStr)
{
  byteStr = string_trim(byteStr);
  vector<string> byteStrList = string_split(byteStr, regex("[\\s\\n]+"));
  vector<BYTE> byteValList = {};
  for (size_t i = 0; i < byteStrList.size(); i++)
  {
    byteValList.push_back(stoi(byteStrList[i], nullptr, 16));
  }
  return byteValList;
}

GameCheatEx::GC::GC(string gameName)
{
  this->gameName = gameName;
  pid = GetPID(gameName);
  if (!pid) return;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProcess) return;

  mi = GetModuleBase(gameName, pid);
}

GameCheatEx::GC::~GC()
{
  // 清理申请的虚拟内存
  for (size_t i = 0; i < newmems.size(); i++)
  {
    if (newmems[i])
      VirtualFreeEx(hProcess, newmems[i], 0, MEM_RELEASE);
  }

  // 关闭进程句柄
  if (hProcess)
    CloseHandle(hProcess);
}

GameCheatEx::SetNop GameCheatEx::GC::setNop(BYTE* addr, size_t size)
{
  GameCheatEx::SetNop r;
  vector<BYTE> origenBytes = {};
  origenBytes.resize(size);
  ReadProcessMemory(hProcess, addr, origenBytes.data(), size, 0);

  r.hProcess = hProcess;
  r.origenBytes = origenBytes;
  r.addr = addr;
  r.size = size;
  r.bSuccess = true;
  return r;
}

GameCheatEx::SetNop GameCheatEx::GC::setNopRVA(uintptr_t addrRVA, size_t size)
{
  return setNop((BYTE*)mi.lpBaseOfDll + addrRVA, size);
}

GameCheatEx::SetHook GameCheatEx::GC::setHook(BYTE* addr, size_t size, vector<BYTE> hookBytes)
{
  GameCheatEx::SetHook r;
  r.bSuccess = false;
  if (size < 5)
  {
    printf("setHook 设置Hook最少需要5字节\n");
    return r;
  }
  // 1. 拷贝原始字节集，保存起来
  vector<BYTE> origenBytes = {};
  origenBytes.resize(size);
  ReadProcessMemory(hProcess, addr, origenBytes.data(), size, 0);

  //2. 申请虚拟空间存hook代码
  BYTE* returnAddr = addr + size;
  size_t codeSize = hookBytes.size() + 100;

  BYTE* newmem = (BYTE*)getVirtualAlloc(codeSize);
  if (!newmem)
  {
    printf("setHook 分配虚拟内存失败。addr: %p\n", addr);
    return r;
  }
  WriteProcessMemory(hProcess, newmem, hookBytes.data(), codeSize, 0);

  // 3. 从hook jmp回addr的字节集
  BYTE* newmemJmpReturnAddr = newmem + hookBytes.size();
  DWORD returnBytes = (DWORD)(returnAddr - newmemJmpReturnAddr - 5);
  WriteProcessMemory(hProcess, newmemJmpReturnAddr, (LPCVOID)&JMP_BYTE, sizeof(BYTE), 0);
  WriteProcessMemory(hProcess, newmemJmpReturnAddr + 1, (LPCVOID)&returnBytes, sizeof(DWORD), 0);

  // 4. 挂钩/enable
  // 5. 脱钩/disable

  DWORD jmpHookBytes = newmem - addr - 5;
  r.hProcess = hProcess;
  r.origenBytes = origenBytes;
  r.addr = addr;
  r.size = size;
  r.hookAddr = newmem;
  r.jmpHookBytes = jmpHookBytes;
  r.bSuccess = true;
  return r;
}

GameCheatEx::SetHook GameCheatEx::GC::moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, string mask)
{
  GameCheatEx::SetHook r;
  vector<BYTE*> addrs = moduleScan(bytes, mask, offset);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return r;
  }
  return setHook(addrs[0], size, hookBytes);
}
GameCheatEx::SetHook GameCheatEx::GC::moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes)
{
  GameCheatEx::SetHook r;
  vector<BYTE*> addrs = moduleScan(bytes, offset);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return r;
  }
  return setHook(addrs[0], size, hookBytes);
}
GameCheatEx::SetHook GameCheatEx::GC::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, string mask)
{
  GameCheatEx::SetHook r;
  vector<BYTE*> addrs = moduleScan(bytes, mask);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return r;
  }
  return setHook(addrs[0], bytes.size(), hookBytes);
}
GameCheatEx::SetHook GameCheatEx::GC::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes)
{
  GameCheatEx::SetHook r;
  vector<BYTE*> addrs = moduleScan(bytes);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return r;
  }
  return setHook(addrs[0], bytes.size(), hookBytes);
}
GameCheatEx::SetHook GameCheatEx::GC::moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, string mask)
{
  return moduleScan(byteStr2Bytes(bytes), offset, size, hookBytes, mask);
}
GameCheatEx::SetHook GameCheatEx::GC::moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes)
{
  return moduleScan(byteStr2Bytes(bytes), offset, size, hookBytes);
}
GameCheatEx::SetHook GameCheatEx::GC::moduleScan(string bytes, vector<BYTE> hookBytes, string mask)
{
  return moduleScan(byteStr2Bytes(bytes), hookBytes, mask);
}
GameCheatEx::SetHook GameCheatEx::GC::moduleScan(string bytes, vector<BYTE> hookBytes)
{
  return moduleScan(byteStr2Bytes(bytes), hookBytes);
}

vector<BYTE*> GameCheatEx::GC::moduleScan(vector<BYTE> bytes)
{
  return _moduleScan(bytes, "", 0);
}
vector<BYTE*> GameCheatEx::GC::moduleScan(vector<BYTE> bytes, string mask)
{
  return _moduleScan(bytes, mask, 0);
}
vector<BYTE*> GameCheatEx::GC::moduleScan(vector<BYTE> bytes, size_t offset)
{
  return _moduleScan(bytes, "", offset);
}
vector<BYTE*> GameCheatEx::GC::moduleScan(vector<BYTE> bytes, string mask, size_t offset)
{
  return _moduleScan(bytes, mask, offset);
}
vector<BYTE*> GameCheatEx::GC::moduleScan(string bytes)
{
  return moduleScan(byteStr2Bytes(bytes));
}
vector<BYTE*> GameCheatEx::GC::moduleScan(string bytes, size_t offset)
{
  return moduleScan(byteStr2Bytes(bytes), offset);
}
vector<BYTE*> GameCheatEx::GC::moduleScan(string bytes, string mask)
{
  return moduleScan(byteStr2Bytes(bytes), mask);
}
vector<BYTE*> GameCheatEx::GC::moduleScan(string bytes, string mask, size_t offset)
{
  return moduleScan(byteStr2Bytes(bytes), mask, offset);
}

GameCheatEx::SetHook GameCheatEx::GC::callHook(BYTE* addr, size_t size, BYTE* hook)
{
  GameCheatEx::SetHook r;
  r.bSuccess = false;
  vector<BYTE> origenBytes = {};
  origenBytes.resize(size);
  ReadProcessMemory(hProcess, addr, origenBytes.data(), size, 0);

  BYTE* newHook = (BYTE*)getVirtualAlloc(1024);
  if (!newHook) return r;

  // call myHook
  BYTE* calllocalFun = GameCheatEx::GC::createCallLocalFunction(hProcess, (uintptr_t)hook);
#ifdef _WIN64
  // 使用堆栈大小
  // 4*8=32=0x20
  // 16*8=128=0x80 rax-r15
  // 16*8=128=0x80  xmm0-xmm15
  // 32+128+128=288=0x120

  /*
    0000- 48 81 EC 20010000     - sub rsp,00000120
    0007- 48 89 44 24 20        - mov [rsp+20],rax
    000C- 48 89 5C 24 28        - mov [rsp+28],rbx
    0011- 48 89 4C 24 30        - mov [rsp+30],rcx
    0016- 48 89 54 24 38        - mov [rsp+38],rdx
    001B- 48 89 74 24 40        - mov [rsp+40],rsi
    0020- 48 89 7C 24 48        - mov [rsp+48],rdi
    0025- 48 89 6C 24 50        - mov [rsp+50],rbp
    002A- 48 89 64 24 58        - mov [rsp+58],rsp
    002F- 4C 89 44 24 60        - mov [rsp+60],r8
    0034- 4C 89 4C 24 68        - mov [rsp+68],r9
    0039- 4C 89 54 24 70        - mov [rsp+70],r10
    003E- 4C 89 5C 24 78        - mov [rsp+78],r11
    0043- 4C 89 A4 24 80000000  - mov [rsp+00000080],r12
    004B- 4C 89 AC 24 88000000  - mov [rsp+00000088],r13
    0053- 4C 89 B4 24 90000000  - mov [rsp+00000090],r14
    005B- 4C 89 BC 24 98000000  - mov [rsp+00000098],r15
    0063- 66 0FD6 84 24 A0000000  - movq [rsp+000000A0],xmm0
    006C- 66 0FD6 8C 24 A8000000  - movq [rsp+000000A8],xmm1
    0075- 66 0FD6 94 24 B0000000  - movq [rsp+000000B0],xmm2
    007E- 66 0FD6 9C 24 B8000000  - movq [rsp+000000B8],xmm3
    0087- 66 0FD6 A4 24 C0000000  - movq [rsp+000000C0],xmm4
    0090- 66 0FD6 AC 24 C8000000  - movq [rsp+000000C8],xmm5
    0099- 66 0FD6 B4 24 D0000000  - movq [rsp+000000D0],xmm6
    00A2- 66 0FD6 BC 24 D8000000  - movq [rsp+000000D8],xmm7
    00AB- 66 44 0FD6 84 24 E0000000  - movq [rsp+000000E0],xmm8
    00B5- 66 44 0FD6 8C 24 E8000000  - movq [rsp+000000E8],xmm9
    00BF- 66 44 0FD6 94 24 F0000000  - movq [rsp+000000F0],xmm10
    00C9- 66 44 0FD6 9C 24 F8000000  - movq [rsp+000000F8],xmm11
    00D3- 66 44 0FD6 A4 24 00010000  - movq [rsp+00000100],xmm12
    00DD- 66 44 0FD6 AC 24 08010000  - movq [rsp+00000108],xmm13
    00E7- 66 44 0FD6 B4 24 10010000  - movq [rsp+00000110],xmm14
    00F1- 66 44 0FD6 BC 24 18010000  - movq [rsp+00000118],xmm15

    00FB- 48 8D 4C 24 20        - lea rcx,[rsp+20]
    0100- 48 B8 A0A10675F87F0000 - mov rax,localFun { callLocalFun }
    010A- FF D0                 - call rax

    010C- 48 8B 44 24 20        - mov rax,[rsp+20]
    0111- 48 8B 5C 24 28        - mov rbx,[rsp+28]
    0116- 48 8B 4C 24 30        - mov rcx,[rsp+30]
    011B- 48 8B 54 24 38        - mov rdx,[rsp+38]
    0120- 48 8B 74 24 40        - mov rsi,[rsp+40]
    0125- 48 8B 7C 24 48        - mov rdi,[rsp+48]
    012A- 48 8B 6C 24 50        - mov rbp,[rsp+50]
    012F- 4C 8B 44 24 60        - mov r8,[rsp+60]
    0134- 4C 8B 4C 24 68        - mov r9,[rsp+68]
    0139- 4C 8B 54 24 70        - mov r10,[rsp+70]
    013E- 4C 8B 5C 24 78        - mov r11,[rsp+78]
    0143- 4C 8B A4 24 80000000  - mov r12,[rsp+00000080]
    014B- 4C 8B AC 24 88000000  - mov r13,[rsp+00000088]
    0153- 4C 8B B4 24 90000000  - mov r14,[rsp+00000090]
    015B- 4C 8B BC 24 98000000  - mov r15,[rsp+00000098]
    0163- F3 0F7E 84 24 A0000000  - movq xmm0,[rsp+000000A0]
    016C- F3 0F7E 8C 24 A8000000  - movq xmm1,[rsp+000000A8]
    0175- F3 0F7E 94 24 B0000000  - movq xmm2,[rsp+000000B0]
    017E- F3 0F7E 9C 24 B8000000  - movq xmm3,[rsp+000000B8]
    0187- F3 0F7E A4 24 C0000000  - movq xmm4,[rsp+000000C0]
    0190- F3 0F7E AC 24 C8000000  - movq xmm5,[rsp+000000C8]
    0199- F3 0F7E B4 24 D0000000  - movq xmm6,[rsp+000000D0]
    01A2- F3 0F7E BC 24 D8000000  - movq xmm7,[rsp+000000D8]
    01AB- F3 44 0F7E 84 24 E0000000  - movq xmm8,[rsp+000000E0]
    01B5- F3 44 0F7E 8C 24 E8000000  - movq xmm9,[rsp+000000E8]
    01BF- F3 44 0F7E 94 24 F0000000  - movq xmm10,[rsp+000000F0]
    01C9- F3 44 0F7E 9C 24 F8000000  - movq xmm11,[rsp+000000F8]
    01D3- F3 44 0F7E A4 24 00010000  - movq xmm12,[rsp+00000100]
    01DD- F3 44 0F7E AC 24 08010000  - movq xmm13,[rsp+00000108]
    01E7- F3 44 0F7E B4 24 10010000  - movq xmm14,[rsp+00000110]
    01F1- F3 44 0F7E BC 24 18010000  - movq xmm15,[rsp+00000118]
    01FB- 48 81 C4 20010000     - add rsp,00000120
  */

  vector<BYTE> bytecode = GameCheatEx::GC::byteStr2Bytes("48 81 EC 20 01 00 00 48 89 44 24 20 48 89 5C 24 28 48 89 4C 24 30 48 89 54 24 38 48 89 74 24 40 48 89 7C 24 48 48 89 6C 24 50 48 89 64 24 58 4C 89 44 24 60 4C 89 4C 24 68 4C 89 54 24 70 4C 89 5C 24 78 4C 89 A4 24 80 00 00 00 4C 89 AC 24 88 00 00 00 4C 89 B4 24 90 00 00 00 4C 89 BC 24 98 00 00 00 66 0F D6 84 24 A0 00 00 00 66 0F D6 8C 24 A8 00 00 00 66 0F D6 94 24 B0 00 00 00 66 0F D6 9C 24 B8 00 00 00 66 0F D6 A4 24 C0 00 00 00 66 0F D6 AC 24 C8 00 00 00 66 0F D6 B4 24 D0 00 00 00 66 0F D6 BC 24 D8 00 00 00 66 44 0F D6 84 24 E0 00 00 00 66 44 0F D6 8C 24 E8 00 00 00 66 44 0F D6 94 24 F0 00 00 00 66 44 0F D6 9C 24 F8 00 00 00 66 44 0F D6 A4 24 00 01 00 00 66 44 0F D6 AC 24 08 01 00 00 66 44 0F D6 B4 24 10 01 00 00 66 44 0F D6 BC 24 18 01 00 00 48 8D 4C 24 20 48 B8 A0 A1 06 75 F8 7F 00 00 FF D0 48 8B 44 24 20 48 8B 5C 24 28 48 8B 4C 24 30 48 8B 54 24 38 48 8B 74 24 40 48 8B 7C 24 48 48 8B 6C 24 50 4C 8B 44 24 60 4C 8B 4C 24 68 4C 8B 54 24 70 4C 8B 5C 24 78 4C 8B A4 24 80 00 00 00 4C 8B AC 24 88 00 00 00 4C 8B B4 24 90 00 00 00 4C 8B BC 24 98 00 00 00 F3 0F 7E 84 24 A0 00 00 00 F3 0F 7E 8C 24 A8 00 00 00 F3 0F 7E 94 24 B0 00 00 00 F3 0F 7E 9C 24 B8 00 00 00 F3 0F 7E A4 24 C0 00 00 00 F3 0F 7E AC 24 C8 00 00 00 F3 0F 7E B4 24 D0 00 00 00 F3 0F 7E BC 24 D8 00 00 00 F3 44 0F 7E 84 24 E0 00 00 00 F3 44 0F 7E 8C 24 E8 00 00 00 F3 44 0F 7E 94 24 F0 00 00 00 F3 44 0F 7E 9C 24 F8 00 00 00 F3 44 0F 7E A4 24 00 01 00 00 F3 44 0F 7E AC 24 08 01 00 00 F3 44 0F 7E B4 24 10 01 00 00 F3 44 0F 7E BC 24 18 01 00 00 48 81 C4 20 01 00 00");

  *(uintptr_t*)(bytecode.data() + 0x102) = (uintptr_t)calllocalFun;

#else
  /*
    000- 54                    - push esp
    001- 55                    - push ebp
    002- 57                    - push edi
    003- 56                    - push esi
    004- 52                    - push edx
    005- 51                    - push ecx
    006- 53                    - push ebx
    007- 50                    - push eax
    008- 54                    - push esp
    009- B8 78563412           - mov eax,12345678 { callLocalFun }
    00E- FF D0                 - call eax
    010- 58                    - pop eax
    011- 5B                    - pop ebx
    012- 59                    - pop ecx
    013- 5A                    - pop edx
    014- 5E                    - pop esi
    015- 5F                    - pop edi
    016- 5D                    - pop ebp
    017- 83 C4 04              - add esp,04
    // return
*/
  vector<BYTE> bytecode = GameCheatEx::GC::byteStr2Bytes("54 55 57 56 52 51 53 50 54 B8 78 56 34 12 FF D0 58 5B 59 5A 5E 5F 5D 83 C4 04");

  *(DWORD*)(bytecode.data() + 0x0A) = (DWORD)calllocalFun;
#endif // _win64

  WriteProcessMemory(hProcess, newHook, bytecode.data(), bytecode.size(), 0);

  DWORD jmpReturnBytes = (addr + size) - (newHook + bytecode.size()) - 5;
  WriteProcessMemory(hProcess, (LPVOID)(newHook + bytecode.size()), (LPCVOID)&JMP_BYTE, sizeof(BYTE), 0);
  WriteProcessMemory(hProcess, (LPVOID)(newHook + bytecode.size() + 1), (LPCVOID)&jmpReturnBytes, sizeof(DWORD), 0);

  DWORD jmpHookBytes = newHook - addr - 5;
  r.hProcess = hProcess;
  r.origenBytes = origenBytes;
  r.addr = addr;
  r.size = size;
  r.hookAddr = hook;
  r.jmpHookBytes = jmpHookBytes;
  r.bSuccess = true;
  return r;
}

void GameCheatEx::GC::openConsole(FILE** f)
{
  AllocConsole();
  freopen_s(f, "CONOUT$", "w", stdout);
}
void GameCheatEx::GC::closeConsole(FILE* f)
{
  fclose(f);
  FreeConsole();
}

LPVOID GameCheatEx::GC::getVirtualAlloc(size_t size)
{
#ifdef _WIN64
  if (registerHookAddrBase == 0) registerHookAddrBase = (BYTE*)mi.lpBaseOfDll;
  BYTE* lpAddress = registerHookAddrBase - 0x10000/* 2-4GB */;
#else
  BYTE* lpAddress = 0;
#endif // _WIN64
  LPVOID newmem = VirtualAllocEx(hProcess, lpAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#ifdef _WIN64
  // TODO: 申请失败，接下来可能一直失败
  if (newmem) registerHookAddrBase = (BYTE*)newmem;
#endif // _WIN64

  if (newmem)
    newmems.push_back((BYTE*)newmem);

  return newmem;
}

uintptr_t GameCheatEx::GC::toVA(uintptr_t rva)
{
  return (uintptr_t)mi.lpBaseOfDll + rva;
}

vector<BYTE*> GameCheatEx::GC::_moduleScan(vector<BYTE> bytes, string mask, size_t offset)
{
  BYTE* base = (BYTE*)mi.lpBaseOfDll;
  uintptr_t imageSize = mi.SizeOfImage;
  size_t bytesSize = bytes.size();
  vector<BYTE*> addrs = {};

  bool hasMask = !mask.empty();
  vector<string> maskList;
  if (hasMask)
  {
    maskList = string_split(string_trim(mask), regex("\\s+"));
    if (maskList.size() != bytes.size())
    {
      printf("%s\n", "mask与bytes长度不相等.");
      return addrs;
    }
  }

  BYTE v;
  for (size_t i = 0; i < imageSize - bytesSize; i++)
  {
    bool found = true;
    for (size_t j = 0; j < bytesSize; j++)
    {
      ReadProcessMemory(hProcess, (LPCVOID)(base + i + j), (LPVOID)&v, sizeof(BYTE), 0);
      bool notEqual = hasMask ? bytes[j] != v && maskList[j] != "?" && maskList[j] != "*" : bytes[j] != v;
      if (notEqual)
      {
        found = false;
        break;
      }
    }
    if (found) addrs.push_back(base + i + offset);
  }
  return addrs;
}

uintptr_t GameCheatEx::GC::getAddress(vector<uintptr_t> offsets)
{
  if (offsets.size() == 1)
    return offsets[0];

  uintptr_t addr = offsets[0];
  for (size_t i = 1; i < offsets.size() - 1; i++)
  {
    addr += offsets[i];
    ReadProcessMemory(hProcess, (LPCVOID)addr, (LPVOID)&addr, sizeof(uintptr_t), 0);
  }
  return (addr + offsets.back());
}

void GameCheatEx::HookBase::enable()
{
  if (!bSuccess)
  {
    printf("[NoSuccess] %s\n", msg.c_str());
    return;
  }

  DWORD oldProc;
  VirtualProtectEx(hProcess, addr, size, PAGE_EXECUTE_READWRITE, &oldProc);
  GameCheatEx::GC::memsetEx(hProcess, addr, 0x90, size);
  this->enableHook();
  VirtualProtectEx(hProcess, addr, size, oldProc, 0);

  if (!msg.empty())
    printf("[enable]  %s\n", msg.c_str());
}

void GameCheatEx::HookBase::disable()
{
  if (!bSuccess)
  {
    printf("[NoSuccess] %s\n", msg.c_str());
    return;
  }
  DWORD oldProc;
  VirtualProtectEx(hProcess, addr, size, PAGE_EXECUTE_READWRITE, &oldProc);
  WriteProcessMemory(hProcess, addr, origenBytes.data(), size, 0);
  VirtualProtectEx(hProcess, addr, size, oldProc, 0);

  if (!msg.empty())
    printf("[disable] %s\n", msg.c_str());
}

void GameCheatEx::HookBase::toggle()
{
  bEnable = !bEnable;
  if (bEnable) enable();
  else disable();
}
