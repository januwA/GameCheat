#pragma once
#include <iostream>
#include <string.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <regex>

const BYTE JMP_BYTE = 0xE9;
const BYTE CALL_BYTE = 0xE9;
const BYTE NOP_BYTE = 0x90;

using namespace std;

namespace GameCheatEx
{

  class HookBase
  {
  public:
    HANDLE hProcess;

    // 拷贝的原始字节
    vector<BYTE> origenBytes = {};

    // 挂钩的地址
    BYTE* addr;

    // 字节大小
    size_t size;

    // 是否开启
    bool bEnable = false;

    // 挂钩过程 是否成功
    bool bSuccess = false;

    // 打印消息
    string msg = "";

    void enable();
    void disable();
    void toggle();
    virtual void enableHook() {
    };
  };

  class SetNop : public HookBase
  {

  };

  class SetHook : public HookBase
  {
  public:
    // hook 函数/bytes 地址
    BYTE* hookAddr;
    DWORD jmpHookBytes;
    void enableHook()
    {
     WriteProcessMemory(hProcess, (LPVOID)addr, (LPCVOID)&JMP_BYTE, sizeof(BYTE), 0);
     WriteProcessMemory(hProcess, (LPVOID)(addr + 1), (LPCVOID)&jmpHookBytes, sizeof(DWORD), 0);
    }
  };

  struct Regs
  {
    union
    {
#ifdef _WIN64
      uint64_t rax;
#endif // _WIN64
      DWORD eax;
      WORD ax;
      // BYTE ah; // *(BYTE*)((BYTE*)(&r.ax) + 1)
      BYTE al;
    };
    union
    {
#ifdef _WIN64
      uintptr_t rbx;
#endif // _WIN64
      DWORD ebx;
      WORD bx;
      BYTE bl;
    };
    union
    {

#ifdef _WIN64
      uintptr_t rcx;
#endif // _WIN64
      DWORD ecx;
      WORD cx;
      BYTE cl;
    };
    union
    {
      uintptr_t rdx;
      DWORD edx;
      WORD dx;
      BYTE dl;
    };
    union
    {
#ifdef _WIN64
      uintptr_t rsi;
#endif // _WIN64
      DWORD esi;
      WORD si;
      BYTE sil;
    };
    union
    {
#ifdef _WIN64
      uintptr_t rdi;
#endif // _WIN64
      DWORD edi;
      WORD di;
      BYTE dil;
    };
    union
    {
#ifdef _WIN64
      uintptr_t rbp;
#endif // _WIN64
      DWORD ebp;
      WORD bp;
      BYTE bpl;
    };
    union
    {
#ifdef _WIN64
      uintptr_t rsp;
#endif // _WIN64
      DWORD esp;
      WORD sp;
      BYTE spl;
    };


#ifdef _WIN64
    union
    {
      uintptr_t r8;
      DWORD r8d;
      WORD r8w;
      BYTE r8b;
    };

    union
    {
      uintptr_t r9;
      DWORD r9d;
      WORD r9w;
      BYTE r9b;
    };

    union
    {
      uintptr_t r10;
      DWORD r10d;
      WORD r10w;
      BYTE r10b;
    };

    union
    {
      uintptr_t r11;
      DWORD r11d;
      WORD r11w;
      BYTE r11b;
    };

    union
    {
      uintptr_t r12;
      DWORD r12d;
      WORD r12w;
      BYTE r12b;
    };

    union
    {
      uintptr_t r13;
      DWORD r13d;
      WORD r13w;
      BYTE r13b;
    };

    union
    {
      uintptr_t r14;
      DWORD r14d;
      WORD r14w;
      BYTE r14b;
    };

    union
    {
      uintptr_t r15;
      DWORD r15d;
      WORD r15w;
      BYTE r15b;
    };

    float xmm0;
    float xmm1;
    float xmm2;
    float xmm3;
    float xmm4;
    float xmm5;
    float xmm6;
    float xmm7;
    float xmm8;
    float xmm9;
    float xmm10;
    float xmm11;
    float xmm12;
    float xmm13;
    float xmm14;
    float xmm15;
#endif // _WIN64
  };

  class GC
  {
  public:

    static GameCheatEx::Regs getRegs(uintptr_t lpRegs)
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

    /* 
     ## 在目标进程创建一个函数，调用本地函数

     return func address
    */
    static BYTE* createCallLocalFunction(HANDLE hProcess, uintptr_t lplocalFun)
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

    static uintptr_t GetProcAddressEx(HANDLE hProcess, string modName, string exportFunName)
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


    static BYTE* memsetEx(HANDLE hProcess, BYTE* targetAddr, BYTE val, size_t size)
    {
      for (size_t i = 0; i < size; i++)
      {
        WriteProcessMemory(hProcess, targetAddr + i, &val, sizeof(BYTE), 0);
      }
      return targetAddr;
    }

    /* string to wstring */
    static wstring toWstring(string str)
    {
      return wstring(str.begin(), str.end());
    }

    /* 获取processID */
    static DWORD GetPID(string gameName)
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

    static MODULEINFO GetModuleInfo(string moduleName, HANDLE hProcess)
    {
      MODULEINFO mi{ 0 };
      HMODULE hModule = GetModuleHandleW(toWstring(moduleName).c_str());
      if (hModule == 0) return mi;
      // 在MODULEINFO结构中检索有关指定模块的信息
      GetModuleInformation(hProcess, hModule, &mi, sizeof(MODULEINFO));
      CloseHandle(hModule);
      return mi;
    }

    static MODULEINFO GetModuleBase(string moduleName, DWORD pid)
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

    // 去掉首尾空格，返回新的string
    static string string_trim(string str)
    {
      string r = regex_replace(str, regex("^\\s+"), "");
      r = regex_replace(r, regex("\\s+$"), "");
      return r;
    }

    /*
    ## 使用正则表达式分割字符串
    ```
    vector<string> r = string_split(str, regex("\\s+"));
    ```
    */
    static vector<string> string_split(string str, regex reg)
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

    /* "01 02" to { 0x01, 0x02 } */
    static vector<BYTE> byteStr2Bytes(string byteStr)
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
  public:

    /* game name 如: game.exe */
    string gameName;

    /* 进程id */
    DWORD pid;

    /* game 进程句柄 */
    HANDLE hProcess;

    /* nameProcessName的模块信息 */
    MODULEINFO mi;

    /* 申请的所有虚拟内存地址 */
    vector<BYTE*> newmems = {};

    GC(string gameName);
    ~GC();

    uintptr_t getAddress(vector<uintptr_t> offsets);

    /*
    ```
    GameCheat gc{ "PlantsVsZombies.exe" };
    vector<uintptr_t> offsets = { (uintptr_t)gc.mi.lpBaseOfDll, 0x379618, 0x868, 0x5578 };
    gc.setValue<DWORD>(offsets, 1000);
    ```
    */
    template<class T>
    void setValue(vector<uintptr_t> offsets, T newValue);

    /*
    ```
    gc.setValue(0x004B3724, 100);
    ```
    */
    template<class T>
    void setValue(uintptr_t addr, T newValue);


    /*
    ```
    GameCheat gc{ "PlantsVsZombies.exe" };
    vector<uintptr_t> offsets = { (uintptr_t)gc.mi.lpBaseOfDll, 0x379618, 0x868, 0x5578 };
    printf("%d\n", gc.getValue<DWORD>(offsets));
    ```
    */
    template<class T>
    T getValue(vector<uintptr_t> offsets);

    /*
    ```
    gc.getValue<DWORD>(0x004B3724)
    ```
    */
    template<class T>
    T getValue(uintptr_t addr);

    /*
    * 将字节集替换为nop

    ```c++
      BYTE* addr = (BYTE*)gc.mi.lpBaseOfDll + 0x2B08C;
      GameCheat::SetNopStruct setNop;
      setNop.bSuccess = gc.setNop(addr, 6, &setNop);
      setNop.toggle();
    ```
    */
    bool setNop(BYTE* addr, size_t size, SetNop* setNopData);

    /*
     传递RVA地址
     ```c++
      gc.setNopRVA(0x2B08C, 6, &setNop);
     ```
    */
    bool setNopRVA(uintptr_t addrRVA, size_t size, SetNop* setNopData);

    /*
    * ## 绕行挂钩 失败返回false
    ```
    bool pSuccess = false;
    BYTE* addr = (BYTE*)(gc.mi.lpBaseOfDll) + 0x1575;
    SetHookStruct setHookStruct = gc.setHook(addr, 5, vector<BYTE>{0xA3, 0x24, 0x37, 0x4B, 0x00}, &pSuccess);

    if (pSuccess) setHookStruct.toggle();
     ```

     ```
    BYTE* addr = (BYTE*)(gc.mi.lpBaseOfDll) + 0x33F86;
    vector<BYTE> codes = {
      0x81, 0xC6, 0xE8, 0x03, 0x00, 0x00, // add esi,000003E8
      0x89, 0xB7, 0x78, 0x55, 0x00, 0x00 // mov [edi+00005578],esi
    };
    SetHookStruct setHookStruct;
    bool pSuccess = gc.setHook(addr, 6, codes, &setHookStruct);

    if (pSuccess) setHookStruct.toggle();
     ```
    */
    bool setHook(BYTE* addr, size_t size, vector<BYTE> hookBytes, SetHook* setHookStruct);

    /*
    * ## 在模块中扫描字节集

    - bytes 需要扫描的字节集
    - offset 挂钩开始的偏移，默认 0
    - size   从挂钩处开始复制的字节数量，默认情况: 如果offset=0那么将是`bytes.size()`,否则`bytes.size() - offset`
    - hookBytes 钩子函数
    - mask  模糊查询，使用空格区分每隔字节, ?/* 将会跳过这个字节检查

    ```
    // ---------- INJECTING HERE ----------
    // "PlantsVsZombies.exe" + 33F86: 89 B7 78 55 00 00 - mov[edi + 00005578], esi
    // ---------- DONE INJECTING  ----------
    vector<BYTE> bytes = { 0x89, 0xB7, 0x78, 0x55, 0x00, 0x00 };
    vector<BYTE> codes = {
      0x81, 0xC6, 0xE8, 0x03, 0x00, 0x00, // add esi,000003E8
      0x89, 0xB7, 0x78, 0x55, 0x00, 0x00 // mov [edi+00005578],esi
    };
    SetHookStruct setHookStruct;
    bool pSuccess = gc.moduleScan(bytes, codes, &setHookStruct);

    ```
    */
    bool moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes,
      SetHook* setHookStruct, string mask);
    bool moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHook* setHookStruct);
    bool moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHook* setHookStruct, string mask);
    bool moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHook* setHookStruct);

    /*
    # hex字符串参数
    ```
    // ---------- INJECTING HERE ----------
    // "PlantsVsZombies.exe" + 33F86: 89 B7 78 55 00 00 - mov[edi + 00005578], esi
    // ---------- DONE INJECTING  ----------
    vector<BYTE> codes = {
      0x81, 0xC6, 0xE8, 0x03, 0x00, 0x00, // add esi,000003E8
      0x89, 0xB7, 0x78, 0x55, 0x00, 0x00 // mov [edi+00005578],esi
    };
    SetHookStruct setHookStruct;
    bool pSuccess = gc.moduleScan("89 B7 78 55 00 00", codes, &setHookStruct);
    ```
    */
    bool moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes,
      SetHook* setHookStruct, string mask);
    bool moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHook* setHookStruct);
    bool moduleScan(string bytes, vector<BYTE> hookBytes, SetHook* setHookStruct, string mask);
    bool moduleScan(string bytes, vector<BYTE> hookBytes, SetHook* setHookStruct);


    /*
    ## 查找后返回地址列表
    ```c++
    vector<BYTE*> addrs = gc.moduleScan("29 83 AC 04 00 00");
    printf("%d\n", addrs.size());
    for (size_t i = 0; i < addrs.size(); i++)
    {
      printf("%x\n", addrs[i]);
    }
    ```
    */
    vector<BYTE*> moduleScan(vector<BYTE> bytes);
    vector<BYTE*> moduleScan(vector<BYTE> bytes, size_t offset);
    vector<BYTE*> moduleScan(vector<BYTE> bytes, string mask);
    vector<BYTE*> moduleScan(vector<BYTE> bytes, string mask, size_t offset);
    vector<BYTE*> moduleScan(string bytes);
    vector<BYTE*> moduleScan(string bytes, size_t offset);
    vector<BYTE*> moduleScan(string bytes, string mask);
    vector<BYTE*> moduleScan(string bytes, string mask, size_t offset);

    /*
    # 使用这个函数挂钩Hook函数, 函数可以获取 寄存器指针 列表

    ## x86:
    ```c++
    GameCheatEx::GC gc{ "Tutorial-i386.exe" };

    void __stdcall hello(uintptr_t lpRegs)
    {
      GameCheatEx::Regs regs = GameCheatEx::GC::getRegs(lpRegs);
      gc.setValue<DWORD>({ regs.ebx, 0x00, 0x4AC }, 100);
    }

    // Tutorial-i386.exe+2578F - 29 83 AC040000        - sub [ebx+000004AC],eax
    GameCheatEx::SetHook sk;
    BYTE* addr = (BYTE*)gc.toVA(0x2578F);
    sk.bSuccess = gc.callHook(addr, 6, (BYTE*)&hello, &sk);
    ```

    ## x64:
    ```c++
    GameCheatEx::GC gc{ "Tutorial-x86_64.exe" };

    void __stdcall hello(uintptr_t lpRegs)
    {
      GameCheatEx::Regs regs = GameCheatEx::GC::getRegs(lpRegs);
      gc.setValue<DWORD>({ regs.rbx, 0x00, 0x7F0 }, 100);
    }

    // Tutorial-x86_64.exe+2B08C - 29 83 F0070000      - sub [rbx+000007F0],eax
    GameCheatEx::SetHook sk;
    BYTE* addr = (BYTE*)gc.toVA(0x2B08C);
    sk.bSuccess = gc.callHook(addr, 6, (BYTE*)&hello, &sk);
    ```
    */
    bool callHook(BYTE* addr, size_t size, BYTE* hook, SetHook* setHookStruct);

    /*
    ## 开启一个控制台
    ```c++
    GameCheat gc{ "game2.exe" };
    FILE* f;
    gc.openConsole(&f);
    printf("INJECT OK\n");
    ```
    */
    void openConsole(FILE** f);

    /*
    ## 关闭一个控制台
    ```c++
    gc.closeConsole(f);
    ```
    */
    void closeConsole(FILE* f);

    /*
    # 申请虚拟内存，务必调用这个函数
    */
    LPVOID getVirtualAlloc(size_t size);

    uintptr_t toVA(uintptr_t rva);
  private:
    /* 在x64如果指针不在2-4GB则无法跳转 */
    BYTE* registerHookAddrBase = 0;

    /*
    * 扫描内存，返回地址
    */
    vector<BYTE*> _moduleScan(vector<BYTE> bytes, string mask, size_t offset);
  };

  template<class T>
  inline void GC::setValue(vector<uintptr_t> offsets, T newValue)
  {
    LPVOID pv = (LPVOID)getAddress(offsets);
    WriteProcessMemory(hProcess, pv, (LPCVOID)&newValue, sizeof(T), 0);
  }

  template<class T>
  inline void GC::setValue(uintptr_t addr, T newValue)
  {
    WriteProcessMemory(hProcess, (LPVOID)addr, (LPCVOID)&newValue, sizeof(T), 0);
  }

  template<class T>
  inline T GC::getValue(vector<uintptr_t> offsets)
  {
    LPVOID pv = getAddress(offsets);
    T val;
    ReadProcessMemory(hProcess, pv, (LPCVOID)&val, sizeof(T), 0);
    return val;
  }

  template<class T>
  inline T GC::getValue(uintptr_t addr)
  {
    T val;
    ReadProcessMemory(hProcess, (LPCVOID)addr, (LPVOID)&val, sizeof(T), 0);
    return val;
  }
}
