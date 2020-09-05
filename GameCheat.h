#pragma once
#include <iostream>
#include <string.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <vector>
#include <regex>

using namespace std;

class GameCheat
{
public:

  struct SetNopStruct
  {
    vector<BYTE> origenBytes = {};
    uintptr_t addr;
    size_t size;
    bool bEnable = false;
    void enable()
    {
      DWORD oldProc;
      VirtualProtect((BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &oldProc);
      memset((BYTE*)addr, 0x90, size);
      VirtualProtect((BYTE*)addr, size, oldProc, 0);
    }
    void disable()
    {
      DWORD oldProc;
      VirtualProtect((BYTE*)addr, size, PAGE_EXECUTE_READWRITE, &oldProc);
      _memccpy((BYTE*)addr, (BYTE*)(origenBytes.data()), 0, size);
      VirtualProtect((BYTE*)addr, size, oldProc, 0);
    }
    void toggle()
    {
      bEnable = !bEnable;
      if (bEnable) enable();
      else disable();
    }
  };
  struct SetHookStruct
  {
    vector<BYTE> origenBytes = {};
    BYTE* addr;
    size_t size;
    BYTE* hookAddr;
    DWORD jmpHookBytes;
    bool bEnable = false;
    void enable()
    {
      DWORD oldProc;
      VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProc);
      memset(addr, 0x90, size);
      *addr = 0xE9;
      *(DWORD*)(addr + 1) = jmpHookBytes;
      VirtualProtect(addr, size, oldProc, 0);
    }
    void disable()
    {
      DWORD oldProc;
      VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &oldProc);
      memcpy_s(addr, size, origenBytes.data(), size);
      VirtualProtect(addr, size, oldProc, 0);
    }
    void toggle()
    {
      bEnable = !bEnable;
      if (bEnable) enable();
      else disable();
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

  static uintptr_t GetModuleBase(string moduleName, DWORD pid)
  {
    uintptr_t addr = 0;
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
            addr = (uintptr_t)me.modBaseAddr;
            break;
          }
        } while (Module32Next(hSnap, &me));
      }
    }
    CloseHandle(hSnap);
    return addr;
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
  GameCheat(string gameName);
  ~GameCheat();

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

  ```
  SetNopStruct setNopData;
  gc.setNop(0x401575, 5, &setNopData);
  if (GetAsyncKeyState(VK_F4) & 1)
  {
    reset.toggle();
  }
  ```
  */
  bool setNop(uintptr_t addr, size_t size, SetNopStruct* setNopStruct);

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
  bool setHook(BYTE* addr, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct);

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
    SetHookStruct* setHookStruct, string mask);
  bool moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct);
  bool moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct, string mask);
  bool moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct);

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
    SetHookStruct* setHookStruct, string mask);
  bool moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct);
  bool moduleScan(string bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct, string mask);
  bool moduleScan(string bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct);


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
  vector<BYTE*> moduleScan(vector<BYTE> bytes, string mask);
  vector<BYTE*> moduleScan(vector<BYTE> bytes);
  vector<BYTE*> moduleScan(string bytes, string mask);
  vector<BYTE*> moduleScan(string bytes);

  /*
  # 使用这个函数挂钩Hook函数, 函数可以获取寄存器列表
  ```c++
  void __stdcall myHook(GameCheat::Regs* regs)
  {
  #ifdef _WIN64
    printf("rax: %x\n", regs->rax);
    printf("rbx: %x\n", regs->rbx);
    printf("rcx: %x\n", regs->rcx);
    printf("rdx: %x\n", regs->rdx);
    printf("xmm0: %f\n", regs->xmm0);
    *&regs->eax = 100;
    *(DWORD*)(regs->rbx + 0x7F0) = *&regs->eax;

  #else
    printf("eax: %x\n", regs->eax);
    printf("ebx: %x\n", regs->ebx);
    printf("ecx: %x\n", regs->ecx);
    printf("edx: %x\n", regs->edx);
    *&regs->eax = 0;
  #endif // _WIN64
  }

  GameCheat::SetHookStruct setHookStruct;
  bool bSuccess = gc.callHook((BYTE*)gc.mi.lpBaseOfDll + 0x2B08C, 6, (BYTE*)&myHook, &setHookStruct);
  if (bSuccess) setHookStruct.toggle();
  ```
  */
  bool callHook(BYTE* addr, size_t size, BYTE* hook, SetHookStruct* setHookStruct);

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
private:
  /* 在x64如果指针不在2-4GB则无法跳转 */
  BYTE* registerHookAddrBase = 0;

};

template<class T>
inline void GameCheat::setValue(vector<uintptr_t> offsets, T newValue)
{
  if (offsets.size() == 1)
  {
    *(T*)offsets.at(0) = newValue;
    return;
  }
  uintptr_t addr = offsets.at(0);
  for (size_t i = 1; i < offsets.size() - 1; i++)
  {
    addr += offsets.at(i);
    addr = *(uintptr_t*)addr;
  }
  *(T*)(addr + offsets.back()) = newValue;
}

template<class T>
inline void GameCheat::setValue(uintptr_t addr, T newValue)
{
  *(T*)addr = newValue;
}

template<class T>
inline T GameCheat::getValue(vector<uintptr_t> offsets)
{
  if (offsets.size() == 1)
  {
    return *(T*)offsets.at(0);
  }
  uintptr_t addr = offsets.at(0);
  for (size_t i = 1; i < offsets.size() - 1; i++)
  {
    addr += offsets.at(i);
    addr = *(uintptr_t*)addr;
  }
  T r = *(T*)(addr + offsets.back());
  return r;
}

template<class T>
inline T GameCheat::getValue(uintptr_t addr)
{
  return *(T*)addr;
}
