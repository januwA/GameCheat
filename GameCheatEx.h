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

    /*
      对于外部作弊，需要手动算出寄存器在堆栈上的指针，将每隔值设置为指针，然后使用Write/ReadProcessMemory去读写这些寄存器
    */
    static GameCheatEx::Regs getRegs(uintptr_t lpRegs);
    /*
     ## 在目标进程创建一个函数，调用本地函数
     return func address
    */
    static BYTE* createCallLocalFunction(HANDLE hProcess, uintptr_t lplocalFun);
  
    /* 获取目标程序的模块的导出表中找到函数的地址 */
    static uintptr_t GetProcAddressEx(HANDLE hProcess, string modName, string exportFunName);

    static BYTE* memsetEx(HANDLE hProcess, BYTE* targetAddr, BYTE val, size_t size);

    /* string to wstring */
    static wstring toWstring(string str);

    /* 获取processID */
    static DWORD GetPID(string gameName);

    static MODULEINFO GetModuleInfo(string moduleName, HANDLE hProcess);

    static MODULEINFO GetModuleBase(string moduleName, DWORD pid);

    // 去掉首尾空格，返回新的string
    static string string_trim(string str);

    /*
    ## 使用正则表达式分割字符串
    ```
    vector<string> r = string_split(str, regex("\\s+"));
    ```
    */
    static vector<string> string_split(string str, regex reg);

    /* "01 02" to { 0x01, 0x02 } */
    static vector<BYTE> byteStr2Bytes(string byteStr);
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
    GC(DWORD pid);
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
      GameCheat::SetNop r = gc.setNop(addr, 6);
      r.toggle();
    ```
    */
    SetNop setNop(BYTE* addr, size_t size);

    /*
     传递RVA地址
     ```c++
     GameCheat::SetNop r = gc.setNopRVA(0x2B08C, 6);
     ```
    */
    SetNop setNopRVA(uintptr_t addrRVA, size_t size);

    /*
    * ## 绕行挂钩 失败返回false
    ```
    BYTE* addr = (BYTE*)(gc.mi.lpBaseOfDll) + 0x1575;
    GameCheatEx::SetHook r = gc.setHook(addr, 5, vector<BYTE>{0xA3, 0x24, 0x37, 0x4B, 0x00});
    r.toggle();
     ```

     ```
    BYTE* addr = (BYTE*)(gc.mi.lpBaseOfDll) + 0x33F86;
    vector<BYTE> codes = {
      0x81, 0xC6, 0xE8, 0x03, 0x00, 0x00, // add esi,000003E8
      0x89, 0xB7, 0x78, 0x55, 0x00, 0x00 // mov [edi+00005578],esi
    };
    GameCheatEx::SetHook r = gc.setHook(addr, 6, codes);
    r.toggle();
     ```
    */
    SetHook setHook(BYTE* addr, size_t size, vector<BYTE> hookBytes);

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
    GameCheatEx::SetHook r = gc.moduleScan(bytes, codes, &setHookStruct);
    ```
    */
    SetHook moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, string mask);
    SetHook moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes);
    SetHook moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, string mask);
    SetHook moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes);

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
    GameCheatEx::SetHook r = gc.moduleScan("89 B7 78 55 00 00", codes);
    ```
    */
    SetHook moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, string mask);
    SetHook moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes);
    SetHook moduleScan(string bytes, vector<BYTE> hookBytes, string mask);
    SetHook moduleScan(string bytes, vector<BYTE> hookBytes);


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
    BYTE* addr = (BYTE*)gc.toVA(0x2578F);
    GameCheatEx::SetHook sk = gc.callHook(addr, 6, (BYTE*)&hello, &sk);
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
    BYTE* addr = (BYTE*)gc.toVA(0x2B08C);
    GameCheatEx::SetHook sk = gc.callHook(addr, 6, (BYTE*)&hello);
    ```
    */
    SetHook callHook(BYTE* addr, size_t size, BYTE* hook);

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
