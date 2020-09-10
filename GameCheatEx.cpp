#include "GameCheatEx.h"

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

bool GameCheatEx::GC::setNop(BYTE* addr, size_t size, SetNop* setNopData)
{
  vector<BYTE> origenBytes = {};
  origenBytes.resize(size);
  ReadProcessMemory(hProcess, addr, origenBytes.data(), size, 0);
  
  setNopData->hProcess = hProcess;
  setNopData->origenBytes = origenBytes;
  setNopData->addr = addr;
  setNopData->size = size;
  return true;
}

bool GameCheatEx::GC::setNopRVA(uintptr_t addrRVA, size_t size, SetNop* setNopData)
{
  return setNop((BYTE*)mi.lpBaseOfDll + addrRVA, size, setNopData);
}

bool GameCheatEx::GC::setHook(BYTE* addr, size_t size, vector<BYTE> hookBytes, SetHook* setHookData)
{
  if (size < 5)
  {
    printf("setHook 设置Hook最少需要5字节\n");
    return false;
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
    return false;
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
  setHookData->hProcess = hProcess;
  setHookData->origenBytes = origenBytes;
  setHookData->addr = addr;
  setHookData->size = size;
  setHookData->hookAddr = newmem;
  setHookData->jmpHookBytes = jmpHookBytes;
  return true;
}

bool GameCheatEx::GC::moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHook* setHookData, string mask)
{
  vector<BYTE*> addrs = moduleScan(bytes, mask, offset);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], size, hookBytes, setHookData);
}
bool GameCheatEx::GC::moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHook* setHookData)
{
  vector<BYTE*> addrs = moduleScan(bytes, offset);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], size, hookBytes, setHookData);
}
bool GameCheatEx::GC::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHook* setHookData, string mask)
{
  vector<BYTE*> addrs = moduleScan(bytes, mask);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], bytes.size(), hookBytes, setHookData);
}
bool GameCheatEx::GC::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHook* setHookData)
{
  vector<BYTE*> addrs = moduleScan(bytes);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], bytes.size(), hookBytes, setHookData);
}
bool GameCheatEx::GC::moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHook* setHookData, string mask)
{
  return moduleScan(byteStr2Bytes(bytes), offset, size, hookBytes, setHookData, mask);
}
bool GameCheatEx::GC::moduleScan(string bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHook* setHookData)
{
  return moduleScan(byteStr2Bytes(bytes), offset, size, hookBytes, setHookData);
}
bool GameCheatEx::GC::moduleScan(string bytes, vector<BYTE> hookBytes, SetHook* setHookData, string mask)
{
  return moduleScan(byteStr2Bytes(bytes), hookBytes, setHookData, mask);
}
bool GameCheatEx::GC::moduleScan(string bytes, vector<BYTE> hookBytes, SetHook* setHookData)
{
  return moduleScan(byteStr2Bytes(bytes), hookBytes, setHookData);
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

bool GameCheatEx::GC::callHook(BYTE* addr, size_t size, BYTE* hook, SetHook* setHookData)
{
  vector<BYTE> origenBytes = {};
  origenBytes.resize(size);
  ReadProcessMemory(hProcess, addr, origenBytes.data(), size, 0);

  BYTE* newHook = (BYTE*)getVirtualAlloc(1024);
  if (!newHook) return false;

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
  setHookData->hProcess = hProcess;
  setHookData->origenBytes = origenBytes;
  setHookData->addr = addr;
  setHookData->size = size;
  setHookData->hookAddr = hook;
  setHookData->jmpHookBytes = jmpHookBytes;
  return true;
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
