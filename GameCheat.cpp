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
  // 清理申请的虚拟内存
  for (size_t i = 0; i < newmems.size(); i++)
  {
    if (newmems[i])
      VirtualFree(newmems[i], 0, MEM_RELEASE);
  }
  
  // 关闭进程句柄
  if (hProcess)
    CloseHandle(hProcess);
}

bool GameCheat::setNop(BYTE* addr, size_t size, SetNopStruct* setNopStruct)
{
  vector<BYTE> origenBytes = {};
  origenBytes.resize(size);
  memcpy_s(origenBytes.data(), size, addr, size);

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
  origenBytes.resize(size);
  memcpy_s(origenBytes.data(), size, (BYTE*)addr, size);

  //2. 申请虚拟空间存hook代码
  BYTE* returnAddr = addr + size;
  size_t codeSize = hookBytes.size() + 100;

  BYTE* newmem = (BYTE*)getVirtualAlloc(codeSize);
  if (!newmem)
  {
    printf("setHook 分配虚拟内存失败。addr: %p\n", addr);
    return false;
  }

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
  vector<BYTE*> addrs = moduleScan(bytes, mask, offset);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], size, hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(vector<BYTE> bytes, size_t offset, size_t size, vector<BYTE> hookBytes, SetHookStruct* setHookStruct)
{
  vector<BYTE*> addrs = moduleScan(bytes, offset);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], size, hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct, string mask)
{
  vector<BYTE*> addrs = moduleScan(bytes, mask);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], bytes.size(), hookBytes, setHookStruct);
}

bool GameCheat::moduleScan(vector<BYTE> bytes, vector<BYTE> hookBytes, SetHookStruct* setHookStruct)
{
  vector<BYTE*> addrs = moduleScan(bytes);
  if (addrs.size() == 0)
  {
    printf("MosuleScan Error: 扫描失败，未找到字节集.\n");
    return false;
  }
  return setHook(addrs[0], bytes.size(), hookBytes, setHookStruct);
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

vector<BYTE*> GameCheat::moduleScan(vector<BYTE> bytes)
{
  return _moduleScan(bytes, "", 0);
}
vector<BYTE*> GameCheat::moduleScan(vector<BYTE> bytes, string mask)
{
  return _moduleScan(bytes, mask, 0);
}
vector<BYTE*> GameCheat::moduleScan(vector<BYTE> bytes, size_t offset)
{
  return _moduleScan(bytes, "", offset);
}
vector<BYTE*> GameCheat::moduleScan(vector<BYTE> bytes, string mask, size_t offset)
{
  return _moduleScan(bytes, mask, offset);
}

vector<BYTE*> GameCheat::moduleScan(string bytes)
{
  return moduleScan(byteStr2Bytes(bytes));
}
vector<BYTE*> GameCheat::moduleScan(string bytes, size_t offset)
{
  return moduleScan(byteStr2Bytes(bytes), offset);
}
vector<BYTE*> GameCheat::moduleScan(string bytes, string mask)
{
  return moduleScan(byteStr2Bytes(bytes), mask);
}
vector<BYTE*> GameCheat::moduleScan(string bytes, string mask, size_t offset)
{
  return moduleScan(byteStr2Bytes(bytes), mask, offset);
}


bool GameCheat::callHook(BYTE* addr, size_t size, BYTE* hook, SetHookStruct* setHookStruct)
{
  vector<BYTE> origenBytes = {};
  origenBytes.resize(size);
  memcpy_s(origenBytes.data(), size, addr, size);

  BYTE* newHook = (BYTE*)getVirtualAlloc(1024);
  if (!newHook) return false;
  size_t position = 0;

#ifdef _WIN64
  // 使用堆栈大小
  // 4*8=32=0x20
  // 16*8=128=0x80 rax-r15
  // 16*8=128=0x80  xmm0-xmm15
  // 32+128+128=288=0x120

  /*
global Start
section .text
  ; 1
  sub rsp,0x120
  mov [rsp+0x20],rax
  mov [rsp+0x28],rbx
  mov [rsp+0x30],rcx
  mov [rsp+0x38],rdx
  mov [rsp+0x40],rsi
  mov [rsp+0x48],rdi
  mov [rsp+0x50],rbp
  mov [rsp+0x58],rsp
  mov [rsp+0x60],r8
  mov [rsp+0x68],r9
  mov [rsp+0x70],r10
  mov [rsp+0x78],r11
  mov [rsp+0x80],r12
  mov [rsp+0x88],r13
  mov [rsp+0x90],r14
  mov [rsp+0x98],r15
  movq [rsp+0xA0],xmm0
  movq [rsp+0xA8],xmm1
  movq [rsp+0xB0],xmm2
  movq [rsp+0xB8],xmm3
  movq [rsp+0xC0],xmm4
  movq [rsp+0xC8],xmm5
  movq [rsp+0xD0],xmm6
  movq [rsp+0xD8],xmm7
  movq [rsp+0xE0],xmm8
  movq [rsp+0xE8],xmm9
  movq [rsp+0xF0],xmm10
  movq [rsp+0xF8],xmm11
  movq [rsp+0x100],xmm12
  movq [rsp+0x108],xmm13
  movq [rsp+0x110],xmm14
  movq [rsp+0x118],xmm15

  ; 2
  lea rcx,[rsp+0x20]
  mov rax,myHook
  call rax

  ; 3
  mov rax,[rsp+0x20]
  mov rbx,[rsp+0x28]
  mov rcx,[rsp+0x30]
  mov rdx,[rsp+0x38]
  mov rsi,[rsp+0x40]
  mov rdi,[rsp+0x48]
  mov rbp,[rsp+0x50]
  ; mov rsp,[rsp+0x58]
  mov r8,[rsp+0x60]
  mov r9,[rsp+0x68]
  mov r10,[rsp+0x70]
  mov r11,[rsp+0x78]
  mov r12,[rsp+0x80]
  mov r13,[rsp+0x88]
  mov r14,[rsp+0x90]
  mov r15,[rsp+0x98]
  movq xmm0,[rsp+0xA0]
  movq xmm1,[rsp+0xA8]
  movq xmm2,[rsp+0xB0]
  movq xmm3,[rsp+0xB8]
  movq xmm4,[rsp+0xC0]
  movq xmm5,[rsp+0xC8]
  movq xmm6,[rsp+0xD0]
  movq xmm7,[rsp+0xD8]
  movq xmm8,[rsp+0xE0]
  movq xmm9,[rsp+0xE8]
  movq xmm10,[rsp+0xF0]
  movq xmm11,[rsp+0xF8]
  movq xmm12,[rsp+0x100]
  movq xmm13,[rsp+0x108]
  movq xmm14,[rsp+0x110]
  movq xmm15,[rsp+0x118]
  add rsp,0x120

myHook:
  */

  // 1
  string bytesStr1 = "48 81 EC 20 01 00 00\n" // sub rsp,0x120
    "48 89 44 24 20\n" // mov [rsp+0x20],rax
    "48 89 5C 24 28\n" // mov [rsp+0x28],rbx
    "48 89 4C 24 30\n" // mov [rsp+0x30],rcx
    "48 89 54 24 38\n" // mov [rsp+0x38],rdx
    "48 89 74 24 40\n" // mov [rsp+0x40],rsi
    "48 89 7C 24 48\n" // mov [rsp+0x48],rdi
    "48 89 6C 24 50\n" // mov [rsp+0x50],rbp
    "48 89 64 24 58\n" // mov [rsp+0x58],rsp
    "4C 89 44 24 60\n" // mov [rsp+0x60],r8
    "4C 89 4C 24 68\n" // mov [rsp+0x68],r9
    "4C 89 54 24 70\n" // mov [rsp+0x70],r10
    "4C 89 5C 24 78\n" // mov [rsp+0x78],r11
    "4C 89 A4 24 80 00 00 00\n" // mov [rsp+0x80],r12
    "4C 89 AC 24 88 00 00 00\n" // mov [rsp+0x88],r13
    "4C 89 B4 24 90 00 00 00\n" // mov [rsp+0x90],r14
    "4C 89 BC 24 98 00 00 00\n" // mov [rsp+0x98],r15
    "66 0F D6 84 24 A0 00 00 00\n" // movq [rsp+0xA0],xmm0
    "66 0F D6 8C 24 A8 00 00 00\n" // movq [rsp+0xA8],xmm1
    "66 0F D6 94 24 B0 00 00 00\n" // movq [rsp+0xB0],xmm2
    "66 0F D6 9C 24 B8 00 00 00\n" // movq [rsp+0xB8],xmm3
    "66 0F D6 A4 24 C0 00 00 00\n" // movq [rsp+0xC0],xmm4
    "66 0F D6 AC 24 C8 00 00 00\n" // movq [rsp+0xC8],xmm5
    "66 0F D6 B4 24 D0 00 00 00\n" // movq [rsp+0xD0],xmm6
    "66 0F D6 BC 24 D8 00 00 00\n" // movq [rsp+0xD8],xmm7
    "66 44 0F D6 84 24 E0 00 00\n" // movq [rsp+0xE0],xmm8
    "00\n"
    "66 44 0F D6 8C 24 E8 00 00\n" // movq [rsp+0xE8],xmm9
    "00\n"
    "66 44 0F D6 94 24 F0 00 00\n" // movq [rsp+0xF0],xmm10
    "00\n"
    "66 44 0F D6 9C 24 F8 00 00\n" // movq [rsp+0xF8],xmm11
    "00\n"
    "66 44 0F D6 A4 24 00 01 00\n" // movq [rsp+0x100],xmm12
    "00\n"
    "66 44 0F D6 AC 24 08 01 00\n" // movq [rsp+0x108],xmm13
    "00\n"
    "66 44 0F D6 B4 24 10 01 00\n" // movq [rsp+0x110],xmm14
    "00\n"
    "66 44 0F D6 BC 24 18 01 00\n" // movq [rsp+0x118],xmm15
    "00\n"

    // 2
    "48 8D 4C 24 20\n" // lea rcx,[rsp+0x20]
    "48 B8"; // mov rax,

  vector<BYTE> bytes1 = GameCheat::byteStr2Bytes(bytesStr1);
  memcpy_s(newHook + position, bytes1.size(), bytes1.data(), bytes1.size());
  position += bytes1.size();

  *(uintptr_t*)(newHook + position) = (uintptr_t)hook; // myHook
  position += sizeof(uintptr_t);

  // 3
  string bytesStr2 = "FF D0\n" // call rax
    "48 8B 44 24 20\n" // mov rax,[rsp+0x20]
    "48 8B 5C 24 28\n" // mov rbx,[rsp+0x28]
    "48 8B 4C 24 30\n" // mov rcx,[rsp+0x30]
    "48 8B 54 24 38\n" // mov rdx,[rsp+0x38]
    "48 8B 74 24 40\n" // mov rsi,[rsp+0x40]
    "48 8B 7C 24 48\n" // mov rdi,[rsp+0x48]
    "48 8B 6C 24 50\n" // mov rbp,[rsp+0x50]
    // "48 8B 64 24 58\n" // mov rsp,[rsp+0x58]
    "4C 8B 44 24 60\n" // mov r8,[rsp+0x60]
    "4C 8B 4C 24 68\n" // mov r9,[rsp+0x68]
    "4C 8B 54 24 70\n" // mov r10,[rsp+0x70]
    "4C 8B 5C 24 78\n" // mov r11,[rsp+0x78]
    "4C 8B A4 24 80 00 00 00\n" // mov r12,[rsp+0x80]
    "4C 8B AC 24 88 00 00 00\n" // mov r13,[rsp+0x88]
    "4C 8B B4 24 90 00 00 00\n" // mov r14,[rsp+0x90]
    "4C 8B BC 24 98 00 00 00\n" // mov r15,[rsp+0x98]
    "F3 0F 7E 84 24 A0 00 00 00\n" // movq xmm0,[rsp+0xA0]
    "F3 0F 7E 8C 24 A8 00 00 00\n" // movq xmm1,[rsp+0xA8]
    "F3 0F 7E 94 24 B0 00 00 00\n" // movq xmm2,[rsp+0xB0]
    "F3 0F 7E 9C 24 B8 00 00 00\n" // movq xmm3,[rsp+0xB8]
    "F3 0F 7E A4 24 C0 00 00 00\n" // movq xmm4,[rsp+0xC0]
    "F3 0F 7E AC 24 C8 00 00 00\n" // movq xmm5,[rsp+0xC8]
    "F3 0F 7E B4 24 D0 00 00 00\n" // movq xmm6,[rsp+0xD0]
    "F3 0F 7E BC 24 D8 00 00 00\n" // movq xmm7,[rsp+0xD8]
    "F3 44 0F 7E 84 24 E0 00 00\n" // movq xmm8,[rsp+0xE0]
    "00\n"
    "F3 44 0F 7E 8C 24 E8 00 00\n" // movq xmm9,[rsp+0xE8]
    "00\n"
    "F3 44 0F 7E 94 24 F0 00 00\n" // movq xmm10,[rsp+0xF0]
    "00\n"
    "F3 44 0F 7E 9C 24 F8 00 00\n" // movq xmm11,[rsp+0xF8]
    "00\n"
    "F3 44 0F 7E A4 24 00 01 00\n" // movq xmm12,[rsp+0x100]
    "00\n"
    "F3 44 0F 7E AC 24 08 01 00\n" // movq xmm13,[rsp+0x108]
    "00\n"
    "F3 44 0F 7E B4 24 10 01 00\n" // movq xmm14,[rsp+0x110]
    "00\n"
    "F3 44 0F 7E BC 24 18 01 00\n" // movq xmm15,[rsp+0x118]
    "00\n"

    "48 81 C4 20 01 00 00"; // add rsp,0x120
  vector<BYTE> bytes2 = GameCheat::byteStr2Bytes(bytesStr2);
  memcpy_s(newHook + position, bytes2.size(), bytes2.data(), bytes2.size());
  position += bytes2.size();

#else

  /*
global Start
section .text
  ; 1
  push esp
  push ebp
  push edi
  push esi
  push edx
  push ecx
  push ebx
  push eax

  ; 2
  push esp
  call myHook

  ; 3
  pop eax
  pop ebx
  pop ecx
  pop edx
  pop esi
  pop edi
  pop ebp
  add esp,0x04

myHook:

*/

// 1
  string bytesStr1 = "54\n" // push esp
    "55\n" // push ebp
    "57\n" // push edi
    "56\n" // push esi
    "52\n" // push edx
    "51\n" // push ecx
    "53\n" // push ebx
    "50\n" // push eax
    "54";  // push esp

  vector<BYTE> bytes1 = GameCheat::byteStr2Bytes(bytesStr1);
  memcpy_s(newHook + position, bytes1.size(), bytes1.data(), bytes1.size());
  position += bytes1.size();

  // call myHook
  DWORD callMyHookBytes = (BYTE*)hook - (newHook + position) - 5;
  *(newHook + position) = 0xE8;
  position += sizeof(BYTE);
  *(DWORD*)(newHook + position) = callMyHookBytes;
  position += sizeof(DWORD);

  // 3
  string bytesStr2 = "58\n" // pop eax
    "5B\n" // pop ebx
    "59\n" // pop ecx
    "5A\n" // pop edx
    "5E\n" // pop esi
    "5F\n" // pop edi
    "5D\n" // pop ebp
    "83 C4 04"; // add esp,0x04

  vector<BYTE> bytes2 = GameCheat::byteStr2Bytes(bytesStr2);
  memcpy_s(newHook + position, bytes2.size(), bytes2.data(), bytes2.size());
  position += bytes2.size();

#endif // _win64

  // return
  DWORD jmpReturnBytes = (addr + size) - (newHook + position) - 5;
  *(newHook + position) = 0xE9;
  position += sizeof(BYTE);
  *(DWORD*)(newHook + position) = jmpReturnBytes;
  
  DWORD jmpHookBytes = newHook - addr - 5;
  setHookStruct->origenBytes = origenBytes;
  setHookStruct->addr = addr;
  setHookStruct->size = size;
  setHookStruct->hookAddr = hook;
  setHookStruct->jmpHookBytes = jmpHookBytes;
  return true;
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

LPVOID GameCheat::getVirtualAlloc(size_t size)
{
#ifdef _WIN64
  if (registerHookAddrBase == 0) registerHookAddrBase = (BYTE*)mi.lpBaseOfDll;
  BYTE* lpAddress = registerHookAddrBase - 0x10000/* 2-4GB */;
#else
  BYTE* lpAddress = 0;
#endif // _WIN64
  LPVOID newmem = VirtualAlloc(lpAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#ifdef _WIN64
  // TODO: 申请失败，接下来可能一直失败
  if (newmem) registerHookAddrBase = (BYTE*)newmem;
#endif // _WIN64

  if (newmem)
    newmems.push_back((BYTE*)newmem);

  return newmem;
}

vector<BYTE*> GameCheat::_moduleScan(vector<BYTE> bytes, string mask, size_t offset)
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

  for (size_t i = 0; i < imageSize - bytesSize; i++)
  {
    bool found = true;
    for (size_t j = 0; j < bytesSize; j++)
    {
      bool notEqual = hasMask ? bytes[j] != *(base + i + j) && maskList[j] != "?" && maskList[j] != "*" : bytes[j] != *(base + i + j);
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
