## GameCheat::GC 内部作弊常用的函数

```c++
#include "pch.h"
#include <iostream>
#include "GameCheat.h"

using namespace std;

DWORD WINAPI MyThread(HMODULE hModule)
{
  GameCheat::GC gc{ "PlantsVsZombies.exe" };
  FILE* f;
  gc.openConsole(&f);

  // "PlantsVsZombies.exe" + 33F86: 89 B7 78 55 00 00 - mov [edi + 00005578], esi
  vector<BYTE> codes = {
    0x81, 0xC6, 0xE8, 0x03, 0x00, 0x00, // add esi,000003E8
    0x89, 0xB7, 0x78, 0x55, 0x00, 0x00 // mov [edi+00005578],esi
  };
  GameCheat::SetHook SetHook;
  bool pSuccess = gc.moduleScan("89 B7 78 55 00 00", codes, &SetHook);
  while (!GetAsyncKeyState(VK_END))
  {
    if (GetAsyncKeyState(VK_F4) & 1)
      SetHook.toggle();

    Sleep(10);
  }

  gc.closeConsole(f);
  FreeLibraryAndExitThread(hModule, 0);
  return 0;
}
```


# 模块扫描+HOOK Example

## AA Script
```
[ENABLE]
aobscanmodule(hp_INJECT,sekiro.exe,C1 8B 00 89 83 30 01 00 00)
alloc(newmem,$1000,"sekiro.exe"+BBF3BE)

label(code)
label(plater)
label(ms)
label(return)

label(bMs) // 是否秒杀

newmem:
  pushfq
  cmp [rbx+18],0
  je plater

  // other
  cmp [bMs],0
  jne ms
  jmp code

ms:
  // 避免自动秒
  cmp [rbx+134],eax
  je code
  mov eax,0
  jmp code

plater:
  mov eax,[rbx+134]
  jmp code

code:
  popfq
  mov [rbx+00000130],eax
  jmp return

bMs:
  db 0

hp_INJECT+03:
  jmp newmem
  nop
return:
registersymbol(hp_INJECT bMs)

[DISABLE]

hp_INJECT+03:
  db 89 83 30 01 00 00

unregistersymbol(hp_INJECT bMs)
dealloc(newmem)
dealloc(bMs)

{
"sekiro.exe"+BBF3B8: 48 0F 4F C1                    -  cmovg rax,rcx
"sekiro.exe"+BBF3BC: 8B 00                          -  mov eax,[rax]
// ---------- INJECTING HERE ----------
"sekiro.exe"+BBF3BE: 89 83 30 01 00 00              -  mov [rbx+00000130],eax
// ---------- DONE INJECTING  ----------
```

## c++
```c++
#include "pch.h"
#include <iostream>
#include "GameCheat.h"

using namespace std;

void __stdcall playerAndEnemyHP_h(GameCheat::Regs regs)
{
  bool isPlayer = (*(DWORD*)(regs.rbx + 0x18)) == 0;
  DWORD* pDamage = &regs.eax;

  DWORD* pCurHP = (DWORD*)(regs.rbx + 0x130);
  DWORD* pMaxHP = (DWORD*)(regs.rbx + 0x134);

  printf("[%s] curHP: %d, maxHP: %d, Damage: %d\n", isPlayer ? "Player" : "Enemy", *pCurHP, *pMaxHP, *pDamage);

  if (isPlayer)
  {
    *pDamage = *pMaxHP;
    *pCurHP = *pDamage;
  }
  else
  {
    if (*pDamage != *pMaxHP) // 避免自动秒
    {
      *pDamage = 0;
      *pCurHP = *pDamage;
    }
  }
}

int WINAPI Mythread(HMODULE hModule)
{

  GameCheat::GC gc{ "sekiro.exe" };
  FILE* f;
  gc.openConsole(&f);

  GameCheat::SetHook playerAndEnemyHP;
  playerAndEnemyHP.msg = "player And Enemy HP";

  vector<BYTE*> addrs = gc.moduleScan("C1 8B 00 89 83 30 01 00 00", 3);
  playerAndEnemyHP.bSuccess = !addrs.empty(); // 是否扫描到字节

  if (playerAndEnemyHP.bSuccess)
    playerAndEnemyHP.bSuccess = gc.callHook(addrs[0], 6, (BYTE*)&playerAndEnemyHP_h, &playerAndEnemyHP); // 是否挂钩成功 addrs[0] == "sekiro.exe"+BBF3BE

  while (!GetAsyncKeyState(VK_END))
  {
    if (GetAsyncKeyState(VK_F3) & 1)
      playerAndEnemyHP.toggle();

    Sleep(10);
  }

  gc.closeConsole(f);
  FreeLibraryAndExitThread(hModule, 0);
  return 0;
}
```


# SetNop Exanmpe

## AAScript
```
[ENABLE]
"Tutorial-x86_64.exe"+2B08C:
  db 90 90 90 90 90 90

[DISABLE]
"Tutorial-x86_64.exe"+2B08C:
  db 29 83 F0 07 00 00

{
// ---------- INJECTING HERE ----------
"Tutorial-x86_64.exe"+2B08C: 29 83 F0 07 00 00              -  sub [rbx+000007F0],eax
// ---------- DONE INJECTING  ----------
}
```

## c++
```c++
#include "pch.h"
#include <iostream>
#include "GameCheat.h"

using namespace std;

int WINAPI Mythread(HMODULE hModule)
{

  GameCheat::GC gc{ "Tutorial-x86_64.exe" };
  FILE* f;
  gc.openConsole(&f);
  
  BYTE* addr = (BYTE*)gc.mi.lpBaseOfDll + 0x2B08C;

  GameCheat::SetNop setNop;
  setNop.bSuccess = gc.setNop(addr, 6, &setNop); // OR: gc.setNopRVA(0x2B08C, 6, &setNop);

  while (!GetAsyncKeyState(VK_END))
  {
    if (GetAsyncKeyState(VK_F3) & 1)
      setNop.toggle();

    Sleep(10);
  }

  gc.closeConsole(f);
  FreeLibraryAndExitThread(hModule, 0);
  return 0;
}
```