## 实例化
```cpp
#include <iostream>
#include <GameCheatEx.h>

int main()
{
    GameCheatEx::GC gc{ "Tutorial-i386.exe" };
}
```

===如果目标进程是x86/x64那么你的程序也要编译为x86/x64===

或者使用pid的重载
```
DWORD pid = 1992;
GameCheatEx::GC gc{ pid };
printf("%s\n", gc.gameName.c_str());
```

## 开启一个控制台

这在Ex中没什么用，通常在dll中使用

```cpp
gc.openConsole();
while (!GetAsyncKeyState(VK_END))
{
	printf("1");
	Sleep(1000);
}
gc.closeConsole();
```

## 获取目标进程函数地址
```cpp
uintptr_t pMessageBoxA = GameCheatEx::GC::GetProcAddressEx(gc.hProcess, "user32.dll", "MessageBoxA");
printf("add: %p\n", addr);
```

[如何执行目标函数?](https://www.cnblogs.com/ajanuw/p/13638106.html)


## 获取本地函数地址
```cpp
void* pMessageBoxA = (void*)GetProcAddress( LoadLibraryA("user32.dll"), "MessageBoxA");
printf("%p\n", pMessageBoxA);

// or
printf("%p\n", &MessageBoxA);
```

[如何让目标进程执行本地函数?](https://www.cnblogs.com/ajanuw/p/13638092.html)