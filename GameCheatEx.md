## ʵ����
```cpp
#include <iostream>
#include <GameCheatEx.h>

int main()
{
    GameCheatEx::GC gc{ "Tutorial-i386.exe" };
}
```

===���Ŀ�������x86/x64��ô��ĳ���ҲҪ����Ϊx86/x64===

����ʹ��pid������
```
DWORD pid = 1992;
GameCheatEx::GC gc{ pid };
printf("%s\n", gc.gameName.c_str());
```

## ����һ������̨

����Ex��ûʲô�ã�ͨ����dll��ʹ��

```cpp
gc.openConsole();
while (!GetAsyncKeyState(VK_END))
{
	printf("1");
	Sleep(1000);
}
gc.closeConsole();
```

## ��ȡĿ����̺�����ַ
```cpp
uintptr_t pMessageBoxA = GameCheatEx::GC::GetProcAddressEx(gc.hProcess, "user32.dll", "MessageBoxA");
printf("add: %p\n", addr);
```

[���ִ��Ŀ�꺯��?](https://www.cnblogs.com/ajanuw/p/13638106.html)


## ��ȡ���غ�����ַ
```cpp
void* pMessageBoxA = (void*)GetProcAddress( LoadLibraryA("user32.dll"), "MessageBoxA");
printf("%p\n", pMessageBoxA);

// or
printf("%p\n", &MessageBoxA);
```

[�����Ŀ�����ִ�б��غ���?](https://www.cnblogs.com/ajanuw/p/13638092.html)