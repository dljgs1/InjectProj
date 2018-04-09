#pragma once  
#include <Windows.h>  
#include <stdlib.h>  
#include <tlhelp32.h>  
#include <Psapi.h>  
#include <string>  

using std::string;
using std::wstring;

#pragma comment (lib,"Psapi.lib")  

#pragma warning(disable:4996)  

class CInjection
{
private:
	bool AdjustProcessTokenPrivilege();//Ã·»®

public:
	bool InjectionExeAndShowMessage(const wstring &wsProcessName);
};

DWORD GetProcessIdByName(char* lpName);