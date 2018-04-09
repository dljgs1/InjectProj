#include "inject.h"  

// from: http://blog.csdn.net/u013761036/article/details/52205171


//64位下的GetProcAddress from: https://blog.csdn.net/yuzehome/article/details/53208462
ULONG_PTR MyGetProcAddress(
	HMODULE hModule,    // handle to DLL module    
	LPCSTR lpProcName   // function name    
	)
{
	int i = 0;
	char *pRet = NULL;
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

	pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pImageNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)hModule + pImageDosHeader->e_lfanew);
	pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hModule + pImageNtHeader->OptionalHeader.DataDirectory
		[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD dwExportRVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD dwExportSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	DWORD *pAddressOfFunction = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (ULONG_PTR)hModule);
	DWORD *pAddressOfNames = (DWORD*)(pImageExportDirectory->AddressOfNames + (ULONG_PTR)hModule);
	DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
	DWORD dwBase = (DWORD)(pImageExportDirectory->Base);

	WORD *pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (ULONG_PTR)hModule);

	//这个是查一下是按照什么方式（函数名称or函数序号）来查函数地址的    
	DWORD dwName = (DWORD)lpProcName;
	if ((dwName & 0xFFFF0000) == 0)
	{
		goto xuhao;
	}

	for (i = 0; i<(int)dwNumberOfNames; i++)
	{
		char *strFunction = (char *)(pAddressOfNames[i] + (ULONG_PTR)hModule);
		if (strcmp(strFunction, (char *)lpProcName) == 0)
		{
			pRet = (char *)(pAddressOfFunction[pAddressOfNameOrdinals[i]] + (ULONG_PTR)hModule);
			goto _exit11;
		}
	}
	//这个是通过以序号的方式来查函数地址的    
xuhao:
	if (dwName < dwBase || dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1)
	{
		return 0;
	}
	pRet = (char *)(pAddressOfFunction[dwName - dwBase] + (ULONG_PTR)hModule);
_exit11:
	//判断得到的地址有没有越界    
	if ((ULONG_PTR)pRet<dwExportRVA + (ULONG_PTR)hModule || (ULONG_PTR)pRet > dwExportRVA + (ULONG_PTR)hModule + dwExportSize)
	{
		return (ULONG_PTR)pRet;
	}
	char pTempDll[100] = { 0 };
	char pTempFuction[100] = { 0 };
	lstrcpyA(pTempDll, pRet);
	char *p = strchr(pTempDll, '.');
	if (!p)
	{
		return (ULONG_PTR)pRet;
	}
	*p = 0;
	lstrcpyA(pTempFuction, p + 1);
	lstrcatA(pTempDll, ".dll");
	HMODULE h = LoadLibraryA(pTempDll);
	if (h == NULL)
	{
		return (ULONG_PTR)pRet;
	}
	return MyGetProcAddress(h, pTempFuction);
}


DWORD G_GetProcessIdByName(WCHAR* lpName)
{
	//根据进程名获取进程ID,失败时返回0(System Idle Process) 
	DWORD dwProcessId;
	HANDLE hSnapshot;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE){
		PROCESSENTRY32 ppe;
		ppe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &ppe)){
			if (wcscmp(lpName, ppe.szExeFile) == 0){
				dwProcessId = ppe.th32ProcessID;
				CloseHandle(hSnapshot);
				return dwProcessId;
			}
			while (Process32Next(hSnapshot, &ppe)){//wcscmp
				if (wcscmp(lpName, ppe.szExeFile) == 0){
					dwProcessId = ppe.th32ProcessID;
					CloseHandle(hSnapshot);
					return dwProcessId;
				}
			}
		}
		CloseHandle(hSnapshot);
	}
	return 0;
}

typedef struct _REMOTE_PARAMETER
{
	CHAR cTitle[64];//传入的程序路径参数 变量名懒得改了
	CHAR cBody[64];
	//DWORD dwMessAgeBoxShowAddress;//64位下要用64位比特串 DWORD（32bit）是不能用的！
	ULONG_PTR dwMessAgeBoxShowAddress;
}RemotePara, *PRemotePara;

bool CInjection::AdjustProcessTokenPrivilege()
{
	LUID luidTmp;
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) // 尝试获取具有申请新的access token的权限的进程access token 
		return false;


	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp))  // 获取代表程序的sedebug权限的局部变量
	{
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luidTmp;  // 目标权限
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  // enable权限

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))  // 安装tkp修改权限
	{
		CloseHandle(hToken);
		return FALSE;
	}
	return true;
}

//注入的线程函数 只需要执行一次
//经过测试直接在这个线程执行 ShellExecuteA 会导致资源管理器崩溃 因此修改方法为注入dll
static  DWORD __stdcall RemoteThread(PRemotePara myData){
	typedef HINSTANCE(WINAPI *_ShellExecuteA)(//库函数ShellExcute的指针 不好使
		_In_opt_ HWND    hwnd,
		_In_opt_ LPCSTR lpOperation,
		_In_     LPCSTR lpFile,
		_In_opt_ LPCSTR lpParameters,
		_In_opt_ LPCSTR lpDirectory,
		_In_     INT     nShowCmd
		);
	typedef HINSTANCE(WINAPI *_LoadLibraryA)(//LoadLibraryA 的指针
		_In_ LPCSTR lpLibFileName
		);
	_LoadLibraryA mLoad = (_LoadLibraryA)myData->dwMessAgeBoxShowAddress;
	mLoad(myData->cTitle);
	return 0;
}

bool CInjection::InjectionExeAndShowMessage(const wstring &wsProcessName)
{
	//1.提权  
	if (!AdjustProcessTokenPrivilege())
		return false;

	//2.获取pid
	DWORD dwProPID = 0;
	if ((dwProPID = G_GetProcessIdByName(L"explorer.exe")) == 0){
		printf("no process\n");
		system("pause");
		return false;
	}

	//3.打开进程  
	HANDLE hProcess = NULL;
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProPID)) == NULL)
		return false;

	//4.初始化参数数据  
	RemotePara rpData = { 0 };
	ZeroMemory(&rpData, sizeof(RemotePara));
	HINSTANCE hInst = NULL;
	//hInst = LoadLibrary(L"Shell32.dll");

	//HINSTANCE hstc = LoadLibrary(L"makeDll.dll");

	//hInst = LoadLibrary(L"User32.dll");
	hInst = LoadLibrary(L"Kernel32.dll");
	if (hInst == NULL) {
		printf("open dll error\n");
		system("pause");
		return false;
	}
	rpData.dwMessAgeBoxShowAddress = (DWORD)ShellExecuteA;
	rpData.dwMessAgeBoxShowAddress = MyGetProcAddress(hInst, (LPCSTR)("LoadLibraryA"));
	
	printf("%x\n", rpData.dwMessAgeBoxShowAddress);//获取该DLL中函数的地址

	if (rpData.dwMessAgeBoxShowAddress == 0){
		printf("find func error\n");
		system("pause");
		return false;
	}
	FreeLibrary(hInst);

	strcat(rpData.cTitle,"C:\\makeDll.dll");
	//这里要写DLL的绝对路径 需要先手动把DLL放到C盘下 其实也可以编程复制 没有写
	strcat(rpData.cBody, "no info");
	//RemoteThread(&rpData);  
	//system("pause");

	//5.在宿主进程里分配内存，用于存参数  
	PRemotePara pPara = NULL;
	pPara = (PRemotePara)VirtualAllocEx(hProcess, 0, sizeof(RemotePara), MEM_COMMIT, PAGE_READWRITE);
	if (pPara == NULL){
		printf("VirtualAllocEx error\n");
		system("pause");
		return false;
	}

	//6.把参数写入宿主进程里，注意结构体的命名（_REMOTE_PARAMETER）  
	if (!WriteProcessMemory(hProcess, pPara, &rpData, sizeof(RemotePara), 0)){
		printf("WriteProcessMemory error\n");
		system("pause");
		return false;
	}

	//7.在宿主进程里分配内存，这里内存分配了2048个字节  
	void *pRemoteThr = VirtualAllocEx(hProcess, NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteThr == NULL){
		printf("VirtualAllocEx error\n");
		system("pause");
		return false;
	}

	//8.把进程函数写入分配的内存里  
	if (!WriteProcessMemory(hProcess, pRemoteThr, &RemoteThread, 2048, 0)){
		printf("WriteProcessMemory error\n");
		system("pause");
		return false;
	}

	//9.启动注入宿主进程的进程  
	DWORD dwThreadId = 0;
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (DWORD(WINAPI *)(LPVOID))pRemoteThr, pPara, 0, &dwThreadId);
	if (!hThread){
		printf("CreateRemoteThread error:");
		printf("%d\n", GetLastError());
		system("pause");
		return false;
	}

	//10.等待线程结束，然后清理内存    

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pPara, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, pRemoteThr, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	printf("over");
	return true;
}