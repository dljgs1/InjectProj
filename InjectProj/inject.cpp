#include "inject.h"  

// from: http://blog.csdn.net/u013761036/article/details/52205171


//64λ�µ�GetProcAddress from: https://blog.csdn.net/yuzehome/article/details/53208462
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

	//����ǲ�һ���ǰ���ʲô��ʽ����������or������ţ����麯����ַ��    
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
	//�����ͨ������ŵķ�ʽ���麯����ַ��    
xuhao:
	if (dwName < dwBase || dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1)
	{
		return 0;
	}
	pRet = (char *)(pAddressOfFunction[dwName - dwBase] + (ULONG_PTR)hModule);
_exit11:
	//�жϵõ��ĵ�ַ��û��Խ��    
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
	//���ݽ�������ȡ����ID,ʧ��ʱ����0(System Idle Process) 
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
	CHAR cTitle[64];//����ĳ���·������ ���������ø���
	CHAR cBody[64];
	//DWORD dwMessAgeBoxShowAddress;//64λ��Ҫ��64λ���ش� DWORD��32bit���ǲ����õģ�
	ULONG_PTR dwMessAgeBoxShowAddress;
}RemotePara, *PRemotePara;

bool CInjection::AdjustProcessTokenPrivilege()
{
	LUID luidTmp;
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) // ���Ի�ȡ���������µ�access token��Ȩ�޵Ľ���access token 
		return false;


	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidTmp))  // ��ȡ��������sedebugȨ�޵ľֲ�����
	{
		CloseHandle(hToken);
		return FALSE;
	}
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luidTmp;  // Ŀ��Ȩ��
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  // enableȨ��

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL))  // ��װtkp�޸�Ȩ��
	{
		CloseHandle(hToken);
		return FALSE;
	}
	return true;
}

//ע����̺߳��� ֻ��Ҫִ��һ��
//��������ֱ��������߳�ִ�� ShellExecuteA �ᵼ����Դ���������� ����޸ķ���Ϊע��dll
static  DWORD __stdcall RemoteThread(PRemotePara myData){
	typedef HINSTANCE(WINAPI *_ShellExecuteA)(//�⺯��ShellExcute��ָ�� ����ʹ
		_In_opt_ HWND    hwnd,
		_In_opt_ LPCSTR lpOperation,
		_In_     LPCSTR lpFile,
		_In_opt_ LPCSTR lpParameters,
		_In_opt_ LPCSTR lpDirectory,
		_In_     INT     nShowCmd
		);
	typedef HINSTANCE(WINAPI *_LoadLibraryA)(//LoadLibraryA ��ָ��
		_In_ LPCSTR lpLibFileName
		);
	_LoadLibraryA mLoad = (_LoadLibraryA)myData->dwMessAgeBoxShowAddress;
	mLoad(myData->cTitle);
	return 0;
}

bool CInjection::InjectionExeAndShowMessage(const wstring &wsProcessName)
{
	//1.��Ȩ  
	if (!AdjustProcessTokenPrivilege())
		return false;

	//2.��ȡpid
	DWORD dwProPID = 0;
	if ((dwProPID = G_GetProcessIdByName(L"explorer.exe")) == 0){
		printf("no process\n");
		system("pause");
		return false;
	}

	//3.�򿪽���  
	HANDLE hProcess = NULL;
	if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProPID)) == NULL)
		return false;

	//4.��ʼ����������  
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
	
	printf("%x\n", rpData.dwMessAgeBoxShowAddress);//��ȡ��DLL�к����ĵ�ַ

	if (rpData.dwMessAgeBoxShowAddress == 0){
		printf("find func error\n");
		system("pause");
		return false;
	}
	FreeLibrary(hInst);

	strcat(rpData.cTitle,"C:\\makeDll.dll");
	//����ҪдDLL�ľ���·�� ��Ҫ���ֶ���DLL�ŵ�C���� ��ʵҲ���Ա�̸��� û��д
	strcat(rpData.cBody, "no info");
	//RemoteThread(&rpData);  
	//system("pause");

	//5.����������������ڴ棬���ڴ����  
	PRemotePara pPara = NULL;
	pPara = (PRemotePara)VirtualAllocEx(hProcess, 0, sizeof(RemotePara), MEM_COMMIT, PAGE_READWRITE);
	if (pPara == NULL){
		printf("VirtualAllocEx error\n");
		system("pause");
		return false;
	}

	//6.�Ѳ���д�����������ע��ṹ���������_REMOTE_PARAMETER��  
	if (!WriteProcessMemory(hProcess, pPara, &rpData, sizeof(RemotePara), 0)){
		printf("WriteProcessMemory error\n");
		system("pause");
		return false;
	}

	//7.����������������ڴ棬�����ڴ������2048���ֽ�  
	void *pRemoteThr = VirtualAllocEx(hProcess, NULL, 2048, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pRemoteThr == NULL){
		printf("VirtualAllocEx error\n");
		system("pause");
		return false;
	}

	//8.�ѽ��̺���д�������ڴ���  
	if (!WriteProcessMemory(hProcess, pRemoteThr, &RemoteThread, 2048, 0)){
		printf("WriteProcessMemory error\n");
		system("pause");
		return false;
	}

	//9.����ע���������̵Ľ���  
	DWORD dwThreadId = 0;
	HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (DWORD(WINAPI *)(LPVOID))pRemoteThr, pPara, 0, &dwThreadId);
	if (!hThread){
		printf("CreateRemoteThread error:");
		printf("%d\n", GetLastError());
		system("pause");
		return false;
	}

	//10.�ȴ��߳̽�����Ȼ�������ڴ�    

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pPara, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, pRemoteThr, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	printf("over");
	return true;
}