#include "inject.h"  
/*

ʵ�黷����64λ windows7 
����������VS2013
�ļ�Ҫ����ѵ�������򣨸���Ϊ3.exe����makeDLL.dll�ŵ�C�̸�Ŀ¼��
���ʱ�䣺 2018.4.9

�������Ǹ������¼����ο��ۺ��޸ĵģ�DLL���򹤳�ʡ�ԣ�����Ҫ��������֮���������

- ע��explore.exe��ע���û��Ӧ��: https://blog.csdn.net/panpanxj/article/details/3870954
- Զ���߳�ע�루�Ƚ���ϸ�Ĵ���ע�벿��û���� ǰ����һ���ģ��� https://blog.csdn.net/heluan123132/article/details/46412355
- ��ע���û��Ӧ���� https://blog.csdn.net/microzone/article/details/9773481
- �ֶ�����PID��ע�룺 https://blog.csdn.net/u013565525/article/details/27585387
- VS2013�´���DLL�� https://blog.csdn.net/lzh2912/article/details/68946494
- ���鳤�����Ǹ��������Դ �Ҳ���explorer.exe �޸�����PID�ķ�������ע��ɹ� ����ִ���߳�ʧ�ܣ��� https://blog.csdn.net/u013761036/article/details/52205171
- ע��ʧ��ԭ��windowsΪ64λ���� https://blog.csdn.net/ly_chg/article/details/55805129
- VS2013����64λDLL��ע���ļ��У�: https://blog.csdn.net/woainishifu/article/details/54017550

��ʹ�õ�DLL��Ҫ������룺
	MessageBox(NULL, TEXT("���Ǳ�ע���DLL������ִ�е��������(C:\\3.exe)����ر�ɱ�������ʾ"), TEXT("����"), MB_OK);
	ShellExecuteA(NULL, "open", "C:\\3.exe", NULL, NULL, SW_SHOWNORMAL);
	MessageBox(NULL, TEXT("ִ�����"), TEXT("����"), MB_OK);

	
*/


int main()
{
	CInjection *pciTest = new CInjection();
	pciTest->InjectionExeAndShowMessage(L"explorer.exe"); //explorer.exe  
	delete pciTest;
	return 0;
}