实验环境：64位 windows7 
开发环境：VS2013
文件要求：请把第三题程序（更名为3.exe）和makeDLL.dll放到C盘根目录下
完成时间： 2018.4.9
存在问题：DLL注入后没有释放，需要手动关闭explorer.exe以关闭DLL，否则只能测试一遍

本程序是根据以下几个参考综合修改的（DLL程序工程省略，其主要三行内容之后给出）：

 - 注入explore.exe（注入后没反应）: https://blog.csdn.net/panpanxj/article/details/3870954
 - 远程线程注入（比较详细的代码注入部分没尝试 前面是一样的）： https://blog.csdn.net/heluan123132/article/details/46412355
 - （注入后没反应）： https://blog.csdn.net/microzone/article/details/9773481
 - 手动搜索PID后注入： https://blog.csdn.net/u013565525/article/details/27585387
 - VS2013下创建DLL： https://blog.csdn.net/lzh2912/article/details/68946494
 - （组长发的那个程序的来源 找不到explorer.exe 修改了找PID的方法可以注入成功 但是执行线程失败）： https://blog.csdn.net/u013761036/article/details/52205171
 - 注入失败原因（windows为64位）： https://blog.csdn.net/ly_chg/article/details/55805129
 - VS2013配置64位DLL（注意文件夹）: https://blog.csdn.net/woainishifu/article/details/54017550
 
所使用的DLL主要程序代码：

	MessageBox(NULL, TEXT("我是被注入的DLL，即将执行第三题程序(C:\\3.exe)，请关闭杀毒软件提示"), TEXT("提醒"), MB_OK);

	ShellExecuteA(NULL, "open", "C:\\3.exe", NULL, NULL, SW_SHOWNORMAL);

	MessageBox(NULL, TEXT("执行完毕"), TEXT("提醒"), MB_OK);
	