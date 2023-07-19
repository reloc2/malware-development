/*

 Red Team Operator course code template
 Process enumeration with Windows Terminal Services
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>
#include <wtsapi32.h>

#pragma comment(lib, "Wtsapi32.lib")

int FindTarget(const char * procname) {

	int pid = 0;
	WTS_PROCESS_INFOA * proc_info;
	DWORD pi_count = 0;
	
	if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &pi_count)) 
		return 0;
	
	for (int i = 0 ; i < pi_count ; i++ ) {
		if (lstrcmpiA(procname, proc_info[i].pProcessName) == 0) {
			pid = proc_info[i].ProcessId;
			break;
		}
	}
	
	return pid;
}


int main(void) {

	int pid = FindTarget("notepad.exe");
	printf("Notepad %s%d)\n", pid > 0 ? "found at PID: (" : "NOT FOUND (", pid);

	return 0;
}
