/*

 Red Team Operator course code template
 Guard pages
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>

//print CreateThread parameters
HANDLE prn(LPSECURITY_ATTRIBUTES rcx, SIZE_T rdx, LPTHREAD_START_ROUTINE r8, LPVOID r9, DWORD stck1, LPDWORD stck2) {
	printf("PRN():\n");
	printf("RCX = %#llx\n", rcx);
	printf("RDX = %#llx\n", rdx);
	printf("R8 = %#llx\n", r8);
	printf("R9 = %#llx\n", r9);
	printf("S1 = %#llx\n", stck1);
	printf("S2 = %#llx\n", stck2);
	getchar();
	
	return NULL;
}

LONG WINAPI handler(EXCEPTION_POINTERS * ExceptionInfo) {

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {

		if (ExceptionInfo->ContextRecord->Rip == (DWORD64) &CreateThread) {
			printf("[!] Exception (%#llx)! Params:\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
			printf("(1): %#llx | ", ExceptionInfo->ContextRecord->Rcx);
			printf("(2): %#llx | ", ExceptionInfo->ContextRecord->Rdx);
			printf("(3): %#llx | ", ExceptionInfo->ContextRecord->R8);
			printf("(4): %#llx | ", ExceptionInfo->ContextRecord->R9);
			printf("RSP = %#llx\n", ExceptionInfo->ContextRecord->Rsp);
			getchar();
			//ExceptionInfo->ContextRecord->Rip = (DWORD64) &prn;
		}
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {

	DWORD old = 0;
	
	// register exception handler as first one
	AddVectoredExceptionHandler(1, &handler);

	// set the PAGE_GUARD on CreateThread() function
	VirtualProtect(&CreateThread, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &old);
	printf("CreateThread addr = %#p\n", &CreateThread);
	
	// call "hooked" function
	DWORD param = 5000;
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE) &Sleep, &param, 0, 0);
	WaitForSingleObject(hThread, param);

	printf("YAY!\n");
	
	return 0;
}
