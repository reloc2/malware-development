/*

 Red Team Operator course code template
 Hardware assisted hooks
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>

int SetHWBP(HANDLE thrd, DWORD64 addr, BOOL setBP) {
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	GetThreadContext(thrd, &ctx);
	
	if (setBP == TRUE) {
		ctx.Dr0 = addr;
		ctx.Dr7 |= (1 << 0);  		// Local DR0 breakpoint
		ctx.Dr7 &= ~(1 << 16);		// break on execution
		ctx.Dr7 &= ~(1 << 17);

	}
	else if (setBP == FALSE) {
		ctx.Dr0 = NULL;
		ctx.Dr7 &= ~(1 << 0);
	}

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;	
	SetThreadContext(thrd, &ctx);

	return 0;
}


LONG WINAPI handler(EXCEPTION_POINTERS * ExceptionInfo) {

	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
		if (ExceptionInfo->ContextRecord->Rip == (DWORD64) &Sleep) {
			printf("[!] Exception (%#llx)! Params:\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
			printf("(1): %#d | ", ExceptionInfo->ContextRecord->Rcx);
			printf("(2): %#llx | ", ExceptionInfo->ContextRecord->Rdx);
			printf("(3): %#llx | ", ExceptionInfo->ContextRecord->R8);
			printf("(4): %#llx | ", ExceptionInfo->ContextRecord->R9);
			printf("RSP = %#llx\n", ExceptionInfo->ContextRecord->Rsp);
			
			printf("Sleep called!\n");
			
			// continue the execution
			ExceptionInfo->ContextRecord->EFlags |= (1 << 16);			// set RF (Resume Flag) to continue execution
			//ExceptionInfo->ContextRecord->Rip++;						// or skip the breakpoint via instruction pointer
		}		
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

int main(void) {

	// register exception handler as first one
	AddVectoredExceptionHandler(1, &handler);
	
	// set the breakpoint on Sleep()
	SetHWBP(GetCurrentThread(), (DWORD64) &Sleep, TRUE);
	
	printf("[+] HPBP set! (%#x)\n", GetLastError());
	printf("Check DRs\n"); getchar();
	
	// generate exception
	Sleep(1000);
	
	printf("Awaiting...");
	
	// remove the breakpoint
	SetHWBP(GetCurrentThread(), (DWORD64) &Sleep, FALSE);
	getchar();
	
	Sleep(4000);
	printf("EOF");

	return 0;
	
}
