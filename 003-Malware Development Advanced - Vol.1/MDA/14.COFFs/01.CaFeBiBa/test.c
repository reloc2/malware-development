/*

 Red Team Operator course code template
 Example COFF module template
 
 author: reenz0h (twitter: @SEKTOR7net)
 credits: COFFLoader (by Kevin Haubris/@kev169)

*/

#include <windows.h>
#include <stdio.h>

// DECLSPEC_IMPORT <return_type> WINAPI <LIB>$<FUNCNAME>(param1, param2, ...);
// ex. DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD th32ProcessID);

// WINBASEAPI <return_type> __cdecl MSVCRT$<FUNCNAME>(param1, param2, ...);
// ex. WINBASEAPI int __cdecl MSVCRT$getchar(void);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);

// global variable declaration
int tval = 0;

int testing(void){
	char funcname[] = "ZwAddBootEntry";
	
	void * addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), funcname);
    MSVCRT$printf("Function %s() @ %p\n", funcname, addr);	
    return 0;
}


int go(void) {
	int inc = 2;

	MSVCRT$printf("Test value 1: %d\n", tval);
    tval += inc + 1;
    MSVCRT$printf("Test value 2: %d\n", tval);
	testing();

	return 0;
}
