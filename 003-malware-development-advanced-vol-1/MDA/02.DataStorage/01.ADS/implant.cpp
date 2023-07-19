/*

 Red Team Operator course code template
 Alternate Data Streams
 
 author: reenz0h (twitter: @SEKTOR7net)

*/
#include <windows.h>
#include <stdio.h>

int main(void) {
	char FSName[1024];
	WCHAR * target_stream = L"c:\\rto\\test.txt:ads";
	BYTE data[] = "SECRET SAUCE";
	char received[1024];
	DWORD bytesOut;
	WIN32_FIND_STREAM_DATA stream_data;

	// ADS works on NTFS only, so need to check it first
	GetVolumeInformation("C:\\", NULL, NULL, NULL, NULL, NULL, FSName, 1024);
	if (_stricmp(FSName, "NTFS") == 0) {
		//printf("[+] We're good!\n");
		HANDLE tFile = CreateFileW(target_stream,
									GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES,
									FILE_SHARE_READ,
									NULL,
									OPEN_ALWAYS,
									FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL,
									NULL);
		if (tFile == INVALID_HANDLE_VALUE) {
			printf("[!] Could not open file: %s\r\n", target_stream);
			return -1;
		}		
		
		// write data into ADS
		WriteFile(tFile, data, sizeof(data), &bytesOut, NULL);

		// list the stream
		HANDLE hFind = FindFirstStreamW(target_stream, FindStreamInfoStandard, &stream_data, 0);
		if (hFind == INVALID_HANDLE_VALUE) {
			printf("[!] Could not find any streams!\n");
			return -1;				
		}

		printf("ADS inside:\n");
		while (TRUE) {
			printf("(%u)\t%S\n", stream_data.StreamSize, stream_data.cStreamName);
			if (!FindNextStreamW(hFind, &stream_data))
				break;
		}
		FindClose(hFind);
		
		// read the data from
		SetFilePointer( tFile, NULL, NULL, FILE_BEGIN );
		ReadFile(tFile, received, sizeof(received), &bytesOut, NULL);
		
		// and print it
		printf("[+] Data from ADS: (%d) %s\n", bytesOut, received);
		// check "dir /r c:\rto" and "more < c:\rto\..."

		CloseHandle(tFile);
	}
	else {
		printf("[!] Nope! Not this time, buddy!\n");
	}
	
	return 0;
}
