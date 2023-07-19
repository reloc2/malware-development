@ECHO OFF

cl.exe /nologo /W0 hookem.cpp /MT /link /DLL detours\lib.X64\detours.lib /OUT:hookem.dll

del *.obj *.lib *.exp