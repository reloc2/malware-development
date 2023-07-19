@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp implant.cpp /EHa /link /OUT:implant.exe /SUBSYSTEM:CONSOLE
del *.obj
