@ECHO OFF

cl.exe /nologo /O1 /MT /W0 /GS- /DNDEBUG /Tc implant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE
del *.obj
