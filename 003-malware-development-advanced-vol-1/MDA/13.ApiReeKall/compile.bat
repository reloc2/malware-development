@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp %1 /link /OUT:implant.exe /SUBSYSTEM:CONSOLE 
del *.obj
