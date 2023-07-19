@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc *.c /link /OUT:implant.exe /SUBSYSTEM:CONSOLE
del *.obj
