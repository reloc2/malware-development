@ECHO OFF
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tc CaFeBiBa.c /link /OUT:CaFeBiBa.exe /SUBSYSTEM:CONSOLE
cl.exe /nologo /c /Od /MT /W0 /GS- /Tc test.c

move /y test.obj test.o
dumpbin /disasm test.o > test.disasm

del *.obj
