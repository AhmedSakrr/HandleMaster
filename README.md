# HandleMaster

Vulnerable kernel drivers aren't a new thing. They allow regular uses to perform tasks that should be impossible from ring3. More specifically, the [CPU-Z](http://www.cpuid.com/softwares/cpu-z.html) driver allows users to read and write directly to physical memory.

HandleMaster exploits that to perform some [DKOM](https://en.wikipedia.org/wiki/Direct_kernel_object_manipulation) and change granted access rights for handles.

The idea is that you can open a handle with low access and then elevate its access rights later on when you want to use it.

This bypasses some Anti-Cheats that use ObRegisterCallbacks to strip access rights from handles at creation time *cough* BattleEye *cough*

### Currently only Win7 SP1 is supported!

I will add support for other versions later on. If you want to do it yourself here's what you need to find.

1. HANDLE_TABLE_ENTRY structure;
2. HANDLE_TABLE structure;
3. ExpLookupHandleTableEntry;
4. The DirectoryTableBase.
4. Some kernel offsets (_KPROCESS::DirectoryTableBase, _EPROCESS::UniqueProcessId, _EPROCESS::ActiveProcessLinks, _EPROCESS::ObjectTable)

Numers 1, 2 and 4 can be easily found with LiveKd (which you can download [from here](https://technet.microsoft.com/en-us/sysinternals/livekd.aspx)) and the Windows Debugging Tools.




