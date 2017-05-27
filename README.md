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

Numers 1, 2 and 4 can be easily found with LiveKd (which you can download [from here](https://technet.microsoft.com/en-us/sysinternals/livekd.aspx)) and the Windows Debugging Tools.

### HANDLE_TABLE_ENTRY

After you've downloaded LiveKd and extracted it to where windbg.exe and kd.exe are located (usually "C:\Program Files (x86)\Windows Kits\<version>\Debuggers\x64"), run LiveKd through cmd.exe and then enter the following:

`dt nt!_HANDLE_TABLE_ENTRY`

Output should look as follows:

![img1](http://i.imgur.com/oRs1E9y.png)

Then you just need to convert that to a C structure. *cough* https://github.com/MarkHC/windbg_to_c *cough*

### HANDLE_TABLE

Can be obtained in the same way as HANDLE_TABLE_ENTRY, just alter the LiveKd command to `dt nt!_HANDLE_TABLE`

### ExpLookupHandleTableEntry

Open up C:\Windows\System32\ntoskrnl.exe on IDA64. Make sure to press 'Yes' when it asks you to download the PDB:

![img2](http://i.imgur.com/AVHZvJl.png)

Now press G and enter ExpLookupHandleTableEntry. Press F5 to go to Disassembly view. Now you can just copy that into the project.

Just make sure to change any dereferences into calls to `read<ULONGLONG>`.

### DirectoryTableBase

Back to LiveKd, type `!process 0 0 System` into LiveKd's command line.

This is what you want:

![img3](http://i.imgur.com/Y0nd5Ed.png)





