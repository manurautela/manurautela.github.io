---
layout: posts
title:  "virtual to physical address using windbg"
date:   2021-10-11 10:00:00 +0530
categories: memory, windows, windbg, pte, pfn, mmpte, pagetable
---

In this post let's explore the general mechanism of how we go for virtual to
physical memory. Trying to understand what happens in between.

<br>
# Paging
___


The end goal is to fix up the page table so that when the application tries to
access the memory location, it can do so seamlessly as if nothing had happened.
The page table walking process is described for x86 briefly.

![paging x86](/assets/images/pagetable/page_table.jpg)


**Refer:**
AMD system programming manual paging section for x86


**virtual Address is composed of for x86**
>* index to page directory (PD)
>* index to page table (PT)
>* offset inside the page

**For the translation or page table walk part**
>* x86 CR3 register holds PFN of the page directory page
>* page directory entry contains pfn of the page table page
>* page table entry points to the pfn of data/code page
>* Also there are page attribute bits in PTE(lower 12-bits)


<br>
# Page Fault
___

A reference to an invalid page is called a page fault. The kernel trap handler
would dispatch fault to the memory manager's fault handler(via MmAccessFault)
to resolve.

A page fault would occur when the valid bit for the PTE is not set for the VA.
This would cause CPU to generate page fault exception (!idt 0xe).
Operating system's page fault exception handler would kickin (nt!KiTrap0E).
It would try to deal with the page fault based on the type of PTE (hard/soft).
Finally exception is dismissed and faulting instruction is tried again for
re-execution.


```
0: kd> !idt 0xe

Dumping IDT: 80b95400

49b0d91d0000000e:	82a972fc nt!KiTrap0E

```


[page states](https://docs.microsoft.com/en-us/windows/win32/memory/page-state)

[reserve and commit](https://docs.microsoft.com/en-us/windows/win32/memory/reserving-and-committing-memory)

[virttual to physical](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/converting-virtual-addresses-to-physical-addresses)

**This is really nice article in great detail**

[triple fault](https://www.triplefault.io/2017/08/exploring-windows-virtual-memory.html)


<br>
# Access violation
___

Accessing a page that isn’t committed (for example, reserved address space or
address space that isn’t allocated) --> Access violation exception.

Accessing a demand-zero page -> Add a zero-filled page to the relevant working set.

There are other scenarios but for this post these are relevant.

<br>
# Page Fault handling
___

Memory manager looks at the PTE corresponding to the faulting VA to and figures
out how the fault should be handled.

Software PTEs (PTE.Valid=0) should contain info needed by Mm to resolve a page
fault

Depending on the type of PTE in question there could be multiple paths in
MmAccessFault -> MiDispatchFault that ends up resolving the fault.


```
1: kd> x nt!mi*resolve*fault*
82ada10d          nt!MiResolveDemandZeroFault (_MiResolveDemandZeroFault@24)
82ae05cf          nt!MiResolveTransitionFault (_MiResolveTransitionFault@28)
82ae267b          nt!MiResolveMappedFileFault (_MiResolveMappedFileFault@32)
82b0bcc2          nt!MiResolvePageFileFault (_MiResolvePageFileFault@28)
82ad6e40          nt!MiResolveProtoPteFault (_MiResolveProtoPteFault@32)

```


<br>
# High level overview of demo application
___

[pagefault.cpp](https://gist.github.com/manurautela/711c7553a8be4ca4c81f99679620e8fd)

We have an application that reserves few pages of memory using VirtualAlloc(...)
Then tries to write to them a byte at a time. The app registers for exception handler
as well.

When trying to access reserved memory an access violation is generated and
MmAccessFault is invoked via trap dispatching mechanism. Which in turn invokes
the exception handler that the app registers. Because we accessed reserved
memory for writing which caues access violation.

Once the fault handler determines what is to be done next. It tries to search
and invoke the exception handler caused the access violation.

Within our exception handler we go ahead and mark the page as commited. And
continue our execution. This takes us back to the original code which ends up
calling MiResolveDemandZeroFault and Mm fixes up the PTE for valid translation
later on.

Then we re-execute the same faulting instruction and write to it without access
violation hopefully ;).

[exception dispatching mechanism](https://doar-e.github.io/blog/2013/10/12/having-a-look-at-the-windows-userkernel-exceptions-dispatcher/)


<br>
# Walkthrough windbg
___

**Trying to access(write) the reserved memory**

![AV Reserved Page](/assets/images/pagetable/reserved_page_av.jpg)

<br>

```cpp
    // Reserve pages in the virtual address space of the process.

    lpvBase = VirtualAlloc(
                     NULL,                 // System selects address
                     PAGELIMIT*dwPageSize, // Size of allocation
                     MEM_RESERVE,          // Allocate reserved pages
                     PAGE_NOACCESS);       // Protection = no access
    if (lpvBase == NULL )
        ErrorExit(TEXT("VirtualAlloc reserve failed."));

    lpPtr = lpNxtPage = (LPTSTR) lpvBase;

    // Use structured exception handling when accessing the pages.
    // If a page fault occurs, the exception filter is executed to
    // commit another page from the reserved block of pages.

    for (i=0; i < PAGELIMIT*dwPageSize; i++)
    {
        __try
        {
            // Write to memory.

            lpPtr[i] = 'a';
        }

        // If there's a page fault, commit another page and try again.

        __except ( PageFaultExceptionFilter( GetExceptionCode() ) )
        {

            // This code is executed only if the filter function
            // is unsuccessful in committing the next page.

            _tprintf (TEXT("Exiting process.\n"));

            ExitProcess( GetLastError() );

        }

    }

```
<br>



```
1: kd> bl
     0 e Disable Clear  01144c41     0001 (0001) pagefault!main+0xc1

1: kd> dt lpPtr
Local var @ 0x17fd48 Type char*
0x001f0000  "--- memory read error at address 0x001f0000 ---"

1: kd> !pte 0x001f0000
                    VA 001f0000
PDE at C0600000            PTE at C0000F80
contains 000000006A1A6867  contains 0000000000000000
pfn 6a1a6     ---DA--UWEV  not valid <--- This being a reserved page causes an access violation


1: kd> !process -1 0
PROCESS 86346318  SessionId: 1  Cid: 0880    Peb: 7ffd5000  ParentCid: 0e18
    DirBase: 7f2124c0  ObjectTable: 89cb2bf0  HandleCount:   7.
    Image: pagefault.exe

```

<br>
**Let's put a process specific breakpoint on nt!MmAccessFault**

___



```
1: kd> x nt!MmAccessFault
82aca315          nt!MmAccessFault (_MmAccessFault@16)

1: kd> bp /p 86346318 82aca315
1: kd> g
Breakpoint 3 hit
nt!MmAccessFault:
0008:82aca315 mov     edi,edi

# It's the same address for our reserved memory but still not commited
# this will invoke the exception handler registered because of the a/v

1: kd> r @cr2
cr2=001f0000

1: kd> !pte 001f0000
                    VA 001f0000
PDE at C0600000            PTE at C0000F80
contains 000000006A1A6867  contains 0000000000000000
pfn 6a1a6     ---DA--UWEV  not valid


```

<br>
**We put another breakpoint at the our PageFaultExceptionFilter function, where
we make the resreved memory as commited**

___


![Exception Handler](/assets/images/pagetable/exception_handler.jpg)

<br>


```
1: kd> g
Breakpoint 1 hit
pagefault!PageFaultExceptionFilter+0x42:
01144af2 push    4
1: kd> !pte 001f0000
                    VA 001f0000
PDE at C0600000            PTE at C0000F80
contains 000000006A1A6867  contains 0000000000000000
pfn 6a1a6     ---DA--UWEV  not valid


1: kd> kn
 # ChildEBP RetAddr
00 0017f77c 01144c66 pagefault!PageFaultExceptionFilter+0x42 [J:\dev\temp\cpp\pagefault.cpp @ 41]
01 0017f784 011480f2 pagefault!main+0xe6 [J:\dev\temp\cpp\pagefault.cpp @ 116]
02 0017f798 01146ec4 pagefault!_EH4_CallFilterFunc+0x12
03 0017f7d4 771b71b9 pagefault!_except_handler4+0xd4
04 0017f7f8 771b718b ntdll!ExecuteHandler2+0x26
05 0017f81c 7718f96f ntdll!ExecuteHandler+0x24
06 0017f8a8 771b7017 ntdll!RtlDispatchException+0x127
07 0017f8a8 01144c47 ntdll!KiUserExceptionDispatcher+0xf
08 0017fd70 01145243 pagefault!main+0xc7 [J:\dev\temp\cpp\pagefault.cpp @ 111]
09 0017fd90 01145097 pagefault!invoke_main+0x33
0a 0017fdec 01144f2d pagefault!__scrt_common_main_seh+0x157
0b 0017fdf4 011452c8 pagefault!__scrt_common_main+0xd
0c 0017fdfc 75613c45 pagefault!mainCRTStartup+0x8
0d 0017fe08 771d37f5 kernel32!BaseThreadInitThunk+0xe
0e 0017fe48 771d37c8 ntdll!__RtlUserThreadStart+0x70
0f 0017fe60 00000000 ntdll!_RtlUserThreadStart+0x1b

```

<br>
**At this point we will mark the reserved memory as commited, but Mm needs
to fix up the page table**

___


```
1: kd> g
Breakpoint 2 hit
pagefault!PageFaultExceptionFilter+0x60:
01144b10 cmp     dword ptr [ebp-4],0
1: kd> !pte 001f0000
                    VA 001f0000
PDE at C0600000            PTE at C0000F80
contains 000000006A1A6867  contains 0000000000000080
pfn 6a1a6     ---DA--UWEV  not valid
                            DemandZero
                            Protect: 4 - ReadWrite

```

<br>
**Notice the pte is still invalid because that is to be fixed by memory manager
When this address is now accessed for writing in the main function**

**Next put a breakpoint in nt!MiResolveDemandZeroFault**

___


```
1: kd> x nt!mm*demand*zero*
1: kd> x nt!MiResolveDemandZeroFault
82ada10d          nt!MiResolveDemandZeroFault (_MiResolveDemandZeroFault@24)
1: kd> bp /p 86346318   82ada10d
1: kd> g
Breakpoint 4 hit
nt!MiResolveDemandZeroFault:
0008:82ada10d mov     edi,edi
1: kd> kn
 # ChildEBP RetAddr
00 a12cfb90 82acc0d8 nt!MiResolveDemandZeroFault
01 a12cfc1c 82a7d3d8 nt!MmAccessFault+0x1dc1
02 a12cfc1c 01144c47 nt!KiTrap0E+0xdc
03 0017fd70 01145243 pagefault!main+0xc7 [J:\dev\temp\cpp\pagefault.cpp @ 111]
04 0017fd90 01145097 pagefault!invoke_main+0x33
05 0017fdec 01144f2d pagefault!__scrt_common_main_seh+0x157
06 0017fdf4 011452c8 pagefault!__scrt_common_main+0xd
07 0017fdfc 75613c45 pagefault!mainCRTStartup+0x8
08 0017fe08 771d37f5 kernel32!BaseThreadInitThunk+0xe
09 0017fe48 771d37c8 ntdll!__RtlUserThreadStart+0x70
0a 0017fe60 00000000 ntdll!_RtlUserThreadStart+0x1b

1: kd> .frame 0n3;dv /t /v
03 0017fd70 01145243 pagefault!main+0xc7 [J:\dev\temp\cpp\pagefault.cpp @ 111]
0017fd48          char * lpPtr = 0x001f0000 "--- memory read error at address 0x001f0000 ---"
0017fd40          int bSuccess = 0
0017fd54          unsigned long i = 0
0017fd50          void * lpvBase = 0x001f0000
0017fd1c          struct _SYSTEM_INFO sSysInfo = struct _SYSTEM_INFO

1: kd> !pte 0x001f0000
                    VA 001f0000
PDE at C0600000            PTE at C0000F80
contains 000000006A1A6867  contains 0000000000000080
pfn 6a1a6     ---DA--UWEV  not valid
                            DemandZero
                            Protect: 4 - ReadWrite

```

<br>
**MiResolveDemandZeroFault would resolve fault and fix up page table entry.
Then the faulting instruction is re-executed**

___


```
# Now We Are Able to Write to Previously Reserved Address Which Is Not Only
# Commited but Also Has a Valid Pte.
1: kd> g
Breakpoint 0 hit
pagefault!main+0xc1:
01144c41 mov     edx,dword ptr [ebp-28h]
1: kd> dt lpPtr
Local var @ 0x17fd48 Type char*
0x001f0000  "a"

# Now the pte has been fixed up and is valid
1: kd> !pte 0x001f0000
                    VA 001f0000
PDE at C0600000            PTE at C0000F80
contains 000000006A1A6867  contains 8000000069FC8867
pfn 6a1a6     ---DA--UWEV  pfn 69fc8     ---DA--UW-V


1: kd> !pte 0x001f0000
                    VA 001f0000
PDE at C0600000            PTE at C0000F80
contains 000000006A1A6867  contains 8000000069FC8867
pfn 6a1a6     ---DA--UWEV  pfn 69fc8     ---DA--UW-V

1: kd> !pfn 69fc8
    PFN 00069FC8 at address 84B979E0
    flink       00000157  blink / share count 00000001  pteaddress C0000F80
    reference count 0001   Cached     color 0   Priority 5
    restore pte 00000080  containing page 06A1A6  Active     M
    Modified

# Dumping page data using PFN in physical memory
1: kd> !db 69fc8000
#69fc8000 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa
#69fc8010 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa
#69fc8020 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa
#69fc8030 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa
#69fc8040 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa
#69fc8050 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa
#69fc8060 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa
#69fc8070 61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61 aaaaaaaaaaaaaaaa

# Validate the same using virtual address
1: kd> db 0x001f0000
001f0000  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f0010  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f0020  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f0030  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f0040  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f0050  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f0060  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f0070  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa


# MMPTE structure for PTE
1: kd> dt nt!_MMPTE C0000F80
   +0x000 u                : <unnamed-tag>
1: kd> dx -id 0,0,86346318 -r1 (*((ntkrpamp!_MMPTE *)0xc0000f80)).u
(*((ntkrpamp!_MMPTE *)0xc0000f80)).u [Type: <unnamed-tag>]
    [+0x000] Long             : 0x8000000069fc8867 [Type: unsigned __int64]
    [+0x000] VolatileLong     : 0x8000000069fc8867 [Type: unsigned __int64]
    [+0x000] HighLow          [Type: _MMPTE_HIGHLOW]
    [+0x000] Flush            [Type: _HARDWARE_PTE]
    [+0x000] Hard             [Type: _MMPTE_HARDWARE]
    [+0x000] Proto            [Type: _MMPTE_PROTOTYPE]
    [+0x000] Soft             [Type: _MMPTE_SOFTWARE]
    [+0x000] TimeStamp        [Type: _MMPTE_TIMESTAMP]
    [+0x000] Trans            [Type: _MMPTE_TRANSITION]
    [+0x000] Subsect          [Type: _MMPTE_SUBSECTION]
    [+0x000] List             [Type: _MMPTE_LIST]
1: kd> dx -id 0,0,86346318 -r1 (*((ntkrpamp!_MMPTE_SOFTWARE *)0xc0000f80))
(*((ntkrpamp!_MMPTE_SOFTWARE *)0xc0000f80))                 [Type: _MMPTE_SOFTWARE]
    [+0x000 ( 0: 0)] Valid            : 0x1 [Type: unsigned __int64]
    [+0x000 ( 4: 1)] PageFileLow      : 0x3 [Type: unsigned __int64]
    [+0x000 ( 9: 5)] Protection       : 0x3 [Type: unsigned __int64]
    [+0x000 (10:10)] Prototype        : 0x0 [Type: unsigned __int64]
    [+0x000 (11:11)] Transition       : 0x1 [Type: unsigned __int64]
    [+0x000 (12:12)] InStore          : 0x0 [Type: unsigned __int64]
    [+0x000 (31:13)] Unused1          : 0x34fe4 [Type: unsigned __int64]
    [+0x000 (63:32)] PageFileHigh     : 0x80000000 [Type: unsigned __int64]

```

<br>
**Important Breakpoints**

___


```
1: kd> bl
     0 e Disable Clear  01144c41     0001 (0001) pagefault!main+0xc1
     1 e Disable Clear  01144af2     0001 (0001) pagefault!PageFaultExceptionFilter+0x42
     2 e Disable Clear  01144b10     0001 (0001) pagefault!PageFaultExceptionFilter+0x60
     3 e Disable Clear  82aca315     0001 (0001) nt!MmAccessFault
     Match process data 86346318
     4 e Disable Clear  82ada10d     0001 (0001) nt!MiResolveDemandZeroFault
     Match process data 86346318

```

<br>
**Next we hit go and same stuff happens for the next page and so on..**

___


```
1: kd> g
Breakpoint 0 hit
pagefault!main+0xc1:
01144c41 mov     edx,dword ptr [ebp-28h]

1: kd> g
Breakpoint 1 hit
pagefault!PageFaultExceptionFilter+0x42:
01144af2 push    4

1: kd> dt lpNxtPage
pagefault!lpNxtPage
0x001f1000  "--- memory read error at address 0x001f1000 ---"

1: kd> !pte 0x001f1000
                    VA 001f1000
PDE at C0600000            PTE at C0000F88
contains 000000006A1A6867  contains 0000000000000000
pfn 6a1a6     ---DA--UWEV  not valid


# Notice previous page is commited with valid data written before current page

1: kd> db 0x001f1000-0x10
001f0ff0  61 61 61 61 61 61 61 61-61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa
001f1000  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
001f1010  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
001f1020  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
001f1030  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
001f1040  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
001f1050  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????
001f1060  ?? ?? ?? ?? ?? ?? ?? ??-?? ?? ?? ?? ?? ?? ?? ??  ????????????????

1: kd> g
Breakpoint 2 hit
pagefault!PageFaultExceptionFilter+0x60:
01144b10 cmp     dword ptr [ebp-4],0
1: kd> g
Breakpoint 4 hit
nt!MiResolveDemandZeroFault:
0008:82ada10d mov     edi,edi
1: kd> g
Breakpoint 0 hit
pagefault!main+0xc1:
01144c41 mov     edx,dword ptr [ebp-28h]
1: kd> !pte 0x001f1000
                    VA 001f1000
PDE at C0600000            PTE at C0000F88
contains 000000006A1A6867  contains 8000000069C49867
pfn 6a1a6     ---DA--UWEV  pfn 69c49     ---DA--UW-V

1: kd> db 001f1000
001f1000  61 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  a...............
001f1010  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
001f1020  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
001f1030  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
001f1040  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
001f1050  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
001f1060  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
001f1070  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................

1: kd> !pfn 69c49
    PFN 00069C49 at address 84B917FC
    flink       00000158  blink / share count 00000001  pteaddress C0000F88
    reference count 0001   Cached     color 0   Priority 5
    restore pte 00000080  containing page 06A1A6  Active     M
    Modified

1: kd> !db 69c49000
#69c49000 61 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 a...............
#69c49010 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
#69c49020 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
#69c49030 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
#69c49040 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
#69c49050 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
#69c49060 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................
#69c49070 00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00 ................

```


