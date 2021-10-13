---
layout: posts
title:  "memory tracking through nt!PoolHitTag"
date:   2021-10-13 10:00:00 +0530
categories: memory, windows, windbg, pool, poolused, poolfind, poolhittag
---

Let's explore how nt!PoolHitTag can be useful for while tracking memory issues.
Along with useful windbg command like !pool, !poolfind, !verifier etc.

<br>
**Sample driver**

___

[sample driver](https://github.com/zodiacon/windowskernelprogrammingbook2e/tree/master/Chapter02)

I have compiled the driver for Windows7 x86 by changing "Target OS Version"


<br>
**sample driver without memory leak**


![sample driver valid](/assets/images/poolhittag/sample_good.jpg)

![sample driver memory](/assets/images/poolhittag/sample_good_buffer.jpg)


<br>
**Windbg logs**

___


```
# Setup PoolHitTag with our driver's pool tag
1: kd> ed nt!PoolHitTag 'dcba'

1: kd> dd nt!PoolHitTag l1
82b37df4  64636261

1: kd> .formats 64636261
Evaluate expression:
  Hex:     64636261
  Decimal: 1684234849
  Octal:   14430661141
  Binary:  01100100 01100011 01100010 01100001
  Chars:   dcba
  Time:    Tue May 16 16:30:49 2023
  Float:   low 1.6778e+022 high 0
  Double:  8.32123e-315

1: kd> g
Break instruction exception - code 80000003 (first chance)
nt!ExAllocatePoolWithTag+0x881:
82b2f88c int     3

# ExAllocatePoolWithTag called trying to allocate paged pool memory

1: kd> kvn
 # ChildEBP RetAddr  Args to Child
00 8772d834 82ab06b1 000000c1 00000070 64636261 nt!ExAllocatePoolWithTag+0x881
01 8772d85c 82d40cba 000000c1 00000070 64636261 nt!ExAllocatePoolWithTagPriority+0x196
02 8772d890 82d4074f 000000c1 00000070 64636261 nt!VeAllocatePoolWithTagPriority+0x1a7
03 8772d8ac a04c3057 00000001 0000006c 64636261 nt!VerifierExAllocatePoolWithTag+0x1e
04 8772d9d8 82bd22e6 86a220d0 86a40000 00000000 Sample!DriverEntry+0x27 (FPO: [Non-Fpo]) (CONV: stdcall) [J:\dev\temp\driver\kerprg2\Chapter02\Sample\Sample.cpp @ 16]
05 8772dbbc 82bd5d98 00000001 00000000 8772dbe4 nt!IopLoadDriver+0x7ed
06 8772dc00 82a8baab 91f8cbd0 00000000 84efcd48 nt!IopLoadUnloadDriver+0x70
07 8772dc50 82c17f5e 00000001 5e0b8526 00000000 nt!ExpWorkerThread+0x10d
08 8772dc90 82abf219 82a8b99e 00000001 00000000 nt!PspSystemThreadStartup+0x9e
09 00000000 00000000 00000000 00000000 00000000 nt!KiThreadStartup+0x19

# Let's examine the memory buffer

1: kd> g
Breakpoint 1 hit
Sample!DriverEntry+0x2c:
a04c305c cmp     dword ptr [Sample!g_RegistryPath+0x4 (a04c500c)],0

1: kd> r @eax
eax=91c26130

1: kd> dt Sample!g_RegistryPath
 ""   +0x000 Length           : 0
   +0x002 MaximumLength    : 0
   +0x004 Buffer           : 0x91c26130  ""

# on x86 win7 pool header is 8 byts before the buffer
1: kd> ?? sizeof(nt!_POOL_HEADER)
unsigned int 8

1: kd> dt nt!_POOL_HEADER 0x91c26130-8
   +0x000 PreviousSize     : 0y000001100 (0xc)
   +0x000 PoolIndex        : 0y0000001 (0x1)
   +0x002 BlockSize        : 0y000001111 (0xf)
   +0x002 PoolType         : 0y1000011 (0x43)
   +0x000 Ulong1           : 0x860f020c
   +0x004 PoolTag          : 0x64636261
   +0x004 AllocatorBackTraceIndex : 0x6261
   +0x006 PoolTagHash      : 0x6463

1: kd> !pool 0x91c26130  2
Pool page 91c26130 region is Paged pool
*91c26128 size:   78 previous size:   60  (Allocated) *abcd
		Owning component : Unknown (update pooltag.txt)

1: kd> g
original registry path: \REGISTRY\MACHINE\SYSTEM\ControlSet001\services\Sample
Copied registry path: \REGISTRY\MACHINE\SYSTEM\ControlSet001\services\Sample
Breakpoint 0 hit
Sample!DriverEntry+0x8a:
a04c30ba mov     eax,dword ptr [ebp+8]
1: kd> g
Windows Version: 6.1.7601
Sample driver initialized successfully

# Later on when the driver is unloaded, it's unload routine that frees up memory is invoked
Break instruction exception - code 80000003 (first chance)
nt!ExFreePoolWithTag+0x649:
82b30104 int     3
1: kd> kvn
 # ChildEBP RetAddr  Args to Child
00 8772dba0 82d40f90 91c26130 64636261 a0a4f900 nt!ExFreePoolWithTag+0x649
01 8772dbb4 a04c3014 91c26130 64636261 8772dc00 nt!VerifierExFreePoolWithTag+0x30
02 8772dbc4 82bd5d46 86a220d0 a0a4f900 84efcd48 Sample!SampleUnload+0x14 (FPO: [Non-Fpo]) (CONV: stdcall) [J:\dev\temp\driver\kerprg2\Chapter02\Sample\Sample.cpp @ 11]
03 8772dc00 82a8baab a0a4f900 00000000 84efcd48 nt!IopLoadUnloadDriver+0x1e
04 8772dc50 82c17f5e 00000001 5e0b8526 00000000 nt!ExpWorkerThread+0x10d
05 8772dc90 82abf219 82a8b99e 00000001 00000000 nt!PspSystemThreadStartup+0x9e
06 00000000 00000000 00000000 00000000 00000000 nt!KiThreadStartup+0x19

1: kd> g
Sample driver Unload called

```


<br>
# Now build driver with memory leak inside unload routine
___

> enable driver verifier and comment the code that frees up the memory

```cpp
void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	//ExFreePoolWithTag(g_RegistryPath.Buffer, DRIVER_TAG);
	KdPrint(("Sample driver Unload called\n"));
}

```

<br>
**Reload faulty driver again and during unload we hit bugcheck caught by verifier**

___

<br>

```
0: kd> g
*******************************************************************************
*
* This is the string you add to your checkin description
* Driver Verifier: Enabled for Sample.sys on Build 7601 rCq7yw90VwDkyhs4XybI3G
*
*******************************************************************************

# This is same as previous without PoolHitTag getting hit.

Break instruction exception - code 80000003 (first chance)
nt!ExAllocatePoolWithTag+0x881:
82b2f88c int     3
0: kd> kvn
 # ChildEBP RetAddr  Args to Child
00 87745834 82ab06b1 000000c1 00000070 64636261 nt!ExAllocatePoolWithTag+0x881
01 8774585c 82d40cba 000000c1 00000070 64636261 nt!ExAllocatePoolWithTagPriority+0x196
02 87745890 82d4074f 000000c1 00000070 64636261 nt!VeAllocatePoolWithTagPriority+0x1a7
03 877458ac a05c1047 00000001 0000006c 64636261 nt!VerifierExAllocatePoolWithTag+0x1e
04 877459d8 82bd22e6 86a55b90 84f27000 00000000 Sample!DriverEntry+0x27 (FPO: [Non-Fpo]) (CONV: stdcall) [J:\dev\temp\driver\kerprg2\Chapter02\Sample\Sample.cpp @ 16]
05 87745bbc 82bd5d98 00000001 00000000 87745be4 nt!IopLoadDriver+0x7ed
06 87745c00 82a8baab 91f8cbd0 00000000 84efda70 nt!IopLoadUnloadDriver+0x70
07 87745c50 82c17f5e 00000001 5e0d0526 00000000 nt!ExpWorkerThread+0x10d
08 87745c90 82abf219 82a8b99e 00000001 00000000 nt!PspSystemThreadStartup+0x9e
09 00000000 00000000 00000000 00000000 00000000 nt!KiThreadStartup+0x19

0: kd> .frame 0n4;dv /t /v
04 877459d8 82bd22e6 Sample!DriverEntry+0x27 [J:\dev\temp\driver\kerprg2\Chapter02\Sample\Sample.cpp @ 16]
877459e0          struct _DRIVER_OBJECT * DriverObject = 0x86a55b90 Driver "\Driver\Sample"
877459e4          struct _UNICODE_STRING * RegistryPath = 0x84f27000 "\REGISTRY\MACHINE\SYSTEM\ControlSet001\services\Sample"
877458c0          struct _OSVERSIONINFOW info = struct _OSVERSIONINFOW

0: kd> g
Breakpoint 0 hit
Sample!DriverEntry+0x2c:
a05c104c cmp     dword ptr [Sample!g_RegistryPath+0x4 (a05c300c)],0
0: kd> dt sample!g_RegistryPath
 ""   +0x000 Length           : 0
   +0x002 MaximumLength    : 0
   +0x004 Buffer           : 0x86491d10  ""


0: kd> !pool 0x86491d10  2
Pool page 86491d10 region is Paged pool
*86491d08 size:   78 previous size:   30  (Allocated) *abcd
		Owning component : Unknown (update pooltag.txt)

0: kd> g
original registry path: \REGISTRY\MACHINE\SYSTEM\ControlSet001\services\Sample
Copied registry path: \REGISTRY\MACHINE\SYSTEM\ControlSet001\services\Sample
Windows Version: 6.1.7601
Sample driver initialized successfully


# But during driver unload, we hit a bugcheck since driver verifier is enabled
# and allocations don't match the frees for driver

Sample driver Unload called

*** Fatal System Error: 0x000000c4
                       (0x00000062,0x86A84EBC,0x86A2D4F8,0x00000001)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

For analysis of this file, run !analyze -v
nt!RtlpBreakWithStatusInstruction:
82a89110 int     3
1: kd> !analyze -v
Connected to Windows 7 7601 x86 compatible target at (Wed Oct 13 10:49:09.459 2021 (UTC + 5:30)), ptr64 FALSE
Loading Kernel Symbols
...............................................................
................................................................
........................
Loading User Symbols
.................................
Loading unloaded module list
..........
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

DRIVER_VERIFIER_DETECTED_VIOLATION (c4)
A device driver attempting to corrupt the system has been caught.  This is
because the driver was specified in the registry as being suspect (by the
administrator) and the kernel has enabled substantial checking of this driver.
If the driver attempts to corrupt the system, bugchecks 0xC4, 0xC1 and 0xA will
be among the most commonly seen crashes.
Arguments:
Arg1: 00000062, A driver has forgotten to free its pool allocations prior to unloading.
Arg2: 86a84ebc, name of the driver having the issue.
Arg3: 86a2d4f8, verifier internal structure with driver information.
Arg4: 00000001, total # of (paged+nonpaged) allocations that weren't freed.
	Type !verifier 3 drivername.sys for info on the allocations
	that were leaked that caused the bugcheck.

Debugging Details:
------------------


KEY_VALUES_STRING: 1

    Key  : Analysis.CPU.Sec
    Value: 3

    Key  : Analysis.DebugAnalysisProvider.CPP
    Value: Create: 8007007e on RED-DRAGON

    Key  : Analysis.DebugData
    Value: CreateObject

    Key  : Analysis.DebugModel
    Value: CreateObject

    Key  : Analysis.Elapsed.Sec
    Value: 3

    Key  : Analysis.Memory.CommitPeak.Mb
    Value: 85

    Key  : Analysis.System
    Value: CreateObject


BUGCHECK_CODE:  c4

BUGCHECK_P1: 62

BUGCHECK_P2: ffffffff86a84ebc

BUGCHECK_P3: ffffffff86a2d4f8

BUGCHECK_P4: 1

IMAGE_NAME:  Sample.sys

MODULE_NAME: Sample

FAULTING_MODULE: a05c0000 Sample

VERIFIER_DRIVER_ENTRY: dt nt!_MI_VERIFIER_DRIVER_ENTRY ffffffff86a2d4f8
Symbol nt!_MI_VERIFIER_DRIVER_ENTRY not found.

<snipped>

Followup:     MachineOwner
---------

1: kd> .thread ; .cxr ; kb
Implicit thread is now 8e976030
 # ChildEBP RetAddr  Args to Child
00 826fb38c 82aed083 00000003 5b16ea6a 00000065 nt!RtlpBreakWithStatusInstruction
01 826fb3dc 82aedb81 00000003 86a2d4f8 00000001 nt!KiBugCheckDebugBreak+0x1c
02 826fb7a0 82aecf20 000000c4 00000062 86a84ebc nt!KeBugCheck2+0x68b
03 826fb7c0 82d44f03 000000c4 00000062 86a84ebc nt!KeBugCheckEx+0x1e
04 826fb7e0 82d495eb 86a84ebc 86a2d4f8 a05c0000 nt!VerifierBugCheckIfAppropriate+0x30
05 826fb7f0 82a1d4ca 86a84e60 82b4ff48 82b4ff48 nt!VfPoolCheckForLeaks+0x33
06 826fb82c 82bae05a 86a84e60 86a84e60 00000100 nt!VfTargetDriversRemove+0x66
07 826fb840 82bbbac2 82b58820 8e976030 00000000 nt!VfDriverUnloadImage+0x5e
08 826fb878 82bbb849 86a84e60 ffffffff 00000000 nt!MiUnloadSystemImage+0x231
09 826fb89c 82cc8ebf 86a84e60 84efe7a8 86a55b78 nt!MmUnloadSystemImage+0x36
0a 826fb8b4 82c31591 86a55b90 86a55b90 86a55b78 nt!IopDeleteDriver+0x38
0b 826fb8cc 82a86d60 00000000 826fbbe8 86a55b90 nt!ObpRemoveObjectRoutine+0x59
0c 826fb8e0 82a86cd0 86a55b90 82cc958d 5b16e38a nt!ObfDereferenceObjectWithTag+0x88
0d 826fb8e8 82cc958d 5b16e38a 826fba54 826fbad0 nt!ObfDereferenceObject+0xd
0e 826fba3c 82cc91de 00000000 826fba54 82a4c1ea nt!IopUnloadDriver+0x3a0
0f 826fba48 82a4c1ea 826fbbe8 826fbc1c 82a4b501 nt!NtUnloadDriver+0xf
10 826fba48 82a4b501 826fbbe8 826fbc1c 82a4b501 nt!KiFastCallEntry+0x12a
11 826fbac4 82cc92dd 826fbbe8 5b16e5aa 00faf644 nt!ZwUnloadDriver+0x11
12 826fbc1c 82cc91de 00000000 826fbc34 82a4c1ea nt!IopUnloadDriver+0xf0
13 826fbc28 82a4c1ea 00faf644 00faf64c 778e70b4 nt!NtUnloadDriver+0xf
14 826fbc28 778e70b4 00faf644 00faf64c 778e70b4 nt!KiFastCallEntry+0x12a
15 00faf628 778e6964 007de711 00faf644 00000000 ntdll!KiFastSystemCallRet
16 00faf62c 007de711 00faf644 00000000 00700468 ntdll!ZwUnloadDriver+0xc
17 00faf64c 007de873 0000000a 00000001 00700468 services!ScUnloadDriver+0x8d
18 00faf664 007cf1dd 00000001 00700468 00faf6c8 services!ScControlDriver+0xde
19 00faf6a0 007c7cef 0030ace0 00000001 00000000 services!ScControlService+0x176
1a 00faf6ec 764404e8 0030ace0 00000001 00faf9a8 services!RControlService+0x2b
1b 00faf70c 764a5311 007c7cc4 00faf8f8 00000003 RPCRT4!Invoke+0x2a
1c 00fafb14 764a431d 00000000 00000000 00310920 RPCRT4!NdrStubCall2+0x2d6
1d 00fafb30 7644063c 00310920 9722349f 00293d58 RPCRT4!NdrServerCall2+0x19
1e 00fafb6c 764407ca 007b28fa 00310920 00fafc1c RPCRT4!DispatchToStubInCNoAvrf+0x4a
1f 00fafbc4 764406b6 00293d58 00000000 00000000 RPCRT4!RPC_INTERFACE::DispatchToStubWorker+0x16c
20 00fafbec 764376db 00000000 00000000 00fafc1c RPCRT4!RPC_INTERFACE::DispatchToStub+0x8b
21 00fafc38 76440ac6 00310868 00fafc54 0030bbe0 RPCRT4!LRPC_SCALL::DispatchRequest+0x257
22 00fafc58 76440a85 00310868 002fb938 0030bbe0 RPCRT4!LRPC_SCALL::QueueOrDispatchCall+0xbd
23 00fafc74 76440921 00000000 002fb920 00293d58 RPCRT4!LRPC_SCALL::HandleRequest+0x34f
24 00fafca8 76440895 00000000 002fb920 0033ac28 RPCRT4!LRPC_SASSOCIATION::HandleRequest+0x144
25 00fafce0 7643fe85 00281eb0 00000000 0033ac28 RPCRT4!LRPC_ADDRESS::HandleRequest+0xbd
26 00fafd58 7643fd1d 00000000 00fafd74 7643fc6a RPCRT4!LRPC_ADDRESS::ProcessIO+0x50a
27 00fafd64 7643fc6a 00281f4c 00000000 00fafd9c RPCRT4!LrpcServerIoHandler+0x16
28 00fafd74 778d1d55 00fafde0 00281f4c 002a3000 RPCRT4!LrpcIoComplete+0x16
29 00fafd9c 778d15ac 00fafde0 00000002 00000000 ntdll!TppAlpcpExecuteCallback+0x1c5
2a 00faff04 76063c45 002ab058 00faff50 779037f5 ntdll!TppWorkerThread+0x5a4
2b 00faff10 779037f5 002ab058 776dadf0 00000000 kernel32!BaseThreadInitThunk+0xe
2c 00faff50 779037c8 778d03e7 002ab058 00000000 ntdll!__RtlUserThreadStart+0x70
2d 00faff68 00000000 778d03e7 002ab058 00000000 ntdll!_RtlUserThreadStart+0x1b

# Dumping the details for our sample driver with verifier
1: kd> !verifier 3 Sample.sys

Verify Flags Level 0x00000008

  STANDARD FLAGS:
    [X] (0x00000000) Automatic Checks
    [ ] (0x00000001) Special pool
    [ ] (0x00000002) Force IRQL checking
    [X] (0x00000008) Pool tracking
    [ ] (0x00000010) I/O verification
    [ ] (0x00000020) Deadlock detection
    [ ] (0x00000080) DMA checking
    [ ] (0x00000100) Security checks
    [ ] (0x00000800) Miscellaneous checks

  ADDITIONAL FLAGS:
    [ ] (0x00000004) Randomized low resources simulation
    [ ] (0x00000200) Force pending I/O requests
    [ ] (0x00000400) IRP logging

    [X] Indicates flag is enabled


Summary of All Verifier Statistics

  RaiseIrqls           0x0
  AcquireSpinLocks     0x0
  Synch Executions     0x0
  Trims                0x0

  Pool Allocations Attempted             0x3
  Pool Allocations Succeeded             0x3
  Pool Allocations Succeeded SpecialPool 0x0
  Pool Allocations With NO TAG           0x0
  Pool Allocations Failed                0x0

  Current paged pool allocations         0x1 for 00000070 bytes
  Peak paged pool allocations            0x1 for 00000070 bytes
  Current nonpaged pool allocations      0x0 for 00000000 bytes
  Peak nonpaged pool allocations         0x0 for 00000000 bytes

Driver Verification List
------------------------

nt!_VF_TARGET_DRIVER 0xa013f2c8: Sample.sys (Loaded and Unloaded)

    Pool Allocation Statistics: ( NonPagedPool / PagedPool )

      Current Pool Allocations: ( 0x00000000 / 0x00000001 )
      Current Pool Bytes:       ( 0x00000000 / 0x00000070 )
      Peak Pool Allocations:    ( 0x00000000 / 0x00000001 )
      Peak Pool Bytes:          ( 0x00000000 / 0x00000070 )
      Contiguous Memory Bytes:       0x00000000
      Peak Contiguous Memory Bytes:  0x00000000

    Pool Allocations:

      Address     Length      Tag   Caller
      ----------  ----------  ----  ----------
      0x86491d10  0x00000070  abcd  0xa05c1047  Sample!DriverEntry+0x27

    Contiguous allocations are not displayed with public symbols.

```

<br>


**Sample driver verifier logs after bugcheck in driver unload**

___

<br>

![sample driver verifier](/assets/images/poolhittag/sample_faulty_verifier.jpg)


# Reference

Pavel's repo for the upcoming book.
[sample driver](https://github.com/zodiacon/windowskernelprogrammingbook2e/tree/master/Chapter02)

[windbg_tips_codemachine](https://www.codemachine.com/articles/windbg_tips.html)

[kernel-memory-leak](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/using-the-kernel-debugger-to-find-a-kernel-mode-memory-leak)

[poolfind](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-poolfind)

[verifier](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/-verifier)

[ExAllocatePoolWithTag](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag)

