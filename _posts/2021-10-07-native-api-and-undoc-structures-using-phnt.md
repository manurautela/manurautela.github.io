---
layout: posts
title:  "native api and undoc windows structure using process hacker's phnt"
date:   2021-10-07 10:00:00 +0530
categories: phnt, processhacker, undoc, windows
---

Quite often on windows accessing native api and undoc structures is required.

The repo contains needed headers to be included to access structure and api.
The projet is updated frequently and very actively maintained over the years.
[process hacker's phnt](https://github.com/processhacker/phnt)

There is another neat utility `pdbex` to get such undoc strucutres from
publicly available pdb similar to phnt.

Just to get an idea let's have a look at the difference between the one
microsoft provides and phnt.

[winternl](https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)

As one can notice most of the fields and structures are either marked as
reserved/hidden in *winternl*.

___

```cpp
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

And here is the same structure definition for PEB from phnt.

___

```cpp
typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PAPI_SET_NAMESPACE ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID *ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[4]; // 19H1 (previously FlsCallback to FlsHighIndex)
    ULONG SpareUlongs[5]; // 19H1
    //PVOID* FlsCallback;
    //LIST_ENTRY FlsListHead;
    //PVOID FlsBitmap;
    //ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    //ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA *LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} PEB, *PPEB;
```

# Steps
___

* `git clone --recurse-submodules https://github.com/manurautela/phnt-sample`

* cd phnt-demo

* open phnt-demo.sln with vs2019

* build

# Sample project
___

[sample project based on phnt](https://github.com/manurautela/phnt-sample)

![image](/assets/images/phnt/phntdemo.jpg)


# Inspecting with windbg
___

```
0:000> !teb
TEB at 00925000
    ExceptionList:        005ff85c
    StackBase:            00600000
    StackLimit:           005fd000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 00925000
    EnvironmentPointer:   00000000
    ClientId:             00004224 . 00001bb8
    RpcHandle:            00000000
    Tls Storage:          0092502c
    PEB Address:          00922000
    LastErrorValue:       0
    LastStatusValue:      c00700bb
    Count Owned Locks:    0
    HardErrorMode:        0
0:000> dd fs:[0x18] l1
0053:00000018  00925000
0:000> dd fs:[0x30] l1
0053:00000030  00922000
0:000> dv /v /t
005ff338          unsigned long dwTeb = 0x925000
005ff344          unsigned long dwPeb = 0x922000
005ff368          struct _PEB _peb = struct _PEB
005ff35c          unsigned long peb_x86 = 0x922000
005ff350          unsigned long teb_x86 = 0x925000
0:000> dx -r1 (*((phnt_demo!_PEB *)0x5ff368))
(*((phnt_demo!_PEB *)0x5ff368))                 [Type: _PEB]
    [+0x000] InheritedAddressSpace : 0x0 [Type: unsigned char]
    [+0x001] ReadImageFileExecOptions : 0x0 [Type: unsigned char]
    [+0x002] BeingDebugged    : 0x1 [Type: unsigned char]
    [+0x003] BitField         : 0x4 [Type: unsigned char]
    [+0x003 ( 0: 0)] ImageUsesLargePages : 0x0 [Type: unsigned char]
    [+0x003 ( 1: 1)] IsProtectedProcess : 0x0 [Type: unsigned char]
    [+0x003 ( 2: 2)] IsImageDynamicallyRelocated : 0x1 [Type: unsigned char]
    [+0x003 ( 3: 3)] SkipPatchingUser32Forwarders : 0x0 [Type: unsigned char]
    [+0x003 ( 4: 4)] IsPackagedProcess : 0x0 [Type: unsigned char]
    [+0x003 ( 5: 5)] IsAppContainer   : 0x0 [Type: unsigned char]
    [+0x003 ( 6: 6)] IsProtectedProcessLight : 0x0 [Type: unsigned char]
    [+0x003 ( 7: 7)] IsLongPathAwareProcess : 0x0 [Type: unsigned char]
    [+0x004] Mutant           : 0xffffffff [Type: void *]
    [+0x008] ImageBaseAddress : 0x6d0000 [Type: void *]
    [+0x00c] Ldr              : 0x77245d80 [Type: _PEB_LDR_DATA *]
    [+0x010] ProcessParameters : 0xa92928 [Type: _RTL_USER_PROCESS_PARAMETERS *]
    [+0x014] SubSystemData    : 0x0 [Type: void *]
    [+0x018] ProcessHeap      : 0xa90000 [Type: void *]
    [+0x01c] FastPebLock      : 0x77245b40 [Type: _RTL_CRITICAL_SECTION *]
    [+0x020] AtlThunkSListPtr : 0x0 [Type: _SLIST_HEADER *]
    [+0x024] IFEOKey          : 0x0 [Type: void *]
    [+0x028] CrossProcessFlags : 0x0 [Type: unsigned long]
    [+0x028 ( 0: 0)] ProcessInJob     : 0x0 [Type: unsigned long]
    [+0x028 ( 1: 1)] ProcessInitializing : 0x0 [Type: unsigned long]
    [+0x028 ( 2: 2)] ProcessUsingVEH  : 0x0 [Type: unsigned long]
    [+0x028 ( 3: 3)] ProcessUsingVCH  : 0x0 [Type: unsigned long]
    [+0x028 ( 4: 4)] ProcessUsingFTH  : 0x0 [Type: unsigned long]
    [+0x028 ( 5: 5)] ProcessPreviouslyThrottled : 0x0 [Type: unsigned long]
    [+0x028 ( 6: 6)] ProcessCurrentlyThrottled : 0x0 [Type: unsigned long]
    [+0x028 ( 7: 7)] ProcessImagesHotPatched : 0x0 [Type: unsigned long]
    [+0x028 (31: 8)] ReservedBits0    : 0x0 [Type: unsigned long]
    [+0x02c] KernelCallbackTable : 0x0 [Type: void *]
    [+0x02c] UserSharedInfoPtr : 0x0 [Type: void *]
    [+0x030] SystemReserved   : 0x0 [Type: unsigned long]
    [+0x034] AtlThunkSListPtr32 : 0x0 [Type: unsigned long]
    [+0x038] ApiSetMap        : 0x4a0000 [Type: _API_SET_NAMESPACE *]
    [+0x03c] TlsExpansionCounter : 0x0 [Type: unsigned long]
    [+0x040] TlsBitmap        : 0x77245d30 [Type: void *]
    [+0x044] TlsBitmapBits    [Type: unsigned long [2]]
    [+0x04c] ReadOnlySharedMemoryBase : 0x7fc90000 [Type: void *]
    [+0x050] SharedData       : 0x0 [Type: void *]
    [+0x054] ReadOnlyStaticServerData : 0x7fc90750 [Type: void * *]
    [+0x058] AnsiCodePageData : 0x7fdf0000 [Type: void *]
    [+0x05c] OemCodePageData  : 0x7fe00228 [Type: void *]
    [+0x060] UnicodeCaseTableData : 0x7fe10650 [Type: void *]
    [+0x064] NumberOfProcessors : 0x8 [Type: unsigned long]
    [+0x068] NtGlobalFlag     : 0x470 [Type: unsigned long]
    [+0x070] CriticalSectionTimeout : {0xffffe86d079b8000} [Type: _ULARGE_INTEGER]
    [+0x078] HeapSegmentReserve : 0x100000 [Type: unsigned long]
    [+0x07c] HeapSegmentCommit : 0x2000 [Type: unsigned long]
    [+0x080] HeapDeCommitTotalFreeThreshold : 0x10000 [Type: unsigned long]
    [+0x084] HeapDeCommitFreeBlockThreshold : 0x1000 [Type: unsigned long]
    [+0x088] NumberOfHeaps    : 0x1 [Type: unsigned long]
    [+0x08c] MaximumNumberOfHeaps : 0x10 [Type: unsigned long]
    [+0x090] ProcessHeaps     : 0x77244840 [Type: void * *]
    [+0x094] GdiSharedHandleTable : 0x0 [Type: void *]
    [+0x098] ProcessStarterHelper : 0x0 [Type: void *]
    [+0x09c] GdiDCAttributeList : 0x0 [Type: unsigned long]
    [+0x0a0] LoaderLock       : 0x77243390 [Type: _RTL_CRITICAL_SECTION *]
    [+0x0a4] OSMajorVersion   : 0xa [Type: unsigned long]
    [+0x0a8] OSMinorVersion   : 0x0 [Type: unsigned long]
    [+0x0ac] OSBuildNumber    : 0x4a63 [Type: unsigned short]
    [+0x0ae] OSCSDVersion     : 0x0 [Type: unsigned short]
    [+0x0b0] OSPlatformId     : 0x2 [Type: unsigned long]
    [+0x0b4] ImageSubsystem   : 0x3 [Type: unsigned long]
    [+0x0b8] ImageSubsystemMajorVersion : 0x6 [Type: unsigned long]
    [+0x0bc] ImageSubsystemMinorVersion : 0x0 [Type: unsigned long]
    [+0x0c0] ActiveProcessAffinityMask : 0xff [Type: unsigned long]
    [+0x0c4] GdiHandleBuffer  [Type: unsigned long [34]]
    [+0x14c] PostProcessInitRoutine : 0x0 [Type: void *]
    [+0x150] TlsExpansionBitmap : 0x77245d18 [Type: void *]
    [+0x154] TlsExpansionBitmapBits [Type: unsigned long [32]]
    [+0x1d4] SessionId        : 0x23 [Type: unsigned long]
    [+0x1d8] AppCompatFlags   : {0x0} [Type: _ULARGE_INTEGER]
    [+0x1e0] AppCompatFlagsUser : {0x0} [Type: _ULARGE_INTEGER]
    [+0x1e8] pShimData        : 0x620000 [Type: void *]
    [+0x1ec] AppCompatInfo    : 0x0 [Type: void *]
    [+0x1f0] CSDVersion       [Type: _UNICODE_STRING]
    [+0x1f8] ActivationContextData : 0x610000 [Type: void *]
    [+0x1fc] ProcessAssemblyStorageMap : 0x0 [Type: void *]
    [+0x200] SystemDefaultActivationContextData : 0x600000 [Type: void *]
    [+0x204] SystemAssemblyStorageMap : 0x0 [Type: void *]
    [+0x208] MinimumStackCommit : 0x0 [Type: unsigned long]
    [+0x20c] SparePointers    [Type: void * [4]]
    [+0x21c] SpareUlongs      [Type: unsigned long [5]]
    [+0x230] WerRegistrationData : 0x0 [Type: void *]
    [+0x234] WerShipAssertPtr : 0x0 [Type: void *]
    [+0x238] pUnused          : 0x0 [Type: void *]
    [+0x23c] pImageHeaderHash : 0x0 [Type: void *]
    [+0x240] TracingFlags     : 0x0 [Type: unsigned long]
    [+0x240 ( 0: 0)] HeapTracingEnabled : 0x0 [Type: unsigned long]
    [+0x240 ( 1: 1)] CritSecTracingEnabled : 0x0 [Type: unsigned long]
    [+0x240 ( 2: 2)] LibLoaderTracingEnabled : 0x0 [Type: unsigned long]
    [+0x240 (31: 3)] SpareTracingBits : 0x0 [Type: unsigned long]
    [+0x248] CsrServerReadOnlySharedMemoryBase : 0x7df467950000 [Type: unsigned __int64]
    [+0x250] TppWorkerpListLock : 0x0 [Type: _RTL_CRITICAL_SECTION *]
    [+0x254] TppWorkerpList   [Type: _LIST_ENTRY]
    [+0x25c] WaitOnAddressHashTable [Type: void * [128]]
    [+0x45c] TelemetryCoverageHeader : 0x0 [Type: void *]
    [+0x460] CloudFileFlags   : 0x0 [Type: unsigned long]
    [+0x464] CloudFileDiagFlags : 0x0 [Type: unsigned long]
    [+0x468] PlaceholderCompatibilityMode : 0 [Type: char]
    [+0x469] PlaceholderCompatibilityModeReserved : "" [Type: char [7]]
    [+0x470] LeapSecondData   : 0x7fde0000 [Type: _LEAP_SECOND_DATA *]
    [+0x474] LeapSecondFlags  : 0x0 [Type: unsigned long]
    [+0x474 ( 0: 0)] SixtySecondEnabled : 0x0 [Type: unsigned long]
    [+0x474 (31: 1)] Reserved         : 0x0 [Type: unsigned long]
    [+0x478] NtGlobalFlag2    : 0x0 [Type: unsigned long]
0:000> dx -r1 ((phnt_demo!_RTL_USER_PROCESS_PARAMETERS *)0xa92928)
((phnt_demo!_RTL_USER_PROCESS_PARAMETERS *)0xa92928)                 : 0xa92928 [Type: _RTL_USER_PROCESS_PARAMETERS *]
    [+0x000] MaximumLength    : 0x2368 [Type: unsigned long]
    [+0x004] Length           : 0x2368 [Type: unsigned long]
    [+0x008] Flags            : 0x2001 [Type: unsigned long]
    [+0x00c] DebugFlags       : 0x0 [Type: unsigned long]
    [+0x010] ConsoleHandle    : 0x90 [Type: void *]
    [+0x014] ConsoleFlags     : 0x0 [Type: unsigned long]
    [+0x018] StandardInput    : 0x9c [Type: void *]
    [+0x01c] StandardOutput   : 0xa0 [Type: void *]
    [+0x020] StandardError    : 0xa4 [Type: void *]
    [+0x024] CurrentDirectory [Type: _CURDIR]
    [+0x030] DllPath          [Type: _UNICODE_STRING]
    [+0x038] ImagePathName    [Type: _UNICODE_STRING]
    [+0x040] CommandLine      [Type: _UNICODE_STRING]
    [+0x048] Environment      : 0xa90b80 [Type: void *]
    [+0x04c] StartingX        : 0x0 [Type: unsigned long]
    [+0x050] StartingY        : 0x0 [Type: unsigned long]
    [+0x054] CountX           : 0x0 [Type: unsigned long]
    [+0x058] CountY           : 0x0 [Type: unsigned long]
    [+0x05c] CountCharsX      : 0x0 [Type: unsigned long]
    [+0x060] CountCharsY      : 0x0 [Type: unsigned long]
    [+0x064] FillAttribute    : 0x0 [Type: unsigned long]
    [+0x068] WindowFlags      : 0x0 [Type: unsigned long]
    [+0x06c] ShowWindowFlags  : 0x0 [Type: unsigned long]
    [+0x070] WindowTitle      [Type: _UNICODE_STRING]
    [+0x078] DesktopInfo      [Type: _UNICODE_STRING]
    [+0x080] ShellInfo        [Type: _UNICODE_STRING]
    [+0x088] RuntimeData      [Type: _UNICODE_STRING]
    [+0x090] CurrentDirectories [Type: _RTL_DRIVE_LETTER_CURDIR [32]]
    [+0x290] EnvironmentSize  : 0x1d8a [Type: unsigned long]
    [+0x294] EnvironmentVersion : 0x4 [Type: unsigned long]
    [+0x298] PackageDependencyData : 0x0 [Type: void *]
    [+0x29c] ProcessGroupId   : 0x4aa8 [Type: unsigned long]
    [+0x2a0] LoaderThreads    : 0x0 [Type: unsigned long]
    [+0x2a4] RedirectionDllName [Type: _UNICODE_STRING]
    [+0x2ac] HeapPartitionName [Type: _UNICODE_STRING]
    [+0x2b4] DefaultThreadpoolCpuSetMasks : 0x0 [Type: unsigned long]
    [+0x2b8] DefaultThreadpoolCpuSetMaskCount : 0x0 [Type: unsigned long]
0:000> dx -r1 (*((phnt_demo!_UNICODE_STRING *)0xa92960))
(*((phnt_demo!_UNICODE_STRING *)0xa92960))                 [Type: _UNICODE_STRING]
    [+0x000] Length           : 0x6a [Type: unsigned short]
    [+0x002] MaximumLength    : 0x6c [Type: unsigned short]
    [+0x004] Buffer           : 0xa92df0 : "J:\dev\temp\phnt-sample\phnt-demo\Debug\phnt-demo.exe" [Type: wchar_t *]
0:000> dx -r1 (*((phnt_demo!_UNICODE_STRING *)0xa92968))
(*((phnt_demo!_UNICODE_STRING *)0xa92968))                 [Type: _UNICODE_STRING]
    [+0x000] Length           : 0x1a [Type: unsigned short]
    [+0x002] MaximumLength    : 0x1c [Type: unsigned short]
    [+0x004] Buffer           : 0xa92e5c : "phnt-demo.exe" [Type: wchar_t *]

```
