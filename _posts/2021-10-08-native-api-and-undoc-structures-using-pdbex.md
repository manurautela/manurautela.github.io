---
layout: posts
title:  "native api and undoc windows structure using pdbex"
date:   2021-10-08 10:00:00 +0530
categories: pdbex, undoc, windows, windbg
---

In the prev post we saw how to use phnt to access windows native api and undoc
structures.

Another cool way to get the same stuff is via a neat utility that can be really
useful in many other situations and tooling. Where one needs c like structure
definition from publicly available pdbs.

[pdbex repo](https://github.com/wbenny/pdbex)

[pdbex-sample](https://github.com/manurautela/pdbex-sample)

# Steps
___

**ntdll.pdb used here is for win7 x86**

>* pdbexe _PEB -m -j -i ntdll.pdb
>* pdbexe _RTL_USER_PROCESS_PARAMETERS -m -j -i ntdll.pdb
>* merge them and include as header in your project


[final dumped structures from pdb](https://github.com/manurautela/pdbex-sample/tree/main/win7sp1x86)

Here is the structure definition for PEB from pdbex.

___


```cpp
typedef struct _PEB {
    /* 0x0000 */ uint8_t InheritedAddressSpace;
    /* 0x0001 */ uint8_t ReadImageFileExecOptions;
    /* 0x0002 */ uint8_t BeingDebugged;
    union {
        /* 0x0003 */ uint8_t BitField;
        struct /* bitfield */
        {
            /* 0x0003 */ uint8_t ImageUsesLargePages : 1; /* bit position: 0 */
            /* 0x0003 */ uint8_t IsProtectedProcess : 1; /* bit position: 1 */
            /* 0x0003 */ uint8_t IsLegacyProcess : 1; /* bit position: 2 */
            /* 0x0003 */ uint8_t IsImageDynamicallyRelocated : 1; /* bit position: 3 */
            /* 0x0003 */ uint8_t SkipPatchingUser32Forwarders : 1; /* bit position: 4 */
            /* 0x0003 */ uint8_t SpareBits : 3; /* bit position: 5 */
        }; /* bitfield */
    }; /* size: 0x0001 */
    /* 0x0004 */ void* Mutant;
    /* 0x0008 */ void* ImageBaseAddress;
    /* 0x000c */ struct _PEB_LDR_DATA* Ldr;
    /* 0x0010 */ struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    /* 0x0014 */ void* SubSystemData;
    /* 0x0018 */ void* ProcessHeap;
    /* 0x001c */ struct _RTL_CRITICAL_SECTION* FastPebLock;
    /* 0x0020 */ void* AtlThunkSListPtr;
    /* 0x0024 */ void* IFEOKey;
    union {
        /* 0x0028 */ uint32_t CrossProcessFlags;
        struct /* bitfield */
        {
            /* 0x0028 */ uint32_t ProcessInJob : 1; /* bit position: 0 */
            /* 0x0028 */ uint32_t ProcessInitializing : 1; /* bit position: 1 */
            /* 0x0028 */ uint32_t ProcessUsingVEH : 1; /* bit position: 2 */
            /* 0x0028 */ uint32_t ProcessUsingVCH : 1; /* bit position: 3 */
            /* 0x0028 */ uint32_t ProcessUsingFTH : 1; /* bit position: 4 */
            /* 0x0028 */ uint32_t ReservedBits0 : 27; /* bit position: 5 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    union {
        /* 0x002c */ void* KernelCallbackTable;
        /* 0x002c */ void* UserSharedInfoPtr;
    }; /* size: 0x0004 */
    /* 0x0030 */ uint32_t SystemReserved[1];
    /* 0x0034 */ uint32_t AtlThunkSListPtr32;
    /* 0x0038 */ void* ApiSetMap;
    /* 0x003c */ uint32_t TlsExpansionCounter;
    /* 0x0040 */ void* TlsBitmap;
    /* 0x0044 */ uint32_t TlsBitmapBits[2];
    /* 0x004c */ void* ReadOnlySharedMemoryBase;
    /* 0x0050 */ void* HotpatchInformation;
    /* 0x0054 */ void** ReadOnlyStaticServerData;
    /* 0x0058 */ void* AnsiCodePageData;
    /* 0x005c */ void* OemCodePageData;
    /* 0x0060 */ void* UnicodeCaseTableData;
    /* 0x0064 */ uint32_t NumberOfProcessors;
    /* 0x0068 */ uint32_t NtGlobalFlag;
    /* 0x006c */ long Padding_0;
    /* 0x0070 */ union _LARGE_INTEGER CriticalSectionTimeout;
    /* 0x0078 */ uint32_t HeapSegmentReserve;
    /* 0x007c */ uint32_t HeapSegmentCommit;
    /* 0x0080 */ uint32_t HeapDeCommitTotalFreeThreshold;
    /* 0x0084 */ uint32_t HeapDeCommitFreeBlockThreshold;
    /* 0x0088 */ uint32_t NumberOfHeaps;
    /* 0x008c */ uint32_t MaximumNumberOfHeaps;
    /* 0x0090 */ void** ProcessHeaps;
    /* 0x0094 */ void* GdiSharedHandleTable;
    /* 0x0098 */ void* ProcessStarterHelper;
    /* 0x009c */ uint32_t GdiDCAttributeList;
    /* 0x00a0 */ struct _RTL_CRITICAL_SECTION* LoaderLock;
    /* 0x00a4 */ uint32_t OSMajorVersion;
    /* 0x00a8 */ uint32_t OSMinorVersion;
    /* 0x00ac */ uint16_t OSBuildNumber;
    /* 0x00ae */ uint16_t OSCSDVersion;
    /* 0x00b0 */ uint32_t OSPlatformId;
    /* 0x00b4 */ uint32_t ImageSubsystem;
    /* 0x00b8 */ uint32_t ImageSubsystemMajorVersion;
    /* 0x00bc */ uint32_t ImageSubsystemMinorVersion;
    /* 0x00c0 */ uint32_t ActiveProcessAffinityMask;
    /* 0x00c4 */ uint32_t GdiHandleBuffer[34];
    /* 0x014c */ void* PostProcessInitRoutine /* function */;
    /* 0x0150 */ void* TlsExpansionBitmap;
    /* 0x0154 */ uint32_t TlsExpansionBitmapBits[32];
    /* 0x01d4 */ uint32_t SessionId;
    /* 0x01d8 */ union _ULARGE_INTEGER AppCompatFlags;
    /* 0x01e0 */ union _ULARGE_INTEGER AppCompatFlagsUser;
    /* 0x01e8 */ void* pShimData;
    /* 0x01ec */ void* AppCompatInfo;
    /* 0x01f0 */ struct _UNICODE_STRING CSDVersion;
    /* 0x01f8 */ const struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
    /* 0x01fc */ struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
    /* 0x0200 */ const struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
    /* 0x0204 */ struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
    /* 0x0208 */ uint32_t MinimumStackCommit;
    /* 0x020c */ struct _FLS_CALLBACK_INFO* FlsCallback;
    /* 0x0210 */ struct _LIST_ENTRY FlsListHead;
    /* 0x0218 */ void* FlsBitmap;
    /* 0x021c */ uint32_t FlsBitmapBits[4];
    /* 0x022c */ uint32_t FlsHighIndex;
    /* 0x0230 */ void* WerRegistrationData;
    /* 0x0234 */ void* WerShipAssertPtr;
    /* 0x0238 */ void* pContextData;
    /* 0x023c */ void* pImageHeaderHash;
    union {
        /* 0x0240 */ uint32_t TracingFlags;
        struct /* bitfield */
        {
            /* 0x0240 */ uint32_t HeapTracingEnabled : 1; /* bit position: 0 */
            /* 0x0240 */ uint32_t CritSecTracingEnabled : 1; /* bit position: 1 */
            /* 0x0240 */ uint32_t SpareTracingBits : 30; /* bit position: 2 */
        }; /* bitfield */
    }; /* size: 0x0004 */
    /* 0x0244 */ int32_t __PADDING__[1];
} PEB, * PPEB; /* size: 0x0248 */
```

# Steps
___

>* git clone https://github.com/manurautela/pdbex-sample
>* cd pdbex-sample
>* launch pdbex-demo.sln with VS2019
>* build


# Windbg output
___

```
0:000> !teb
TEB at 010f4000
    ExceptionList:        012ffc4c
    StackBase:            01300000
    StackLimit:           012fd000
    SubSystemTib:         00000000
    FiberData:            00001e00
    ArbitraryUserPointer: 00000000
    Self:                 010f4000
    EnvironmentPointer:   00000000
    ClientId:             000030b8 . 00001534
    RpcHandle:            00000000
    Tls Storage:          010f402c
    PEB Address:          010f1000
    LastErrorValue:       0
    LastStatusValue:      c00700bb
    Count Owned Locks:    0
    HardErrorMode:        0
0:000> dd fs:[0x30] l1
0053:00000030  010f1000
0:000> dd fs:[0x18] l1
0053:00000018  010f4000
0:000> dv /v /t
012ff960          unsigned long dwTeb = 0x10f4000
012ff96c          unsigned long dwPeb = 0x10f1000
012ff990          struct _PEB _peb = struct _PEB
012ff984          unsigned long peb_x86 = 0x10f1000
012ff978          unsigned long teb_x86 = 0x10f4000
0:000> dx -r1 (*((pdbex_demo!_PEB *)0x12ff990))
(*((pdbex_demo!_PEB *)0x12ff990))                 [Type: _PEB]
    [+0x000] InheritedAddressSpace : 0x0 [Type: unsigned char]
    [+0x001] ReadImageFileExecOptions : 0x0 [Type: unsigned char]
    [+0x002] BeingDebugged    : 0x1 [Type: unsigned char]
    [+0x003] BitField         : 0x4 [Type: unsigned char]
    [+0x003 ( 0: 0)] ImageUsesLargePages : 0x0 [Type: unsigned char]
    [+0x003 ( 1: 1)] IsProtectedProcess : 0x0 [Type: unsigned char]
    [+0x003 ( 2: 2)] IsLegacyProcess  : 0x1 [Type: unsigned char]
    [+0x003 ( 3: 3)] IsImageDynamicallyRelocated : 0x0 [Type: unsigned char]
    [+0x003 ( 4: 4)] SkipPatchingUser32Forwarders : 0x0 [Type: unsigned char]
    [+0x003 ( 7: 5)] SpareBits        : 0x0 [Type: unsigned char]
    [+0x004] Mutant           : 0xffffffff [Type: void *]
    [+0x008] ImageBaseAddress : 0xc40000 [Type: void *]
    [+0x00c] Ldr              : 0x77245d80 [Type: _PEB_LDR_DATA *]
    [+0x010] ProcessParameters : 0x14c6078 [Type: _RTL_USER_PROCESS_PARAMETERS *]
    [+0x014] SubSystemData    : 0x0 [Type: void *]
    [+0x018] ProcessHeap      : 0x14c0000 [Type: void *]
    [+0x01c] FastPebLock      : 0x77245b40 [Type: _RTL_CRITICAL_SECTION *]
    [+0x020] AtlThunkSListPtr : 0x0 [Type: void *]
    [+0x024] IFEOKey          : 0x0 [Type: void *]
    [+0x028] CrossProcessFlags : 0x0 [Type: unsigned int]
    [+0x028 ( 0: 0)] ProcessInJob     : 0x0 [Type: unsigned int]
    [+0x028 ( 1: 1)] ProcessInitializing : 0x0 [Type: unsigned int]
    [+0x028 ( 2: 2)] ProcessUsingVEH  : 0x0 [Type: unsigned int]
    [+0x028 ( 3: 3)] ProcessUsingVCH  : 0x0 [Type: unsigned int]
    [+0x028 ( 4: 4)] ProcessUsingFTH  : 0x0 [Type: unsigned int]
    [+0x028 (31: 5)] ReservedBits0    : 0x0 [Type: unsigned int]
    [+0x02c] KernelCallbackTable : 0x0 [Type: void *]
    [+0x02c] UserSharedInfoPtr : 0x0 [Type: void *]
    [+0x030] SystemReserved   [Type: unsigned int [1]]
    [+0x034] AtlThunkSListPtr32 : 0x0 [Type: unsigned int]
    [+0x038] ApiSetMap        : 0xf00000 [Type: void *]
    [+0x03c] TlsExpansionCounter : 0x0 [Type: unsigned int]
    [+0x040] TlsBitmap        : 0x77245d30 [Type: void *]
    [+0x044] TlsBitmapBits    [Type: unsigned int [2]]
    [+0x04c] ReadOnlySharedMemoryBase : 0x7fdd0000 [Type: void *]
    [+0x050] HotpatchInformation : 0x0 [Type: void *]
    [+0x054] ReadOnlyStaticServerData : 0x7fdd0750 [Type: void * *]
    [+0x058] AnsiCodePageData : 0x7ff30000 [Type: void *]
    [+0x05c] OemCodePageData  : 0x7ff40228 [Type: void *]
    [+0x060] UnicodeCaseTableData : 0x7ff50650 [Type: void *]
    [+0x064] NumberOfProcessors : 0x8 [Type: unsigned int]
    [+0x068] NtGlobalFlag     : 0x470 [Type: unsigned int]
    [+0x06c] Padding_0        : 0x0 [Type: long]
    [+0x070] CriticalSectionTimeout : {-25920000000000} [Type: _LARGE_INTEGER]
    [+0x078] HeapSegmentReserve : 0x100000 [Type: unsigned int]
    [+0x07c] HeapSegmentCommit : 0x2000 [Type: unsigned int]
    [+0x080] HeapDeCommitTotalFreeThreshold : 0x10000 [Type: unsigned int]
    [+0x084] HeapDeCommitFreeBlockThreshold : 0x1000 [Type: unsigned int]
    [+0x088] NumberOfHeaps    : 0x1 [Type: unsigned int]
    [+0x08c] MaximumNumberOfHeaps : 0x10 [Type: unsigned int]
    [+0x090] ProcessHeaps     : 0x77244840 [Type: void * *]
    [+0x094] GdiSharedHandleTable : 0x0 [Type: void *]
    [+0x098] ProcessStarterHelper : 0x0 [Type: void *]
    [+0x09c] GdiDCAttributeList : 0x0 [Type: unsigned int]
    [+0x0a0] LoaderLock       : 0x77243390 [Type: _RTL_CRITICAL_SECTION *]
    [+0x0a4] OSMajorVersion   : 0xa [Type: unsigned int]
    [+0x0a8] OSMinorVersion   : 0x0 [Type: unsigned int]
    [+0x0ac] OSBuildNumber    : 0x4a63 [Type: unsigned short]
    [+0x0ae] OSCSDVersion     : 0x0 [Type: unsigned short]
    [+0x0b0] OSPlatformId     : 0x2 [Type: unsigned int]
    [+0x0b4] ImageSubsystem   : 0x3 [Type: unsigned int]
    [+0x0b8] ImageSubsystemMajorVersion : 0x6 [Type: unsigned int]
    [+0x0bc] ImageSubsystemMinorVersion : 0x0 [Type: unsigned int]
    [+0x0c0] ActiveProcessAffinityMask : 0xff [Type: unsigned int]
    [+0x0c4] GdiHandleBuffer  [Type: unsigned int [34]]
    [+0x14c] PostProcessInitRoutine : 0x0 [Type: void *]
    [+0x150] TlsExpansionBitmap : 0x77245d18 [Type: void *]
    [+0x154] TlsExpansionBitmapBits [Type: unsigned int [32]]
    [+0x1d4] SessionId        : 0x23 [Type: unsigned int]
    [+0x1d8] AppCompatFlags   : {0x0} [Type: _ULARGE_INTEGER]
    [+0x1e0] AppCompatFlagsUser : {0x0} [Type: _ULARGE_INTEGER]
    [+0x1e8] pShimData        : 0xf80000 [Type: void *]
    [+0x1ec] AppCompatInfo    : 0x0 [Type: void *]
    [+0x1f0] CSDVersion       [Type: _UNICODE_STRING]
    [+0x1f8] ActivationContextData : 0xf70000 [Type: _ACTIVATION_CONTEXT_DATA *]
    [+0x1fc] ProcessAssemblyStorageMap : 0x0 [Type: _ASSEMBLY_STORAGE_MAP *]
    [+0x200] SystemDefaultActivationContextData : 0xf60000 [Type: _ACTIVATION_CONTEXT_DATA *]
    [+0x204] SystemAssemblyStorageMap : 0x0 [Type: _ASSEMBLY_STORAGE_MAP *]
    [+0x208] MinimumStackCommit : 0x0 [Type: unsigned int]
    [+0x20c] FlsCallback      : 0x0 [Type: _FLS_CALLBACK_INFO *]
    [+0x210] FlsListHead      [Type: _LIST_ENTRY]
    [+0x218] FlsBitmap        : 0x0 [Type: void *]
    [+0x21c] FlsBitmapBits    [Type: unsigned int [4]]
    [+0x22c] FlsHighIndex     : 0x0 [Type: unsigned int]
    [+0x230] WerRegistrationData : 0x0 [Type: void *]
    [+0x234] WerShipAssertPtr : 0x0 [Type: void *]
    [+0x238] pContextData     : 0x0 [Type: void *]
    [+0x23c] pImageHeaderHash : 0x0 [Type: void *]
    [+0x240] TracingFlags     : 0x0 [Type: unsigned int]
    [+0x240 ( 0: 0)] HeapTracingEnabled : 0x0 [Type: unsigned int]
    [+0x240 ( 1: 1)] CritSecTracingEnabled : 0x0 [Type: unsigned int]
    [+0x240 (31: 2)] SpareTracingBits : 0x0 [Type: unsigned int]
    [+0x244] __PADDING__      [Type: int [1]]
0:000> dx -r1 ((pdbex_demo!_RTL_USER_PROCESS_PARAMETERS *)0x14c6078)
((pdbex_demo!_RTL_USER_PROCESS_PARAMETERS *)0x14c6078)                 : 0x14c6078 [Type: _RTL_USER_PROCESS_PARAMETERS *]
    [+0x000] MaximumLength    : 0x5b1e [Type: unsigned int]
    [+0x004] Length           : 0x5b1e [Type: unsigned int]
    [+0x008] Flags            : 0x2001 [Type: unsigned int]
    [+0x00c] DebugFlags       : 0x0 [Type: unsigned int]
    [+0x010] ConsoleHandle    : 0x90 [Type: void *]
    [+0x014] ConsoleFlags     : 0x0 [Type: unsigned int]
    [+0x018] StandardInput    : 0x9c [Type: void *]
    [+0x01c] StandardOutput   : 0xa0 [Type: void *]
    [+0x020] StandardError    : 0xa4 [Type: void *]
    [+0x024] CurrentDirectory [Type: _CURDIR]
    [+0x030] DllPath          [Type: _UNICODE_STRING]
    [+0x038] ImagePathName    [Type: _UNICODE_STRING]
    [+0x040] CommandLine      [Type: _UNICODE_STRING]
    [+0x048] Environment      : 0x14c0b80 [Type: void *]
    [+0x04c] StartingX        : 0x0 [Type: unsigned int]
    [+0x050] StartingY        : 0x0 [Type: unsigned int]
    [+0x054] CountX           : 0x0 [Type: unsigned int]
    [+0x058] CountY           : 0x0 [Type: unsigned int]
    [+0x05c] CountCharsX      : 0x0 [Type: unsigned int]
    [+0x060] CountCharsY      : 0x0 [Type: unsigned int]
    [+0x064] FillAttribute    : 0x0 [Type: unsigned int]
    [+0x068] WindowFlags      : 0x0 [Type: unsigned int]
    [+0x06c] ShowWindowFlags  : 0x0 [Type: unsigned int]
    [+0x070] WindowTitle      [Type: _UNICODE_STRING]
    [+0x078] DesktopInfo      [Type: _UNICODE_STRING]
    [+0x080] ShellInfo        [Type: _UNICODE_STRING]
    [+0x088] RuntimeData      [Type: _UNICODE_STRING]
    [+0x090] CurrentDirectores [Type: _RTL_DRIVE_LETTER_CURDIR [32]]
    [+0x290] EnvironmentSize  : 0x54de [Type: unsigned int]
    [+0x294] EnvironmentVersion : 0x4 [Type: unsigned int]
0:000> dx -r1 (*((pdbex_demo!_UNICODE_STRING *)0x14c60b0))
(*((pdbex_demo!_UNICODE_STRING *)0x14c60b0))                 [Type: _UNICODE_STRING]
    [+0x000] Length           : 0x70 [Type: unsigned short]
    [+0x002] MaximumLength    : 0x72 [Type: unsigned short]
    [+0x004] Buffer           : 0x14c6540 : 0x4a [Type: unsigned short *]
0:000> dx -r1 ((pdbex_demo!unsigned short *)0x14c6540)
((pdbex_demo!unsigned short *)0x14c6540)                 : 0x14c6540 : 0x4a [Type: unsigned short *]
    0x4a [Type: unsigned short]
0:000> du 0x14c6540  <--- The only thing we have to do in the end is the manually map to windows type
014c6540  "J:\dev\temp\pdbex-sample\pdbex-d"
014c6580  "emo\Debug\pdbex-demo.exe"

```

pdbex doesn't seem to map windows type so we might have to manually do the
needed casting at the end. It also shows even the offsets to structure members
that is really useful times.


