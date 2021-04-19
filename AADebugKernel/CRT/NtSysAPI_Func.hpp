#pragma once
#include "Ntddk.hpp"
#include "NativeEnums.h"
#include "PEStructs.h"


typedef unsigned long       DWORD;
typedef int                 BOOL;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef float               FLOAT;
typedef int                 INT;
typedef unsigned int        UINT;
typedef unsigned int        *PUINT;
typedef PVOID* PPVOID;



//Struct
//-------------------------------------------
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	HANDLE Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG  ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;        // ProcessParameters
	UNICODE_STRING DllPath;         // ProcessParameters
	UNICODE_STRING ImagePathName;   // ProcessParameters
	UNICODE_STRING CommandLine;     // ProcessParameters
	PVOID Environment;              // NtAllocateVirtualMemory

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;     // ProcessParameters
	UNICODE_STRING DesktopInfo;     // ProcessParameters
	UNICODE_STRING ShellInfo;       // ProcessParameters
	UNICODE_STRING RuntimeData;     // ProcessParameters
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[RTL_MAX_DRIVE_LETTERS];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_ENTRY
{
	ULONG Attribute;    // PROC_THREAD_ATTRIBUTE_XXX
	SIZE_T Size;
	ULONG_PTR Value;
	ULONG Unknown;
} NT_PROC_THREAD_ATTRIBUTE_ENTRY, *NT_PPROC_THREAD_ATTRIBUTE_ENTRY;

typedef struct _NT_PROC_THREAD_ATTRIBUTE_LIST
{
	ULONG Length;
	NT_PROC_THREAD_ATTRIBUTE_ENTRY Entry[1];
} NT_PROC_THREAD_ATTRIBUTE_LIST, *PNT_PROC_THREAD_ATTRIBUTE_LIST;

#ifdef _AMD64_
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, *PPEB;
#else
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY    InLoadOrderLinks;
	LIST_ENTRY    InMemoryOrderLinks;
	LIST_ENTRY    InInitializationOrderLinks;
	PVOID            DllBase;
	PVOID            EntryPoint;
	ULONG            SizeOfImage;
	UNICODE_STRING    FullDllName;
	UNICODE_STRING     BaseDllName;
	ULONG            Flags;
	USHORT            LoadCount;
	USHORT            TlsIndex;
	PVOID            SectionPointer;
	ULONG            CheckSum;
	PVOID            LoadedImports;
	PVOID            EntryPointActivationContext;
	PVOID            PatchInformation;
	LIST_ENTRY    ForwarderLinks;
	LIST_ENTRY    ServiceTagLinks;
	LIST_ENTRY    StaticLinks;
	PVOID            ContextInformation;
	ULONG            OriginalBase;
	LARGE_INTEGER    LoadTime;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID PostProcessInitRoutine;//PPS_POST_PROCESS_INIT_ROUTINE
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} PEB, *PPEB;
#endif // _AMD64_

typedef struct _NON_PAGED_DEBUG_INFO
{
	USHORT      Signature;
	USHORT      Flags;
	ULONG       Size;
	USHORT      Machine;
	USHORT      Characteristics;
	ULONG       TimeDateStamp;
	ULONG       CheckSum;
	ULONG       SizeOfImage;
	ULONGLONG   ImageBase;
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

/// nt!_HARDWARE_PTE on x86 PAE-disabled Windows
struct HardwarePteX86 {
	ULONG valid : 1;               //!< [0]
	ULONG write : 1;               //!< [1]
	ULONG owner : 1;               //!< [2]
	ULONG write_through : 1;       //!< [3]
	ULONG cache_disable : 1;       //!< [4]
	ULONG accessed : 1;            //!< [5]
	ULONG dirty : 1;               //!< [6]
	ULONG large_page : 1;          //!< [7]
	ULONG global : 1;              //!< [8]
	ULONG copy_on_write : 1;       //!< [9]
	ULONG prototype : 1;           //!< [10]
	ULONG reserved0 : 1;           //!< [11]
	ULONG page_frame_number : 20;  //!< [12:31]
};

/// nt!_HARDWARE_PTE on x86 PAE-enabled Windows
struct HardwarePteX86Pae {
	ULONG64 valid : 1;               //!< [0]
	ULONG64 write : 1;               //!< [1]
	ULONG64 owner : 1;               //!< [2]
	ULONG64 write_through : 1;       //!< [3]     PWT
	ULONG64 cache_disable : 1;       //!< [4]     PCD
	ULONG64 accessed : 1;            //!< [5]
	ULONG64 dirty : 1;               //!< [6]
	ULONG64 large_page : 1;          //!< [7]     PAT
	ULONG64 global : 1;              //!< [8]
	ULONG64 copy_on_write : 1;       //!< [9]
	ULONG64 prototype : 1;           //!< [10]
	ULONG64 reserved0 : 1;           //!< [11]
	ULONG64 page_frame_number : 26;  //!< [12:37]
	ULONG64 reserved1 : 25;          //!< [38:62]
	ULONG64 no_execute : 1;          //!< [63]
};

/// nt!_HARDWARE_PTE on x64 Windows
struct HardwarePteX64 {
	ULONG64 valid : 1;               //!< [0]
	ULONG64 write : 1;               //!< [1]
	ULONG64 owner : 1;               //!< [2]
	ULONG64 write_through : 1;       //!< [3]     PWT
	ULONG64 cache_disable : 1;       //!< [4]     PCD
	ULONG64 accessed : 1;            //!< [5]
	ULONG64 dirty : 1;               //!< [6]
	ULONG64 large_page : 1;          //!< [7]     PAT
	ULONG64 global : 1;              //!< [8]
	ULONG64 copy_on_write : 1;       //!< [9]
	ULONG64 prototype : 1;           //!< [10]
	ULONG64 reserved0 : 1;           //!< [11]
	ULONG64 page_frame_number : 36;  //!< [12:47]
	ULONG64 reserved1 : 4;           //!< [48:51]
	ULONG64 software_ws_index : 11;  //!< [52:62]
	ULONG64 no_execute : 1;          //!< [63]
};

#if defined(_X86_)
using HardwarePte = HardwarePteX86;
#elif defined(_AMD64_)
using HardwarePte = HardwarePteX64;
#endif

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;
typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;


typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID ServiceTableBase;
	PVOID ServiceCounterTableBase;
#if defined(_X86_)
	ULONG NumberOfServices;
#elif defined(_AMD64_)
	ULONG64	NumberOfServices;
#endif
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;


#ifdef _AMD64_
typedef struct _NOTIFY_INFO
{
	ULONG	Count; // 0号索引存放个数
	ULONG	CallbackType;
	ULONG64	CallbacksAddr;
	ULONG64	Cookie; // just work to cmpcallback
	CHAR	ImgPath[260];
}NOTIFY_INFO, *PNOTIFY_INFO;

typedef struct
{
	PVOID section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	char ImageName[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATIONEX
{
	ULONG Count;//内核中以加载的模块的个数 
	SYSTEM_MODULE Module[0];
} SYSTEM_MODULE_INFORMATIONEX, *PSYSTEM_MODULE_INFORMATIONEX;
#endif

#ifdef _AMD64_
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;         // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef struct _SYSTEM_MODULE_INFORMATION{
	HANDLE Section;
	PVOID MappedBase;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
#endif // _AMD64_

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _WOW64_PROCESS
{
	PPEB32 Wow64;
} WOW64_PROCESS, *PWOW64_PROCESS;



#if (NTDDI_VERSION == NTDDI_WINXP)
typedef struct _AUX_ACCESS_DATA {
	PPRIVILEGE_SET PrivilegesUsed;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK AccessesToAudit;
	ACCESS_MASK MaximumAuditMask;
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN CaseInsensitive;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	/*OB_DUMP_METHOD DumpProcedure;
	OB_OPEN_METHOD OpenProcedure;
	OB_CLOSE_METHOD CloseProcedure;
	OB_DELETE_METHOD DeleteProcedure;
	OB_PARSE_METHOD ParseProcedure;
	OB_SECURITY_METHOD SecurityProcedure;
	OB_QUERYNAME_METHOD QueryNameProcedure;
	OB_OKAYTOCLOSE_METHOD OkayToCloseProcedure;*/
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE { //XP
	ERESOURCE Mutex;
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;            // Copy from object header for convenience
	PVOID DefaultObject;
	ULONG Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
//#ifdef POOL_TAGGING
//	ULONG Key;
//#endif //POOL_TAGGING
//	ERESOURCE ObjectLocks[OBJECT_LOCK_COUNT];
} OBJECT_TYPE, *POBJECT_TYPE;
#endif

#if (NTDDI_VERSION == NTDDI_WIN7)
typedef struct _AUX_ACCESS_DATA
{
	/* 0x0000 */ struct _PRIVILEGE_SET* PrivilegesUsed;
	/* 0x0008 */ struct _GENERIC_MAPPING GenericMapping;
	/* 0x0018 */ unsigned long AccessesToAudit;
	/* 0x001c */ unsigned long MaximumAuditMask;
	/* 0x0020 */ struct _GUID TransactionId;
	/* 0x0030 */ void* NewSecurityDescriptor;
	/* 0x0038 */ void* ExistingSecurityDescriptor;
	/* 0x0040 */ void* ParentSecurityDescriptor;
	/* 0x0048 */ void* DeRefSecurityDescriptor /* function */;
	/* 0x0050 */ void* SDLock;
	/* 0x0058 */ struct _ACCESS_REASONS AccessReasons;
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA; /* size: 0x00d8 */

typedef struct _OBJECT_TYPE_INITIALIZER //7601
{
	/* 0x0000 */ unsigned short Length;
	union
	{
		/* 0x0002 */ unsigned char ObjectTypeFlags;
		struct /* bitfield */
		{
			/* 0x0002 */ unsigned char CaseInsensitive : 1; /* bit position: 0 */
			/* 0x0002 */ unsigned char UnnamedObjectsOnly : 1; /* bit position: 1 */
			/* 0x0002 */ unsigned char UseDefaultObject : 1; /* bit position: 2 */
			/* 0x0002 */ unsigned char SecurityRequired : 1; /* bit position: 3 */
			/* 0x0002 */ unsigned char MaintainHandleCount : 1; /* bit position: 4 */
			/* 0x0002 */ unsigned char MaintainTypeList : 1; /* bit position: 5 */
			/* 0x0002 */ unsigned char SupportsObjectCallbacks : 1; /* bit position: 6 */
		}; /* bitfield */
	}; /* size: 0x0001 */
	/* 0x0003 */ char Padding_1;
	/* 0x0004 */ unsigned long ObjectTypeCode;
	/* 0x0008 */ unsigned long InvalidAttributes;
	/* 0x000c */ struct _GENERIC_MAPPING GenericMapping;
	/* 0x001c */ unsigned long ValidAccessMask;
	/* 0x0020 */ unsigned long RetainAccess;
	/* 0x0024 */ enum _POOL_TYPE PoolType;
	/* 0x0028 */ unsigned long DefaultPagedPoolCharge;
	/* 0x002c */ unsigned long DefaultNonPagedPoolCharge;
	/* 0x0030 */ void* DumpProcedure /* function */;
	/* 0x0038 */ void* OpenProcedure /* function */;
	/* 0x0040 */ void* CloseProcedure /* function */;
	/* 0x0048 */ void* DeleteProcedure /* function */;
	/* 0x0050 */ void* ParseProcedure /* function */;
	/* 0x0058 */ void* SecurityProcedure /* function */;
	/* 0x0060 */ void* QueryNameProcedure /* function */;
	/* 0x0068 */ void* OkayToCloseProcedure /* function */;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER; /* size: 0x0070 */

typedef struct _OBJECT_TYPE//7601
{
	/* 0x0000 */ struct _LIST_ENTRY TypeList;
	/* 0x0010 */ struct _UNICODE_STRING Name;
	/* 0x0020 */ void* DefaultObject;
	/* 0x0028 */ unsigned char Index;
	/* 0x0029 */ char Padding_2[3];
	/* 0x002c */ unsigned long TotalNumberOfObjects;
	/* 0x0030 */ unsigned long TotalNumberOfHandles;
	/* 0x0034 */ unsigned long HighWaterNumberOfObjects;
	/* 0x0038 */ unsigned long HighWaterNumberOfHandles;
	/* 0x003c */ long Padding_3;
	/* 0x0040 */ struct _OBJECT_TYPE_INITIALIZER TypeInfo;
	///* 0x00b0 */ struct _EX_PUSH_LOCK TypeLock;
	///* 0x00b8 */ unsigned long Key;
	///* 0x00bc */ long Padding_4;
	///* 0x00c0 */ struct _LIST_ENTRY CallbackList;
} OBJECT_TYPE, *POBJECT_TYPE; /* size: 0x00d0 */

typedef struct _DEBUG_OBJECT
{
	/* 0x0000 */ struct _KEVENT EventsPresent;
	/* 0x0018 */ struct _FAST_MUTEX Mutex;
	/* 0x0050 */ struct _LIST_ENTRY EventList;
	/* 0x0060 */ unsigned long Flags;
	/* 0x0064 */ long __PADDING__[1];
} DEBUG_OBJECT, *PDEBUG_OBJECT; /* size: 0x0068 */

typedef enum _DBGKM_APINUMBER
{
	DbgKmExceptionApi = 0,
	DbgKmCreateThreadApi = 1,
	DbgKmCreateProcessApi = 2,
	DbgKmExitThreadApi = 3,
	DbgKmExitProcessApi = 4,
	DbgKmLoadDllApi = 5,
	DbgKmUnloadDllApi = 6,
	DbgKmErrorReportApi = 7,
	DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER, *PDBGKM_APINUMBER;

typedef struct _PORT_MESSAGE
{
	union
	{
		union
		{
			struct
			{
				/* 0x0000 */ short DataLength;
				/* 0x0002 */ short TotalLength;
			} /* size: 0x0004 */ s1;
			/* 0x0000 */ unsigned long Length;
		}; /* size: 0x0004 */
	} /* size: 0x0004 */ u1;
	union
	{
		union
		{
			struct
			{
				/* 0x0004 */ short Type;
				/* 0x0006 */ short DataInfoOffset;
			} /* size: 0x0004 */ s2;
			/* 0x0004 */ unsigned long ZeroInit;
		}; /* size: 0x0004 */
	} /* size: 0x0004 */ u2;
	union
	{
		/* 0x0008 */ struct _CLIENT_ID ClientId;
		/* 0x0008 */ double DoNotUseThisField;
	}; /* size: 0x0010 */
	/* 0x0018 */ unsigned long MessageId;
	/* 0x001c */ long Padding_41;
	union
	{
		/* 0x0020 */ unsigned __int64 ClientViewSize;
		struct
		{
			/* 0x0020 */ unsigned long CallbackId;
			/* 0x0024 */ long __PADDING__[1];
		}; /* size: 0x0008 */
	}; /* size: 0x0008 */
} PORT_MESSAGE, *PPORT_MESSAGE; /* size: 0x0028 */

typedef struct _DBGKM_EXCEPTION
{
	/* 0x0000 */ struct _EXCEPTION_RECORD ExceptionRecord;
	/* 0x0098 */ unsigned long FirstChance;
	/* 0x009c */ long __PADDING__[1];
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION; /* size: 0x00a0 */

typedef struct _DBGKM_CREATE_THREAD
{
	/* 0x0000 */ unsigned long SubSystemKey;
	/* 0x0004 */ long Padding_17;
	/* 0x0008 */ void* StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD; /* size: 0x0010 */

typedef struct _DBGKM_CREATE_PROCESS
{
	/* 0x0000 */ unsigned long SubSystemKey;
	/* 0x0004 */ long Padding_18;
	/* 0x0008 */ void* FileHandle;
	/* 0x0010 */ void* BaseOfImage;
	/* 0x0018 */ unsigned long DebugInfoFileOffset;
	/* 0x001c */ unsigned long DebugInfoSize;
	/* 0x0020 */ struct _DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS; /* size: 0x0030 */

typedef struct _DBGKM_EXIT_THREAD
{
	/* 0x0000 */ long ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD; /* size: 0x0004 */

typedef struct _DBGKM_EXIT_PROCESS
{
	/* 0x0000 */ long ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS; /* size: 0x0004 */

typedef struct _DBGKM_LOAD_DLL
{
	/* 0x0000 */ void* FileHandle;
	/* 0x0008 */ void* BaseOfDll;
	/* 0x0010 */ unsigned long DebugInfoFileOffset;
	/* 0x0014 */ unsigned long DebugInfoSize;
	/* 0x0018 */ void* NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL; /* size: 0x0020 */

typedef struct _DBGKM_UNLOAD_DLL
{
	/* 0x0000 */ void* BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL; /* size: 0x0008 */

typedef struct _MI_EXTRA_IMAGE_INFORMATION
{
	/* 0x0000 */ unsigned long SizeOfHeaders;
	/* 0x0004 */ unsigned long SizeOfImage;
} MI_EXTRA_IMAGE_INFORMATION, *PMI_EXTRA_IMAGE_INFORMATION; /* size: 0x0008 */

typedef struct _SECTION_IMAGE_INFORMATION
{
	/* 0x0000 */ void* TransferAddress;
	/* 0x0008 */ unsigned long ZeroBits;
	/* 0x000c */ long Padding_491;
	/* 0x0010 */ unsigned __int64 MaximumStackSize;
	/* 0x0018 */ unsigned __int64 CommittedStackSize;
	/* 0x0020 */ unsigned long SubSystemType;
	union
	{
		struct
		{
			/* 0x0024 */ unsigned short SubSystemMinorVersion;
			/* 0x0026 */ unsigned short SubSystemMajorVersion;
		}; /* size: 0x0004 */
		/* 0x0024 */ unsigned long SubSystemVersion;
	}; /* size: 0x0004 */
	/* 0x0028 */ unsigned long GpValue;
	/* 0x002c */ unsigned short ImageCharacteristics;
	/* 0x002e */ unsigned short DllCharacteristics;
	/* 0x0030 */ unsigned short Machine;
	/* 0x0032 */ unsigned char ImageContainsCode;
	union
	{
		/* 0x0033 */ unsigned char ImageFlags;
		struct /* bitfield */
		{
			/* 0x0033 */ unsigned char ComPlusNativeReady : 1; /* bit position: 0 */
			/* 0x0033 */ unsigned char ComPlusILOnly : 1; /* bit position: 1 */
			/* 0x0033 */ unsigned char ImageDynamicallyRelocated : 1; /* bit position: 2 */
			/* 0x0033 */ unsigned char ImageMappedFlat : 1; /* bit position: 3 */
			/* 0x0033 */ unsigned char Reserved : 4; /* bit position: 4 */
		}; /* bitfield */
	}; /* size: 0x0001 */
	/* 0x0034 */ unsigned long LoaderFlags;
	/* 0x0038 */ unsigned long ImageFileSize;
	/* 0x003c */ unsigned long CheckSum;
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION; /* size: 0x0040 */

typedef struct _MI_SECTION_IMAGE_INFORMATION
{
	/* 0x0000 */ struct _SECTION_IMAGE_INFORMATION ExportedImageInformation;
	/* 0x0040 */ struct _MI_EXTRA_IMAGE_INFORMATION InternalImageInformation;
} MI_SECTION_IMAGE_INFORMATION, *PMI_SECTION_IMAGE_INFORMATION; /* size: 0x0048 */

typedef struct _DBGKM_ERROR_MSG
{
	/* 0x0000 */ struct _EXCEPTION_RECORD ExceptionRecord;
	/* 0x0098 */ struct _SECTION_IMAGE_INFORMATION ImageInfo;
	union
	{
		/* 0x00d8 */ unsigned long Flags;
		struct /* bitfield */
		{
			/* 0x00d8 */ unsigned long IsProtectedProcess : 1; /* bit position: 0 */
			/* 0x00d8 */ unsigned long IsWow64Process : 1; /* bit position: 1 */
			/* 0x00d8 */ unsigned long IsFilterMessage : 1; /* bit position: 2 */
			/* 0x00d8 */ unsigned long SpareBits : 29; /* bit position: 3 */
		}; /* bitfield */
	}; /* size: 0x0004 */
	/* 0x00dc */ long __PADDING__[1];
} DBGKM_ERROR_MSG, *PDBGKM_ERROR_MSG; /* size: 0x00e0 */

typedef struct _DBGKM_APIMSG
{
	/* 0x0000 */ struct _PORT_MESSAGE h;
	/* 0x0028 */ enum _DBGKM_APINUMBER ApiNumber;
	/* 0x002c */ long ReturnedStatus;
	union
	{
		union
		{
			/* 0x0030 */ struct _DBGKM_EXCEPTION Exception;
			/* 0x0030 */ struct _DBGKM_CREATE_THREAD CreateThread;
			/* 0x0030 */ struct _DBGKM_CREATE_PROCESS CreateProcessInfo;
			/* 0x0030 */ struct _DBGKM_EXIT_THREAD ExitThread;
			/* 0x0030 */ struct _DBGKM_EXIT_PROCESS ExitProcess;
			/* 0x0030 */ struct _DBGKM_LOAD_DLL LoadDll;
			/* 0x0030 */ struct _DBGKM_UNLOAD_DLL UnloadDll;
			/* 0x0030 */ struct _DBGKM_ERROR_MSG ErrorMsg;
		}; /* size: 0x00e0 */
	} /* size: 0x00e0 */ u;
} DBGKM_APIMSG, *PDBGKM_APIMSG; /* size: 0x0110 */

typedef struct _DEBUG_EVENT
{
	/* 0x0000 */ struct _LIST_ENTRY EventList;
	/* 0x0010 */ struct _KEVENT ContinueEvent;
	/* 0x0028 */ struct _CLIENT_ID ClientId;
	/* 0x0038 */ PEPROCESS Process;
	/* 0x0040 */ PETHREAD Thread;
	/* 0x0048 */ long Status;
	/* 0x004c */ unsigned long Flags;
	/* 0x0050 */ PETHREAD BackoutThread;
	/* 0x0058 */ struct _DBGKM_APIMSG ApiMsg;
} DEBUG_EVENT, *PDEBUG_EVENT; /* size: 0x0168 */
#endif

typedef struct _GDI_TEB_BATCH {
	ULONG	Offset;
	UCHAR	Alignment[4];
	ULONG_PTR HDC;
	ULONG	Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
	ULONG Flags;
	PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;
							  // 17/3/2011 updated
typedef struct _TEB_ACTIVE_FRAME
{
	ULONG Flags;
	struct _TEB_ACTIVE_FRAME *Previous;
	PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB_ACTIVE_FRAME;

							  // 18/04/2011
typedef struct _TEB
{
	NT_TIB NtTib;

	PVOID EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID ActiveRpcHandle;
	PVOID ThreadLocalStoragePointer;
	PPEB ProcessEnvironmentBlock;

	ULONG LastErrorValue;
	ULONG CountOfOwnedCriticalSections;
	PVOID CsrClientThread;
	PVOID Win32ThreadInfo;
	ULONG User32Reserved[26];
	ULONG UserReserved[5];
	PVOID WOW32Reserved;
	LCID CurrentLocale;
	ULONG FpSoftwareStatusRegister;
	PVOID SystemReserved1[54];
	NTSTATUS ExceptionCode;
	PVOID ActivationContextStackPointer;
#if defined(_M_X64)
	UCHAR SpareBytes[24];
#else
	UCHAR SpareBytes[36];
#endif
	ULONG TxFsContext;

	GDI_TEB_BATCH GdiTebBatch;
	CLIENT_ID RealClientId;
	HANDLE GdiCachedProcessHandle;
	ULONG GdiClientPID;
	ULONG GdiClientTID;
	PVOID GdiThreadLocalInfo;
	ULONG_PTR Win32ClientInfo[62];
	PVOID glDispatchTable[233];
	ULONG_PTR glReserved1[29];
	PVOID glReserved2;
	PVOID glSectionInfo;
	PVOID glSection;
	PVOID glTable;
	PVOID glCurrentRC;
	PVOID glContext;

	NTSTATUS LastStatusValue;
	UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];

	PVOID DeallocationStack;
	PVOID TlsSlots[64];
	LIST_ENTRY TlsLinks;

	PVOID Vdm;
	PVOID ReservedForNtRpc;
	PVOID DbgSsReserved[2];

	ULONG HardErrorMode;
#if defined(_M_X64)
	PVOID Instrumentation[11];
#else
	PVOID Instrumentation[9];
#endif
	GUID ActivityId;

	PVOID SubProcessTag;
	PVOID EtwLocalData;
	PVOID EtwTraceData;
	PVOID WinSockData;
	ULONG GdiBatchCount;

	union
	{
		PROCESSOR_NUMBER CurrentIdealProcessor;
		ULONG IdealProcessorValue;
		struct
		{
			UCHAR ReservedPad0;
			UCHAR ReservedPad1;
			UCHAR ReservedPad2;
			UCHAR IdealProcessor;
		};
	};

	ULONG GuaranteedStackBytes;
	PVOID ReservedForPerf;
	PVOID ReservedForOle;
	ULONG WaitingOnLoaderLock;
	PVOID SavedPriorityState;
	ULONG_PTR SoftPatchPtr1;
	PVOID ThreadPoolData;
	PPVOID TlsExpansionSlots;
#if defined(_M_X64)
	PVOID DeallocationBStore;
	PVOID BStoreLimit;
#endif
	ULONG MuiGeneration;
	ULONG IsImpersonating;
	PVOID NlsCache;
	PVOID pShimData;
	ULONG HeapVirtualAffinity;
	HANDLE CurrentTransactionHandle;
	PTEB_ACTIVE_FRAME ActiveFrame;
	PVOID FlsData;

	PVOID PreferredLanguages;
	PVOID UserPrefLanguages;
	PVOID MergedPrefLanguages;
	ULONG MuiImpersonation;

	union
	{
		USHORT CrossTebFlags;
		USHORT SpareCrossTebBits : 16;
	};
	union
	{
		USHORT SameTebFlags;
		struct
		{
			USHORT SafeThunkCall : 1;
			USHORT InDebugPrint : 1;
			USHORT HasFiberData : 1;
			USHORT SkipThreadAttach : 1;
			USHORT WerInShipAssertCode : 1;
			USHORT RanProcessInit : 1;
			USHORT ClonedThread : 1;
			USHORT SuppressDebugMsg : 1;
			USHORT DisableUserStackWalk : 1;
			USHORT RtlExceptionAttached : 1;
			USHORT InitialThread : 1;
			USHORT SpareSameTebBits : 1;
		};
	};

	PVOID TxnScopeEnterCallback;
	PVOID TxnScopeExitCallback;
	PVOID TxnScopeContext;
	ULONG LockCount;
	ULONG SpareUlong0;
	PVOID ResourceRetValue;
} TEB, *PTEB;


//-------------------------------------------
extern "C" POBJECT_TYPE *IoDriverObjectType;

#define KeGetPreviousMode ExGetPreviousMode

//Function
//-------------------------------------------
extern "C" NTKERNELAPI NTSTATUS NTAPI NtQueryInformationProcess(
__in HANDLE ProcessHandle,
__in PROCESSINFOCLASS ProcessInformationClass,
__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
__in ULONG ProcessInformationLength,
__out_opt PULONG ReturnLength
);

#if defined(_X86_)
extern "C" NTKERNELAPI NTSTATUS NTAPI NtQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);
#elif defined(_AMD64_)
extern "C" NTKERNELAPI NTSTATUS NTAPI NtQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);
#endif

extern "C" NTKERNELAPI UCHAR* NTAPI PsGetProcessImageFileName(
	__in PEPROCESS Process
	);

extern "C" NTSYSAPI PVOID NTAPI RtlPcToFileHeader(
	PVOID PcValue,
	PVOID *BaseOfImage
	);

extern "C" NTKERNELAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(
	PVOID Base
	);

extern "C" NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
	);

extern "C" NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
	);

extern "C" NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(IN PEPROCESS Process);

extern "C" NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

extern "C" NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(
	PVOID ImageBase,
	BOOLEAN MappedAsImage,
	USHORT DirectoryEntry,
	PULONG Size
);

typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);
typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
	PRKAPC Apc,
	PKNORMAL_ROUTINE *NormalRoutine,
	PVOID *NormalContext,
	PVOID *SystemArgument1,
	PVOID *SystemArgument2
	);
typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(PRKAPC Apc);
extern "C" NTKERNELAPI VOID NTAPI KeInitializeApc(
	IN PKAPC Apc,
	IN PKTHREAD Thread,
	IN KAPC_ENVIRONMENT ApcStateIndex,
	IN PKKERNEL_ROUTINE KernelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine,
	IN PKNORMAL_ROUTINE NormalRoutine,
	IN KPROCESSOR_MODE ApcMode,
	IN PVOID NormalContext
);

extern "C" NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
	PKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

extern "C" NTKERNELAPI PVOID NTAPI PsGetCurrentProcessWow64Process();

extern "C" NTKERNELAPI BOOLEAN NTAPI KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

extern "C" NTKERNELAPI PVOID NTAPI PsGetThreadTeb(IN PETHREAD Thread);

extern "C" NTKERNELAPI NTSTATUS NTAPI SeCreateAccessState(
	IN PACCESS_STATE AccessState,
	IN PAUX_ACCESS_DATA AuxData,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping OPTIONAL
);

extern "C" NTSYSAPI VOID NTAPI SeDeleteAccessState(
	PACCESS_STATE AccessState
);

extern "C" NTSYSAPI NTSTATUS NTAPI ObOpenObjectByName(
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__inout_opt PVOID ParseContext,
	__out PHANDLE Handle
);

extern "C" NTSYSAPI NTSTATUS NTAPI PsLookupProcessThreadByCid(
	__in PCLIENT_ID Cid,
	__deref_opt_out PEPROCESS *Process,
	__deref_out PETHREAD *Thread
);

extern "C" NTSYSAPI PPEB NTAPI PsGetProcessPeb(
	__in PEPROCESS Process
	);

extern "C" NTSYSAPI PVOID NTAPI PsGetProcessDebugPort(
	__in PEPROCESS Process
	);

extern "C" NTSYSAPI NTSTATUS NTAPI ObCreateObject(
	_In_ KPROCESSOR_MODE ProbeMode,
	_In_ POBJECT_TYPE    ObjectType,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ KPROCESSOR_MODE OwnershipMode,
	_Inout_opt_  PVOID   ParseContext,
	_In_ ULONG           ObjectBodySize,
	_In_ ULONG           PagedPoolCharge,
	_In_ ULONG           NonPagedPoolCharge,
	_Out_ PVOID *        Object
);

extern "C" NTSYSAPI PVOID NTAPI PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);

extern "C" NTSYSAPI NTSTATUS NTAPI ZwFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN OPTIONAL PVOID BaseAddress,
	IN SIZE_T Length);

//extern "C" NTSYSAPI NTSTATUS NTAPI ObInsertObject(
//	_In_ PVOID              Object,
//	_In_opt_ PACCESS_STATE  PassedAccessState,
//	_In_opt_ ACCESS_MASK    DesiredAccess,
//	_In_ ULONG              ObjectPointerBias,
//	_Out_opt_ PVOID *       NewObject,
//	_Out_opt_ PHANDLE       Handle
//);
//extern "C" NTSYSAPI VOID NTAPI ProbeForWriteHandle(PVOID);
//extern "C" NTSYSAPI VOID NTAPI ProbeForReadSmallStructure(PVOID, ULONG, ULONG);
//-------------------------------------------

typedef NTSTATUS(NTAPI *_NtOpenProcessToken)(
__in HANDLE ProcessHandle,
__in ACCESS_MASK DesiredAccess,
__out PHANDLE TokenHandle
);

typedef NTSTATUS(NTAPI *_ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);

typedef VOID(NTAPI *_MiProcessLoaderEntry)(
	IN PVOID DataTableEntry,//PKLDR_DATA_TABLE_ENTRY
	IN LOGICAL Insert
	);

typedef NTSTATUS(*_NtReadVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL
	);

typedef NTSTATUS(*_NtProtectVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID *BaseAddress,
	IN OUT PSIZE_T ProtectSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

typedef NTSTATUS(*_NtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG64                NumberOfBytesToWrite,
	OUT PULONG64              NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(*_NtAllocateVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

typedef NTSTATUS(NTAPI *_NtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* _NtTerminateThread)(
	IN HANDLE ThreadHandle, IN NTSTATUS ExitStatus);

typedef VOID(NTAPI* _DbgkpWakeTarget)(
	IN PDEBUG_EVENT DebugEvent);

typedef NTSTATUS(NTAPI* _PsResumeThread)(
	IN PETHREAD Thread,
	OUT PULONG PreviousSuspendCount OPTIONAL);

typedef NTSTATUS(NTAPI* _PsSuspendThread)(
	_In_ PETHREAD aThread,
	_Out_opt_ PULONG aPreviousSuspendCount);

typedef NTSTATUS(NTAPI* _NtCreateDebugObject)(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);

typedef PETHREAD(NTAPI* _PsGetNextProcessThread)(
	IN PEPROCESS Process,
	IN PETHREAD Thread);

typedef VOID(NTAPI* _PsQuitNextProcessThread)(IN PETHREAD Thread);

typedef HANDLE(NTAPI* _DbgkpSectionToFileHandle)(IN PVOID SectionObject);

typedef NTSTATUS(NTAPI* _MmGetFileNameForAddress)(
	IN PVOID ProcessVa,
	OUT PUNICODE_STRING FileName);

#ifdef _AMD64_
typedef VOID(NTAPI* _KiDispatchException)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PKTRAP_FRAME TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance);
#else
typedef VOID(NTAPI* _KiDispatchException)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN void *ExceptionFrame,
	IN void *TrapFrame,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN FirstChance);
#endif // _AMD64_



typedef BOOLEAN(NTAPI* _DbgkForwardException)(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN BOOLEAN DebugException,
	IN BOOLEAN SecondChance);

typedef BOOLEAN(NTAPI* _DbgkpSuspendProcess)(VOID);

typedef BOOLEAN(NTAPI* _KeThawAllThreads)(VOID);

typedef VOID(NTAPI* _DbgkCreateThread)(PETHREAD Thread, PVOID StartAddress);

#ifdef _AMD64_
typedef VOID(NTAPI* _DbgkMapViewOfSection)(
	PEPROCESS Process,
	void *SectionObject,
	void *BaseAddress,
	unsigned int SectionOffset,
	unsigned __int64 ViewSize);
#else
typedef VOID(NTAPI* _DbgkMapViewOfSection)(
	IN HANDLE SectionHandle,
	IN PVOID BaseAddress,
	IN ULONG SectionOffset,
	IN ULONG_PTR ViewSize);
#endif // _AMD64_



typedef VOID(NTAPI* _DbgkUnMapViewOfSection)(IN PVOID BaseAddress);

typedef NTSTATUS(NTAPI* _PspCreateProcess)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess OPTIONAL,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel);

typedef VOID(NTAPI* _DbgkpMarkProcessPeb)(PEPROCESS Process);

typedef NTSTATUS(NTAPI* _NtCreateUserProcess)(
	PHANDLE ProcessHandle,
	PETHREAD ThreadHandle,
	ACCESS_MASK ProcessDesiredAccess,
	ACCESS_MASK ThreadDesiredAccess,
	_OBJECT_ATTRIBUTES *ProcessObjectAttributes,
	_OBJECT_ATTRIBUTES *ThreadObjectAttributes,
	ULONG ProcessFlags,
	ULONG ThreadFlags,
	_RTL_USER_PROCESS_PARAMETERS *ProcessParameters,
	void *CreateInfo,
	void *AttributeList);

typedef NTSTATUS(NTAPI* _DbgkpSuppressDbgMsg)(_TEB *Teb);

typedef NTSTATUS(NTAPI* _NtCreateDebugObject)(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);
//-------------------------------------------



//Offset
//-------------------------------------------
#define NtSysAPI_PrevMode_X64_Win7 0x1F6
#define NtSysAPI_PrevMode_X64_Win7SP1 0x1F6
#define NtSysAPI_PrevMode_X64_Win8 0x232
#define NtSysAPI_PrevMode_X64_Win8_1 0x232
#define NtSysAPI_PrevMode_X64_Win10_1511 0x232
#define NtSysAPI_PrevMode_X64_Win10_1607 0x232
#define NtSysAPI_PrevMode_X64_Win10_1607 0x232
#define NtSysAPI_PrevMode_X64_Win10_1703 0x232

#if (NTDDI_VERSION == NTDDI_WIN7)
#ifdef _AMD64_
#define NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7 0x0448
#define NtSysAPI_ETHREAD_RundownProtect_X64_Win7 0x0430
#define NtSysAPI_ETHREAD_StartAddress_X64_Win7 0x0430 
#define NtSysAPI_KTHREAD_Timer_X64_Win7 0x00c0

#define NtSysAPI_EPROCESS_Flags_X64_Win7 0x0440
#define NtSysAPI_EPROCESS_Wow64Process_X64_Win7 0x0320
#define NtSysAPI_EPROCESS_RundownProtect_X64_Win7 0x0178
#define NtSysAPI_EPROCESS_SectionObject_X64_Win7 0x0268
#define NtSysAPI_EPROCESS_SectionBaseAddress_X64_Win7 0x0270
#define NtSysAPI_EPROCESS_DebugPort_X64_Win7 0x01f0

#define NtSysAPI_KPROCESS_UserTime_X64_Win7 0x00fc

#else

#define NtSysAPI_ETHREAD_CrossThreadFlags_X64_Win7 0x280
#define NtSysAPI_ETHREAD_RundownProtect_X64_Win7 0x270
#define NtSysAPI_ETHREAD_StartAddress_X64_Win7 0x218 

#define NtSysAPI_KTHREAD_Timer_X64_Win7 0x00c0//error

#define NtSysAPI_EPROCESS_Flags_X64_Win7 0x270
#define NtSysAPI_EPROCESS_Wow64Process_X64_Win7 0x0320//error
#define NtSysAPI_EPROCESS_RundownProtect_X64_Win7 0x0b0
#define NtSysAPI_EPROCESS_SectionObject_X64_Win7 0x128
#define NtSysAPI_EPROCESS_SectionBaseAddress_X64_Win7 0x12c
#define NtSysAPI_EPROCESS_DebugPort_X64_Win7 0x0ec

#define NtSysAPI_KPROCESS_UserTime_X64_Win7 0x08c

#endif // _AMD64_
#endif



//-------------------------------------------


#if (NTDDI_VERSION == NTDDI_WIN7)

#ifdef _AMD64_
#define NtSysAPI_SSDT_NtProtectVirtualMemory 0x004d
#define NtSysAPI_SSDT_NtCreateThreadEx_X64_Win7 0x00A5
#define NtSysAPI_SSDT_NtTerminateThread_X64_Win7 0x0050
#define NtSysAPI_SSDT_NtCreateDebugObject_X64_Win7 0x0090 
#else
#define NtSysAPI_SSDT_NtProtectVirtualMemory 0x00d7
#endif // _AMD64_

#endif

#define NtSysAPI_NtProtectVirtualMemory_X64_Win10_ALL 0x0050


