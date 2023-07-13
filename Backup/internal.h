#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntimage.h>



//
//NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process); //未公开的进行导出即可
//NTKERNELAPI VOID NTAPI KeAttachProcess(PEPROCESS Process);
//NTKERNELAPI VOID NTAPI KeDetachProcess();
//#define DWORD unsigned long
//用于自己删自己
typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;//这个成员把系统所有加载(可能是停止没被卸载)已经读取到内存中 我们关心第一个  我们要遍历链表 双链表 不管中间哪个节点都可以遍历整个链表 本驱动的驱动对象就是一个节点
	LIST_ENTRY InMemoryOrderLinks;//系统已经启动 没有被初始化 没有调用DriverEntry这个历程的时候 通过这个链表进程串接起来
	LIST_ENTRY InInitializationOrderLinks;//已经调用DriverEntry这个函数的所有驱动程序
	PVOID DllBase;
	PVOID EntryPoint;//驱动的进入点 DriverEntry
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;//驱动的满路径
	UNICODE_STRING BaseDllName;//不带路径的驱动名字
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

//用于干别人
#define SYSTEMPROCESSINFORMATION 5
//进程信息结构体 
typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG    WaitTime;
	PVOID    StartAddress;
	CLIENT_ID   ClientID;
	KPRIORITY   Priority;
	KPRIORITY   BasePriority;
	ULONG    ContextSwitchCount;
	ULONG    ThreadState;
	KWAIT_REASON  WaitReason;
	ULONG    Reserved; //Add
}SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES
{
	ULONG    NextEntryDelta;
	ULONG    ThreadCount;
	ULONG    Reserved[6];
	LARGE_INTEGER  CreateTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY   BasePriority;
	HANDLE   ProcessId;  //Modify
	HANDLE   InheritedFromProcessId;//Modify
	ULONG    HandleCount;
	ULONG    SessionId;
	ULONG_PTR  PageDirectoryBase;
	VM_COUNTERS VmCounters;
	SIZE_T    PrivatePageCount;//Add
	IO_COUNTERS  IoCounters; //windows 2000 only
	struct _SYSTEM_THREADS Threads[1];
}SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

//声明ZqQueryAyatemInformation
NTSTATUS ZwQuerySystemInformation(
	IN ULONG SystemInformationClass,  //处理进程信息,只需要处理类别为5的即可
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
);
