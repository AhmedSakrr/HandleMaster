#pragma once

#define WIN32_LEAN_AND_MEAN
#define NO_STRICT
#define NOMINMAX
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>

typedef struct _EPROCESS *PEPROCESS;
typedef struct _HANDLE_TABLE_ENTRY_INFO *PHANDLE_TABLE_ENTRY_INFO;
typedef PVOID EX_PUSH_LOCK;

typedef struct _HANDLE_TABLE_ENTRY
{
  union
  {
    PVOID Object;
    ULONG ObAttributes;
    PHANDLE_TABLE_ENTRY_INFO InfoTable;
    ULONGLONG Value;
  };
  union
  {
    ULONGLONG GrantedAccess;
    USHORT GrantedAccessIndex;
    ULONG NextFreeTableEntry;
  };
  USHORT CreatorBackTraceIndex;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;

typedef struct _HANDLE_TABLE
{
  ULONGLONG TableCode;
  PEPROCESS QuotaProcess;
  PVOID UniqueProcessId;
  EX_PUSH_LOCK HandleLock;
  LIST_ENTRY HandleTableList;
  EX_PUSH_LOCK HandleContentionEvent;
  PVOID DebugInfo;
  LONG ExtraInfoPages;
  union
  {
    ULONG Flags;
    struct
    {
      UCHAR StrictFIFO : 1;
    };
  };
  ULONG FirstFreeHandle;
  PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
  ULONG HandleCount;
  ULONG NextHandleNeedingPool;
  ULONG HandleCountHighWatermark;
} HANDLE_TABLE, *PHANDLE_TABLE;
