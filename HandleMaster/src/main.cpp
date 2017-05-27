#include "windefs.h"
#include <stdio.h>
#include <stdlib.h>

#include "process.hpp"

int main()
{
  try {
    auto pid = process::find(L"notepad++.exe");

    if(!pid)
      throw std::runtime_error("Process not running");

    // 
    // Open a handle WITHOUT read access, as proof of concept
    // 
    auto handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    if(!handle)
      throw std::runtime_error("Failed to open process");

    // 
    // Attach to the process that contains the handle we 
    // want to elevate (this is the current process on this case)
    // 
    if(process::attach(GetCurrentProcessId())) {
      // 
      // Use CPU-Z to elevate the handle access to PROCESS_ALL_ACCESS
      // 
      if(!process::grant_handle_access(handle, PROCESS_ALL_ACCESS))
        throw std::runtime_error("Failed to set handle access");

      process::detach();
    }

    // 
    // Use the now elevated handle to perform a query and some reads.
    // You can use this handle for pretty much anything you want from now on. :)
    // 
    ULONG return_len;
    PEB   process_peb;
    PROCESS_BASIC_INFORMATION process_info;
    RTL_USER_PROCESS_PARAMETERS process_parameters;
    WCHAR buffer[512];

    if(NtQueryInformationProcess(handle, ProcessBasicInformation, &process_info, sizeof(process_info), &return_len) < 0)
      throw std::runtime_error("NtQueryInformationProcess failed");

    if(!ReadProcessMemory(handle, process_info.PebBaseAddress, &process_peb, sizeof(process_peb), nullptr) ||
       !ReadProcessMemory(handle, process_peb.ProcessParameters, &process_parameters, sizeof(process_parameters), nullptr) ||
       !ReadProcessMemory(handle, process_parameters.CommandLine.Buffer, buffer, process_parameters.CommandLine.Length, nullptr))
      throw std::runtime_error("ReadProcessMemory failed");

    printf("CommandLine: %ws\n", buffer);

    CloseHandle(handle);
  } catch(const std::exception& ex) {
    fprintf(stderr, "%s\n", ex.what());
    fprintf(stderr, "GetLastError: %X\n", GetLastError());
  }

  getc(stdin);
  return 0;
}