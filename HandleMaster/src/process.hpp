#pragma once

#include "windefs.h"
#include <cstdint>
#include <stdexcept>

namespace process
{
  std::uint32_t find(const wchar_t* proc);

  bool attach(std::uint32_t pid);
  void detach();

  bool grant_handle_access(HANDLE handle, ACCESS_MASK access_rights);

  bool read(PVOID base, PVOID buf, size_t len);
  bool write(PVOID base, PVOID buf, size_t len);

  template<typename T> 
  T read(PVOID base)
  {
    T temp = T{};
    read(base, &temp, sizeof(T));
    return temp;
  }
  template<typename T> 
  bool write(PVOID base, T value)
  {
    return write(base, &value, sizeof(T));
  }
};
