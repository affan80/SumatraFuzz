#pragma once

#ifdef _WIN32

#include <windows.h>
#include <aclapi.h>

#include <cstddef>

namespace sumatrafuzz::supervisor {

struct PrivateAclGrant {
  PSID sid;
  ACCESS_MASK access;
};

// Build a small ACL directly from validated SIDs so private kernel-object
// permissions do not depend on trustee-name resolution or ACL merging.
inline PACL CreatePrivateAccessAcl(const PrivateAclGrant* grants, size_t count) {
  if (!grants || count == 0 || count > 2) {
    SetLastError(ERROR_INVALID_PARAMETER);
    return nullptr;
  }

  size_t acl_size = sizeof(ACL);
  for (size_t index = 0; index < count; ++index) {
    if (!grants[index].sid || !IsValidSid(grants[index].sid)) {
      SetLastError(ERROR_INVALID_SID);
      return nullptr;
    }
    acl_size += sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + GetLengthSid(grants[index].sid);
  }
  if (acl_size > MAXWORD) {
    SetLastError(ERROR_INVALID_ACL);
    return nullptr;
  }

  PACL acl = static_cast<PACL>(LocalAlloc(LPTR, acl_size));
  if (!acl) return nullptr;
  if (!InitializeAcl(acl, static_cast<DWORD>(acl_size), ACL_REVISION)) {
    const DWORD error = GetLastError();
    LocalFree(acl);
    SetLastError(error);
    return nullptr;
  }
  for (size_t index = 0; index < count; ++index) {
    if (!AddAccessAllowedAceEx(acl, ACL_REVISION, 0, grants[index].access, grants[index].sid)) {
      const DWORD error = GetLastError();
      LocalFree(acl);
      SetLastError(error);
      return nullptr;
    }
  }
  return acl;
}

}  // namespace sumatrafuzz::supervisor

#endif  // _WIN32
