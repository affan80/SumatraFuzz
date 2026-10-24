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

// Return a standalone SACL that marks a securable object low integrity while
// retaining the default no-write-up policy for callers below that level.
inline PACL CreateLowIntegrityMandatorySacl() {
  alignas(DWORD) BYTE sid_storage[SECURITY_MAX_SID_SIZE]{};
  DWORD sid_bytes = sizeof(sid_storage);
  if (!CreateWellKnownSid(WinLowLabelSid, nullptr, sid_storage, &sid_bytes)) return nullptr;
  const DWORD acl_bytes = static_cast<DWORD>(sizeof(ACL) +
      sizeof(SYSTEM_MANDATORY_LABEL_ACE) - sizeof(DWORD) + GetLengthSid(sid_storage));
  PACL acl = static_cast<PACL>(LocalAlloc(LPTR, acl_bytes));
  if (!acl) return nullptr;
  if (!InitializeAcl(acl, acl_bytes, ACL_REVISION) ||
      !AddMandatoryAce(acl, ACL_REVISION, 0, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, sid_storage)) {
    const DWORD error = GetLastError();
    LocalFree(acl);
    SetLastError(error);
    return nullptr;
  }
  return acl;
}

}  // namespace sumatrafuzz::supervisor

#endif  // _WIN32
