//! A private corpus namespace that WinAFL cannot redirect by adding `queue`.
#[cfg(windows)]
use std::fs::File;
use std::{
    fs,
    path::{Path, PathBuf},
};
use worker_protocol::WorkerError;

#[derive(Debug)]
pub(super) struct CorpusSnapshot {
    pub path: PathBuf,
    pub files: Vec<fs::File>,
    #[cfg(windows)]
    cleanup: Option<File>,
}

impl CorpusSnapshot {
    pub fn create(path: PathBuf) -> Result<Self, WorkerError> {
        #[cfg(windows)]
        {
            windows::create_private(&path)?;
            let cleanup = windows::cleanup_handle(&path);
            match cleanup {
                Ok(cleanup) => Ok(Self {
                    path,
                    files: Vec::new(),
                    cleanup: Some(cleanup),
                }),
                Err(error) => {
                    let _ = fs::remove_dir(&path);
                    Err(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .map_err(|_| WorkerError::InvalidConfig)?;
            Ok(Self {
                path,
                files: Vec::new(),
            })
        }
    }

    pub fn copy_seed(&self, source: &Path) -> Result<PathBuf, WorkerError> {
        let dest = self
            .path
            .join(source.file_name().ok_or(WorkerError::InvalidConfig)?);
        fs::copy(source, &dest).map_err(|_| WorkerError::UnverifiedToolchain)?;
        Ok(dest)
    }

    pub fn seal(&self) -> Result<(), WorkerError> {
        #[cfg(windows)]
        return windows::set_acl(self.cleanup.as_ref().unwrap(), windows::SEALED);
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o500))
                .map_err(|_| WorkerError::UnverifiedToolchain)
        }
    }
}

impl Drop for CorpusSnapshot {
    fn drop(&mut self) {
        self.files.clear();
        #[cfg(windows)]
        if let Some(handle) = self.cleanup.take() {
            // The handle was granted WRITE_DAC before sealing; it is not inherited by native children.
            if windows::set_acl(&handle, windows::PRIVATE).is_err() {
                return;
            }
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::{
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::CreateDirectoryW,
    };
    // OWNER RIGHTS suppresses implicit owner WRITE_DAC. Explicitly deny mutation even for an admin owner.
    pub const PRIVATE: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";
    pub const SEALED: &str = "D:P(D;;0x000d0156;;;OW)(A;;GRGX;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";

    struct Descriptor(PSECURITY_DESCRIPTOR);
    impl Descriptor {
        fn from_sddl(sddl: &str) -> Result<Self, WorkerError> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut descriptor = ptr::null_mut();
            // SAFETY: NUL-terminated input, valid out pointer, descriptor freed with LocalFree.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    1,
                    &mut descriptor,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(WorkerError::UnverifiedToolchain);
            }
            Ok(Self(descriptor))
        }
    }
    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocation returned by the SDDL conversion API.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    pub fn create_private(path: &Path) -> Result<(), WorkerError> {
        let descriptor = Descriptor::from_sddl(PRIVATE)?;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: descriptor and NUL-terminated path live throughout the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), &attrs) } == 0 {
            return Err(WorkerError::InvalidConfig);
        }
        Ok(())
    }
    pub fn cleanup_handle(path: &Path) -> Result<File, WorkerError> {
        fs::OpenOptions::new()
            .read(true)
            .access_mode(0x00040001) // WRITE_DAC | FILE_LIST_DIRECTORY
            .share_mode(3)
            .custom_flags(0x02000000 | 0x00200000)
            .open(path)
            .map_err(|_| WorkerError::UnverifiedToolchain)
    }
    pub fn set_acl(handle: &File, sddl: &str) -> Result<(), WorkerError> {
        let descriptor = Descriptor::from_sddl(sddl)?;
        // SAFETY: the owned directory handle has WRITE_DAC and the descriptor is live.
        if unsafe {
            SetKernelObjectSecurity(
                handle.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        } == 0
        {
            return Err(WorkerError::UnverifiedToolchain);
        }
        Ok(())
    }
}
