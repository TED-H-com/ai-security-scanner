//! Cross-process ownership for destructive data-directory operations.
//!
//! SQLite serializes database writes, but it cannot coordinate the desktop's
//! in-memory workers and credential capabilities with a standalone CLI. The
//! desktop therefore owns one exclusive lease for its lifetime. Read-only CLI
//! inspection remains available; destructive CLI maintenance must acquire the
//! same lease and fails closed while the desktop is running.

use crate::error::{AppError, AppResult};
use fs2::FileExt;
#[cfg(windows)]
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::{Mutex, mpsc};

const LEASE_FILENAME: &str = ".exclusive-process.lock";
pub(crate) const DATA_DIRECTORY_LEASE_CONTENTION_MESSAGE: &str = "another ai-security-scanner desktop or destructive maintenance operation owns this local data directory; close that desktop or let the exact operation finish, then retry";

#[cfg(windows)]
#[derive(Debug)]
struct WindowsOwnedMutex {
    release: Option<mpsc::Sender<()>>,
    owner: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl WindowsOwnedMutex {
    fn acquire(parent: &File, data_directory: &File) -> AppResult<Self> {
        let user_sid = windows_current_user_sid_string()?;
        let name = windows_mutex_name(parent, data_directory, &user_sid)?;
        let (ready_send, ready_receive) = mpsc::sync_channel::<AppResult<()>>(1);
        let (release_send, release_receive) = mpsc::channel::<()>();
        let owner = std::thread::Builder::new()
            .name("data-directory-lease".into())
            .spawn(move || {
                use windows_sys::Win32::Foundation::{
                    CloseHandle, WAIT_ABANDONED_0, WAIT_OBJECT_0, WAIT_TIMEOUT,
                };
                use windows_sys::Win32::System::Threading::{
                    CreateMutexW, ReleaseMutex, WaitForSingleObject,
                };

                let security = match windows_mutex_security(&user_sid) {
                    Ok(security) => security,
                    Err(error) => {
                        let _ = ready_send.send(Err(error.into()));
                        return;
                    }
                };
                // A protected current-user + LocalSystem DACL lets the normal
                // desktop and its elevated uninstaller coordinate without
                // granting another account the ability to open this mutex.
                let handle = unsafe { CreateMutexW(security.as_ptr(), 0, name.as_ptr()) };
                if handle.is_null() {
                    let _ = ready_send.send(Err(std::io::Error::last_os_error().into()));
                    return;
                }
                match windows_mutex_security_matches(handle, security.descriptor()) {
                    Ok(true) => {}
                    Ok(false) => {
                        unsafe {
                            CloseHandle(handle);
                        }
                        let _ = ready_send.send(Err(AppError::NotAuthorized(
                            "Windows data-directory mutex has an unexpected owner or access policy"
                                .into(),
                        )));
                        return;
                    }
                    Err(error) => {
                        unsafe {
                            CloseHandle(handle);
                        }
                        let _ = ready_send.send(Err(error.into()));
                        return;
                    }
                }
                match unsafe { WaitForSingleObject(handle, 0) } {
                    WAIT_OBJECT_0 | WAIT_ABANDONED_0 => {
                        if ready_send.send(Ok(())).is_ok() {
                            let _ = release_receive.recv();
                        }
                        unsafe {
                            let _ = ReleaseMutex(handle);
                            CloseHandle(handle);
                        }
                    }
                    WAIT_TIMEOUT => {
                        unsafe {
                            CloseHandle(handle);
                        }
                        let _ = ready_send.send(Err(AppError::NotAvailable(
                            DATA_DIRECTORY_LEASE_CONTENTION_MESSAGE.into(),
                        )));
                    }
                    _ => {
                        let error = std::io::Error::last_os_error();
                        unsafe {
                            CloseHandle(handle);
                        }
                        let _ = ready_send.send(Err(error.into()));
                    }
                }
            })?;
        match ready_receive.recv() {
            Ok(Ok(())) => Ok(Self {
                release: Some(release_send),
                owner: Some(owner),
            }),
            Ok(Err(error)) => {
                let _ = owner.join();
                Err(error)
            }
            Err(_) => {
                let _ = owner.join();
                Err(AppError::Internal(
                    "Windows data-directory mutex owner exited before reporting readiness".into(),
                ))
            }
        }
    }
}

#[cfg(windows)]
impl Drop for WindowsOwnedMutex {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}

#[cfg(windows)]
struct WindowsMutexSecurity {
    descriptor: *mut std::ffi::c_void,
    attributes: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl WindowsMutexSecurity {
    fn as_ptr(&self) -> *const windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
        &raw const self.attributes
    }

    fn descriptor(&self) -> windows_sys::Win32::Security::PSECURITY_DESCRIPTOR {
        self.descriptor
    }
}

#[cfg(windows)]
impl Drop for WindowsMutexSecurity {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::LocalFree;

        unsafe {
            LocalFree(self.descriptor);
        }
    }
}

#[cfg(windows)]
fn windows_mutex_security(user_sid: &str) -> std::io::Result<WindowsMutexSecurity> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    // MUTEX_ALL_ACCESS (0x001f0001) is explicit so validation observes the
    // same mask after the kernel's generic-right mapping.
    let sddl = format!("O:{user_sid}D:P(A;;0x001f0001;;;SY)(A;;0x001f0001;;;{user_sid})")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if descriptor.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned a null mutex security descriptor",
        ));
    }
    Ok(WindowsMutexSecurity {
        descriptor,
        attributes: SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        },
    })
}

#[cfg(windows)]
#[derive(Debug, PartialEq, Eq)]
struct WindowsMutexSecuritySemantics {
    owner: Vec<u8>,
    protected_dacl: bool,
    allowed: Vec<(Vec<u8>, u32)>,
}

#[cfg(windows)]
fn windows_security_descriptor_semantics(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> std::io::Result<WindowsMutexSecuritySemantics> {
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce, GetAclInformation,
        GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, IsValidSid, SE_DACL_PROTECTED,
    };

    let mut owner = std::ptr::null_mut();
    let mut owner_defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted) }
        == 0
        || owner.is_null()
        || unsafe { IsValidSid(owner) } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let owner_length = unsafe { GetLengthSid(owner) };
    if owner_length == 0 || owner_length > 256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows mutex owner SID was not bounded",
        ));
    }
    let owner = unsafe { std::slice::from_raw_parts(owner.cast(), owner_length as usize) }.to_vec();

    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let mut dacl_present = 0;
    let mut dacl = std::ptr::null_mut();
    let mut dacl_defaulted = 0;
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    } == 0
        || dacl_present == 0
        || dacl.is_null()
        || dacl_defaulted != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Windows mutex does not have one explicit DACL",
        ));
    }
    let mut acl_information = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&raw mut acl_information).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if acl_information.AceCount > 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows mutex DACL has an unexpected ACE count",
        ));
    }
    let mut allowed = Vec::with_capacity(acl_information.AceCount as usize);
    for index in 0..acl_information.AceCount {
        let mut raw_ace = std::ptr::null_mut();
        if unsafe { GetAce(dacl, index, &raw mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let ace = raw_ace.cast::<ACCESS_ALLOWED_ACE>();
        // ACCESS_ALLOWED_ACE_TYPE is zero. Every other ACE type fails closed.
        if unsafe { (*ace).Header.AceType } != 0
            || usize::from(unsafe { (*ace).Header.AceSize })
                < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Windows mutex DACL contains a non-allow or malformed ACE",
            ));
        }
        let sid = unsafe { std::ptr::addr_of!((*ace).SidStart).cast_mut().cast() };
        if unsafe { IsValidSid(sid) } == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows mutex DACL contains an invalid SID",
            ));
        }
        let sid_length = unsafe { GetLengthSid(sid) };
        if sid_length == 0 || sid_length > 256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Windows mutex DACL SID was not bounded",
            ));
        }
        allowed.push((
            unsafe { std::slice::from_raw_parts(sid.cast(), sid_length as usize) }.to_vec(),
            unsafe { (*ace).Mask },
        ));
    }
    allowed.sort_unstable();
    Ok(WindowsMutexSecuritySemantics {
        owner,
        protected_dacl: control & SE_DACL_PROTECTED != 0,
        allowed,
    })
}

#[cfg(windows)]
fn windows_mutex_security_matches(
    handle: windows_sys::Win32::Foundation::HANDLE,
    expected: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> std::io::Result<bool> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};

    let mut actual = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut actual,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    if actual.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned a null mutex security descriptor",
        ));
    }
    let actual_semantics = windows_security_descriptor_semantics(actual);
    unsafe {
        LocalFree(actual);
    }
    Ok(actual_semantics? == windows_security_descriptor_semantics(expected)?)
}

#[cfg(windows)]
fn windows_current_user_sid_string() -> std::io::Result<String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetTokenInformation, IsValidSid, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut raw_token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut required = 0_u32;
    let probe = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut required,
        )
    };
    let probe_error = std::io::Error::last_os_error();
    if probe != 0
        || required < std::mem::size_of::<TOKEN_USER>() as u32
        || probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(probe_error);
    }
    let mut token_information =
        vec![0_usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            token_information.as_mut_ptr().cast(),
            required,
            &raw mut required,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let token_user = unsafe { &*token_information.as_ptr().cast::<TOKEN_USER>() };
    if token_user.User.Sid.is_null() || unsafe { IsValidSid(token_user.User.Sid) } == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned an invalid current-user SID",
        ));
    }
    let mut raw_string = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &raw mut raw_string) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if raw_string.is_null() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned a null current-user SID string",
        ));
    }
    let mut length = 0_usize;
    while length < 256 && unsafe { *raw_string.add(length) } != 0 {
        length += 1;
    }
    let sid = if length == 256 {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows current-user SID string was not bounded",
        ))
    } else {
        Ok(String::from_utf16_lossy(unsafe {
            std::slice::from_raw_parts(raw_string, length)
        }))
    };
    unsafe {
        LocalFree(raw_string.cast());
    }
    sid
}

#[cfg(windows)]
fn windows_file_id(file: &File) -> std::io::Result<(u64, [u8; 16])> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };

    let mut information = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&raw mut information).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok((
        information.VolumeSerialNumber,
        information.FileId.Identifier,
    ))
}

#[cfg(windows)]
fn windows_normalized_volume_path(file: &File) -> std::io::Result<Vec<u16>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_GUID,
    };

    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), std::ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if required > 65_536 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows normalized data-directory path was not bounded",
        ));
    }
    let mut value = vec![0_u16; required as usize];
    let length = unsafe {
        GetFinalPathNameByHandleW(file.as_raw_handle(), value.as_mut_ptr(), required, flags)
    };
    if length == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length >= required || length as usize > value.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows normalized data-directory path changed while queried",
        ));
    }
    value.truncate(length as usize);
    if value.is_empty() || value.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned an invalid normalized data-directory path",
        ));
    }
    Ok(value)
}

#[cfg(windows)]
fn windows_mutex_name(
    parent: &File,
    data_directory: &File,
    user_sid: &str,
) -> std::io::Result<Vec<u16>> {
    let parent_identity = windows_file_id(parent)?;
    let normalized_path = windows_normalized_volume_path(data_directory)?;
    let leaf_start = normalized_path
        .iter()
        .rposition(|unit| *unit == b'\\' as u16 || *unit == b'/' as u16)
        .map_or(0, |position| position + 1);
    let canonical_leaf = normalized_path.get(leaf_start..).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows normalized data-directory path has no final component",
        )
    })?;
    if canonical_leaf.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows normalized data-directory path has an empty final component",
        ));
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlUpcaseUnicodeChar(source_character: u16) -> u16;
    }
    let mut digest = Sha256::new();
    digest.update(parent_identity.0.to_le_bytes());
    digest.update(parent_identity.1);
    digest.update(user_sid.as_bytes());
    // NT object and Win32 directory namespaces compare ordinary Windows file
    // names case-insensitively. Fold each UTF-16 code unit with the same native
    // NLS primitive before hashing so a case-only replacement created after
    // the original directory is staged cannot split the lifetime mutex key.
    for unit in canonical_leaf {
        let folded = unsafe { RtlUpcaseUnicodeChar(*unit) };
        digest.update(folded.to_le_bytes());
    }
    Ok(format!(
        "Global\\ai-security-scanner-data-directory-lease-{}",
        hex::encode(digest.finalize())
    )
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect())
}

#[cfg(windows)]
fn open_windows_directory_no_follow(path: &Path, allow_delete: bool) -> AppResult<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    let access = FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | if allow_delete { DELETE } else { 0 };
    let sharing =
        FILE_SHARE_READ | FILE_SHARE_WRITE | if allow_delete { FILE_SHARE_DELETE } else { 0 };
    options
        .access_mode(access)
        .share_mode(sharing)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let directory = options.open(path)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AppError::NotAuthorized(
            "process lease data directory must be a real non-reparse directory".into(),
        ));
    }
    Ok(directory)
}

#[derive(Debug)]
pub struct DataDirectoryExclusiveLease {
    #[cfg(not(windows))]
    _file: File,
    #[cfg(unix)]
    _sentinel: File,
    #[cfg(windows)]
    sentinel: Mutex<Option<File>>,
    #[cfg(windows)]
    data_directory: Mutex<Option<File>>,
    #[cfg(windows)]
    data_directory_identity: (u64, [u8; 16]),
    #[cfg(windows)]
    parent: File,
    #[cfg(windows)]
    _mutex: WindowsOwnedMutex,
    path: PathBuf,
}

impl DataDirectoryExclusiveLease {
    pub fn acquire(data_directory: &Path) -> AppResult<Self> {
        fs::create_dir_all(data_directory)?;
        #[cfg(windows)]
        let parent_path = data_directory.parent().ok_or_else(|| {
            AppError::NotAuthorized("process lease data directory has no real parent".into())
        })?;
        #[cfg(windows)]
        let parent = open_windows_directory_no_follow(parent_path, false)?;
        #[cfg(windows)]
        let data_directory_guard = open_windows_directory_no_follow(data_directory, false)?;
        #[cfg(windows)]
        let data_directory_identity = windows_file_id(&data_directory_guard)?;
        #[cfg(windows)]
        let windows_mutex = WindowsOwnedMutex::acquire(&parent, &data_directory_guard)?;
        let path = data_directory.join(LEASE_FILENAME);
        let sentinel = open_regular_lock_file(&path)?;
        #[cfg(windows)]
        {
            // The user-supplied path can be replaced through an ancestor while
            // handles are being opened. Once the non-delete-sharing sentinel
            // exists, re-resolve both namespace objects and require them to be
            // the exact objects from which the mutex identity was derived.
            let current_parent = open_windows_directory_no_follow(parent_path, false)?;
            let current_data_directory = open_windows_directory_no_follow(data_directory, false)?;
            if windows_file_id(&parent)? != windows_file_id(&current_parent)?
                || windows_file_id(&data_directory_guard)?
                    != windows_file_id(&current_data_directory)?
            {
                return Err(AppError::NotAuthorized(
                    "process lease data-directory namespace changed during acquisition".into(),
                ));
            }
        }
        #[cfg(unix)]
        let file = {
            let metadata = fs::symlink_metadata(data_directory)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(AppError::NotAuthorized(
                    "process lease data directory must be a real directory".into(),
                ));
            }
            File::open(data_directory)?
        };
        #[cfg(all(not(unix), not(windows)))]
        let file = sentinel;
        #[cfg(windows)]
        let lock_file = &sentinel;
        #[cfg(not(windows))]
        let lock_file = &file;
        if let Err(error) = FileExt::try_lock_exclusive(lock_file) {
            let contention = fs2::lock_contended_error();
            if error.kind() == contention.kind()
                && error.raw_os_error() == contention.raw_os_error()
            {
                return Err(AppError::NotAvailable(
                    DATA_DIRECTORY_LEASE_CONTENTION_MESSAGE.into(),
                ));
            }
            return Err(error.into());
        }
        Ok(Self {
            #[cfg(not(windows))]
            _file: file,
            #[cfg(unix)]
            _sentinel: sentinel,
            #[cfg(windows)]
            sentinel: Mutex::new(Some(sentinel)),
            #[cfg(windows)]
            data_directory: Mutex::new(Some(data_directory_guard)),
            #[cfg(windows)]
            data_directory_identity,
            #[cfg(windows)]
            parent,
            #[cfg(windows)]
            _mutex: windows_mutex,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(windows)]
    pub(crate) fn windows_parent(&self) -> &File {
        &self.parent
    }

    #[cfg(windows)]
    pub(crate) fn windows_directory_matches(&self, other: &File) -> AppResult<bool> {
        Ok(self.data_directory_identity == windows_file_id(other)?)
    }

    #[cfg(windows)]
    pub(crate) fn open_windows_staged_directory_for_identity_check(
        &self,
        path: &Path,
    ) -> AppResult<File> {
        // The pinned staging handle necessarily has DELETE access. A second
        // identity-check handle must therefore also share deletion or Windows
        // correctly rejects the open before FILE_ID can be compared.
        open_windows_directory_no_follow(path, true)
    }

    #[cfg(windows)]
    pub(crate) fn prepare_windows_directory_for_staging(&self) -> AppResult<File> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
        };

        let mut held = self
            .data_directory
            .lock()
            .map_err(|_| AppError::Internal("process lease directory lock was poisoned".into()))?;
        let ordinary = held.take().ok_or_else(|| {
            AppError::NotAvailable(
                "process lease directory was already prepared for staging".into(),
            )
        })?;
        let mut sentinel = self
            .sentinel
            .lock()
            .map_err(|_| AppError::Internal("process lease sentinel lock was poisoned".into()))?;
        let sentinel_file = sentinel.take().ok_or_else(|| {
            AppError::NotAvailable("process lease sentinel was already released".into())
        })?;

        if let Err(error) = FileExt::unlock(&sentinel_file) {
            *held = Some(ordinary);
            *sentinel = Some(sentinel_file);
            return Err(error.into());
        }
        let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                sentinel_file.as_raw_handle(),
                FileDispositionInfo,
                (&raw const disposition).cast(),
                std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            let _ = FileExt::try_lock_exclusive(&sentinel_file);
            *held = Some(ordinary);
            *sentinel = Some(sentinel_file);
            return Err(error.into());
        }
        drop(sentinel_file);
        drop(ordinary);

        // The ordinary root guard pins the root while the sentinel is removed.
        // After that guard is closed, open the DELETE-capable handle and
        // revalidate the stable FILE_ID before any destructive namespace
        // operation. A path swap can therefore only make staging fail closed.
        let directory_path = self.path.parent().ok_or_else(|| {
            AppError::NotAuthorized("process lease sentinel has no data-directory parent".into())
        })?;
        let staged = match open_windows_directory_no_follow(directory_path, true) {
            Ok(staged) => staged,
            Err(error) => {
                let restored = open_windows_directory_no_follow(directory_path, false).map_err(
                    |_| {
                        AppError::NotAuthorized(
                            "process lease could not restore its pinned root after a failed staging transition"
                                .into(),
                        )
                    },
                )?;
                if windows_file_id(&restored)? != self.data_directory_identity {
                    return Err(AppError::NotAuthorized(
                        "process lease data-directory identity changed during a failed staging transition"
                            .into(),
                    ));
                }
                let restored_sentinel = open_regular_lock_file(&self.path)?;
                FileExt::try_lock_exclusive(&restored_sentinel)?;
                *held = Some(restored);
                *sentinel = Some(restored_sentinel);
                return Err(error);
            }
        };
        if windows_file_id(&staged)? != self.data_directory_identity {
            return Err(AppError::NotAuthorized(
                "process lease data-directory identity changed before staging".into(),
            ));
        }
        Ok(staged)
    }

    #[cfg(windows)]
    pub(crate) fn windows_sentinel_is_held(&self) -> AppResult<bool> {
        let sentinel = self
            .sentinel
            .lock()
            .map_err(|_| AppError::Internal("process lease sentinel lock was poisoned".into()))?;
        Ok(sentinel.is_some())
    }
}

impl Drop for DataDirectoryExclusiveLease {
    fn drop(&mut self) {
        // On Unix, flock locks belong to the open file description. A child
        // forked by another thread can briefly inherit a duplicate descriptor,
        // so closing only our descriptor would not release the lease until the
        // child execs. Explicitly unlock while this owner is being dropped.
        #[cfg(not(windows))]
        let _ = FileExt::unlock(&self._file);
        #[cfg(windows)]
        if let Ok(sentinel) = self.sentinel.get_mut()
            && let Some(file) = sentinel.take()
        {
            let _ = FileExt::unlock(&file);
        }
    }
}

#[cfg(not(windows))]
fn open_regular_lock_file(path: &Path) -> AppResult<File> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(all(not(unix), not(windows)))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(AppError::NotAuthorized(
            "process lease path is not a regular file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(windows)]
fn open_regular_lock_file(path: &Path) -> AppResult<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .create(true)
        // Deliberately omit FILE_SHARE_DELETE. The sentinel cannot be renamed
        // or unlinked while this ordinary handle is held.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AppError::NotAuthorized(
            "process lease path is not a real non-reparse regular file".into(),
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    const CHILD_ROOT_ENV: &str = "AI_SECURITY_SCANNER_LEASE_TEST_CHILD_ROOT";
    #[cfg(windows)]
    const CHILD_MODE_ENV: &str = "AI_SECURITY_SCANNER_LEASE_TEST_CHILD_MODE";
    #[cfg(windows)]
    const CHILD_READY: &str = "AI_SECURITY_SCANNER_LEASE_CHILD_READY";

    #[cfg(windows)]
    fn windows_test_mutex_name(data_directory: &Path) -> Vec<u16> {
        let parent = open_windows_directory_no_follow(data_directory.parent().unwrap(), false)
            .expect("open mutex-test parent");
        let directory = open_windows_directory_no_follow(data_directory, false)
            .expect("open mutex-test directory");
        windows_mutex_name(
            &parent,
            &directory,
            &windows_current_user_sid_string().unwrap(),
        )
        .unwrap()
    }

    #[cfg(windows)]
    fn windows_short_path(path: &Path) -> std::io::Result<PathBuf> {
        use std::ffi::{OsStr, OsString};
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;

        let long = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let required = unsafe { GetShortPathNameW(long.as_ptr(), std::ptr::null_mut(), 0) };
        if required == 0 || required > 65_536 {
            return Err(std::io::Error::last_os_error());
        }
        let mut short = vec![0_u16; required as usize];
        let length = unsafe { GetShortPathNameW(long.as_ptr(), short.as_mut_ptr(), required) };
        if length == 0 || length >= required {
            return Err(std::io::Error::last_os_error());
        }
        short.truncate(length as usize);
        Ok(PathBuf::from(OsString::from_wide(&short)))
    }

    #[cfg(windows)]
    fn spawn_windows_lease_child(
        data_directory: &Path,
        mode: &str,
    ) -> (
        std::process::Child,
        std::io::BufReader<std::process::ChildStdout>,
    ) {
        use std::io::BufRead;
        use std::process::{Command, Stdio};

        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("process_lease::tests::windows_cross_process_owner_helper")
            .arg("--nocapture")
            .env(CHILD_ROOT_ENV, data_directory)
            .env(CHILD_MODE_ENV, mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "child exited before lease ready"
            );
            if line.contains(CHILD_READY) {
                break;
            }
        }
        (child, output)
    }

    #[cfg(windows)]
    fn release_windows_lease_child(child: &mut std::process::Child) {
        use std::io::Write;

        child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        child.stdin.as_mut().unwrap().flush().unwrap();
    }

    #[test]
    fn exclusive_lease_blocks_a_second_process_and_releases_on_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        assert_eq!(first.path(), temporary.path().join(LEASE_FILENAME));
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(temporary.path()),
            Err(AppError::NotAvailable(_))
        ));
        drop(first);
        DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn moving_the_sentinel_cannot_bypass_the_lifetime_mutex() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        let moved = temporary.path().join("moved-process-lease");

        // The ordinary sentinel is not delete-sharing, so an attacker cannot
        // rename it out from under a live lease.
        assert!(fs::rename(first.path(), &moved).is_err());
        // Staging deliberately removes that sentinel, but the namespace mutex
        // continues to exclude the original canonical directory name.
        let pinned_directory = first.prepare_windows_directory_for_staging().unwrap();
        assert!(DataDirectoryExclusiveLease::acquire(temporary.path()).is_err());

        drop(pinned_directory);
        drop(first);
        DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn case_only_replacement_after_staging_cannot_split_the_lifetime_mutex() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("ProductDataRoot");
        fs::create_dir(&root).unwrap();
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let pinned_directory = first.prepare_windows_directory_for_staging().unwrap();
        let staged = temporary.path().join("staged-original-product-root");
        fs::rename(&root, &staged).unwrap();

        let case_only_replacement = temporary.path().join("productdataroot");
        fs::create_dir(&case_only_replacement).unwrap();
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(&case_only_replacement),
            Err(AppError::NotAvailable(_))
        ));

        drop(pinned_directory);
        drop(first);
        let replacement = DataDirectoryExclusiveLease::acquire(&case_only_replacement).unwrap();
        drop(replacement);
    }

    #[cfg(windows)]
    #[test]
    fn windows_cross_process_owner_helper() {
        use std::io::Read;

        let Some(root) = std::env::var_os(CHILD_ROOT_ENV) else {
            return;
        };
        let mode = std::env::var(CHILD_MODE_ENV).unwrap();
        let lease = DataDirectoryExclusiveLease::acquire(Path::new(&root)).unwrap();
        println!("{CHILD_READY}");
        use std::io::Write;
        std::io::stdout().flush().unwrap();
        let mut release = [0_u8; 1];
        std::io::stdin().read_exact(&mut release).unwrap();
        if mode == "abort" {
            std::process::abort();
        }
        drop(lease);
    }

    #[cfg(windows)]
    #[test]
    fn lifetime_mutex_excludes_another_process_and_releases_cleanly() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("cross-process-root");
        let (mut child, _output) = spawn_windows_lease_child(&root, "release");

        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(&root),
            Err(AppError::NotAvailable(_))
        ));
        release_windows_lease_child(&mut child);
        assert!(child.wait().unwrap().success());
        drop(DataDirectoryExclusiveLease::acquire(&root).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn abandoned_cross_process_mutex_is_recovered_without_restarting_the_goal() {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        use windows_sys::Win32::System::Threading::OpenMutexW;

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("abandoned-cross-process-root");
        let (mut child, _output) = spawn_windows_lease_child(&root, "abort");
        let name = windows_test_mutex_name(&root);
        let raw = unsafe { OpenMutexW(SYNCHRONIZE, 0, name.as_ptr()) };
        assert!(
            !raw.is_null(),
            "open child mutex: {}",
            std::io::Error::last_os_error()
        );
        let _keepalive = unsafe { OwnedHandle::from_raw_handle(raw) };

        release_windows_lease_child(&mut child);
        assert!(!child.wait().unwrap().success());
        // The keepalive handle preserves the abandoned kernel object so this
        // acquisition necessarily exercises WAIT_ABANDONED rather than merely
        // creating a new mutex after process exit.
        drop(DataDirectoryExclusiveLease::acquire(&root).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn precreated_wrong_kernel_object_and_broad_dacl_fail_closed() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW};

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("precreated-object-root");
        fs::create_dir(&root).unwrap();
        let name = windows_test_mutex_name(&root);

        let event = unsafe { CreateEventW(std::ptr::null(), 0, 0, name.as_ptr()) };
        assert!(!event.is_null(), "create wrong named object fixture");
        assert!(DataDirectoryExclusiveLease::acquire(&root).is_err());
        unsafe { CloseHandle(event) };

        let broad = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        assert!(!broad.is_null(), "create default-DACL mutex fixture");
        let expected = windows_mutex_security(&windows_current_user_sid_string().unwrap()).unwrap();
        assert!(!windows_mutex_security_matches(broad, expected.descriptor()).unwrap());
        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(&root),
            Err(AppError::NotAuthorized(_))
        ));
        unsafe { CloseHandle(broad) };

        drop(DataDirectoryExclusiveLease::acquire(&root).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn case_short_name_trailing_dot_and_junction_aliases_cannot_split_the_lease() {
        use std::process::Command;

        let temporary = tempfile::tempdir().unwrap();
        let real_parent = temporary.path().join("RealParentWithLongName");
        let root = real_parent.join("ProductDataDirectoryWithLongName");
        fs::create_dir(&real_parent).unwrap();
        let first = DataDirectoryExclusiveLease::acquire(&root).unwrap();

        let case_alias = real_parent.join("productdatadirectorywithlongname");
        assert!(DataDirectoryExclusiveLease::acquire(&case_alias).is_err());
        let trailing_dot_alias = real_parent.join("ProductDataDirectoryWithLongName.");
        assert!(DataDirectoryExclusiveLease::acquire(&trailing_dot_alias).is_err());
        if let Ok(short_alias) = windows_short_path(&root) {
            assert!(DataDirectoryExclusiveLease::acquire(&short_alias).is_err());
        }

        let junction_parent = temporary.path().join("JunctionParent");
        let command = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
        let output = Command::new(command)
            .arg("/d")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(&junction_parent)
            .arg(&real_parent)
            .output()
            .unwrap();
        assert!(output.status.success(), "mklink fixture failed");
        assert!(
            DataDirectoryExclusiveLease::acquire(
                &junction_parent.join("ProductDataDirectoryWithLongName")
            )
            .is_err()
        );

        drop(first);
        fs::remove_dir(&junction_parent).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn pinned_parent_and_sentinel_prevent_root_or_parent_namespace_swaps() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().join("pinned-parent");
        let root = parent.join("pinned-root");
        fs::create_dir(&parent).unwrap();
        let lease = DataDirectoryExclusiveLease::acquire(&root).unwrap();
        let moved_root = parent.join("moved-root");
        let moved_parent = temporary.path().join("moved-parent");

        assert!(fs::rename(&root, &moved_root).is_err());
        assert!(fs::rename(&parent, &moved_parent).is_err());
        drop(lease);

        fs::rename(&root, &moved_root).unwrap();
        fs::rename(&moved_root, &root).unwrap();
        fs::rename(&parent, &moved_parent).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dropping_the_lease_unlocks_an_inherited_file_description() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        let inherited_descriptor = first._file.try_clone().unwrap();

        drop(first);

        DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        drop(inherited_descriptor);
    }

    #[cfg(unix)]
    #[test]
    fn lease_refuses_a_symlink_target() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, temporary.path().join(LEASE_FILENAME)).unwrap();

        assert!(DataDirectoryExclusiveLease::acquire(temporary.path()).is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"outside");
    }

    #[cfg(unix)]
    #[test]
    fn unlinking_the_sentinel_cannot_bypass_the_directory_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let first = DataDirectoryExclusiveLease::acquire(temporary.path()).unwrap();
        fs::remove_file(first.path()).unwrap();

        assert!(matches!(
            DataDirectoryExclusiveLease::acquire(temporary.path()),
            Err(AppError::NotAvailable(_))
        ));
    }
}
