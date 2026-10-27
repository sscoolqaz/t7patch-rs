//! The live Win32 and ntdll implementation of [`ThreadOps`], and the aligned
//! context buffer and terminal latch that go with it.

use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Wdk::System::Threading::{NtQueryInformationThread, ThreadBasicInformation};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, HANDLE, STATUS_INFO_LENGTH_MISMATCH,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64, GetThreadContext, ReadProcessMemory,
    SetThreadContext,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetProcessIdOfThread, GetThreadId,
    OpenThread, ResumeThread, Sleep, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    WaitForSingleObject,
};

use crate::{Context, FreezeError, IdSet, Liveness, NextThread, OpenError, ThreadOps};

/// `SYNCHRONIZE`, for a zero-timeout wait on a thread handle. windows-sys does not
/// re-export it under Threading.
const SYNCHRONIZE: u32 = 0x0010_0000;
/// Access a frozen-walk handle needs: a zero-timeout wait and a thread-id read.
const WALK_ACCESS: u32 = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION;
/// Access the freeze opens its threads with. `SET_CONTEXT` is needed because a
/// caller (`MinHook`) moves a suspended thread's instruction pointer.
const THREAD_ACCESS: u32 = THREAD_SUSPEND_RESUME
    | THREAD_GET_CONTEXT
    | THREAD_SET_CONTEXT
    | THREAD_QUERY_INFORMATION
    | SYNCHRONIZE;
const SUSPEND_FAILED: u32 = u32::MAX;
const MIN_PROCESS_BUFFER: usize = 256 * 1024;

windows_link::link!("ntdll.dll" "system" fn NtGetNextThread(process: HANDLE, thread: HANDLE, access: u32, attributes: u32, flags: u32, new_thread: *mut HANDLE) -> i32);

/// Set once a freeze anywhere in the process left a live thread suspended. Terminal.
static THAW_FAILED: AtomicBool = AtomicBool::new(false);

pub(crate) fn thaw_failed() -> bool {
    THAW_FAILED.load(Ordering::Acquire)
}

pub(crate) fn set_thaw_failed() {
    THAW_FAILED.store(true, Ordering::Release);
}

#[cfg(any(test, feature = "test-seams"))]
pub(crate) fn clear_thaw_failed() {
    THAW_FAILED.store(false, Ordering::Release);
}

/// A thread context buffer. `Get/SetThreadContext` need 16-byte alignment on x64,
/// which the `windows-sys` `CONTEXT` does not carry.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub(crate) struct AlignedContext(CONTEXT);

impl AlignedContext {
    pub(crate) fn captured() -> Self {
        // SAFETY: `CONTEXT` is plain data; all-zero is valid.
        let mut context = Self(unsafe { core::mem::zeroed::<CONTEXT>() });
        context.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
        context
    }

    pub(crate) fn rip(&self) -> usize {
        usize::try_from(self.0.Rip).unwrap_or(0)
    }

    pub(crate) fn rsp(&self) -> usize {
        usize::try_from(self.0.Rsp).unwrap_or(0)
    }

    pub(crate) fn registers(&self) -> [u64; 16] {
        let c = &self.0;
        [
            c.Rax, c.Rbx, c.Rcx, c.Rdx, c.Rsi, c.Rdi, c.Rbp, c.Rsp, c.R8, c.R9, c.R10, c.R11,
            c.R12, c.R13, c.R14, c.R15,
        ]
    }

    pub(crate) fn moved_to(&self, ip: usize) -> Self {
        let mut context = *self;
        context.0.ContextFlags = CONTEXT_CONTROL_AMD64;
        context.0.Rip = ip as u64;
        context
    }

    #[cfg(any(test, feature = "test-seams"))]
    pub(crate) fn set_test(&mut self, rip: usize, rsp: usize) {
        self.0.Rip = rip as u64;
        self.0.Rsp = rsp as u64;
    }

    #[cfg(any(test, feature = "test-seams"))]
    pub(crate) fn set_test_r13(&mut self, value: u64) {
        self.0.R13 = value;
    }

    #[cfg(any(test, feature = "test-seams"))]
    pub(crate) fn is_control_only(&self) -> bool {
        self.0.ContextFlags == CONTEXT_CONTROL_AMD64
    }
}

/// The live implementation. Owns the enumeration buffer, sized before any freeze.
pub struct LiveOps {
    process_id: u32,
    current_thread: u32,
    buffer: Vec<u64>,
    wine: bool,
}

impl LiveOps {
    /// Sizes the enumeration buffer with headroom and detects the host. Allocates,
    /// so it runs before any thread is suspended.
    ///
    /// # Errors
    ///
    /// Returns [`FreezeError::Enumerate`] if the process list cannot be sized.
    pub fn new() -> Result<Self, FreezeError> {
        // SAFETY: both queries take no arguments and cannot fail.
        let process_id = unsafe { GetCurrentProcessId() };
        // SAFETY: as above.
        let current_thread = unsafe { GetCurrentThreadId() };
        let wine = detect_wine();
        let mut bytes = MIN_PROCESS_BUFFER;
        for _ in 0..8 {
            let mut buffer = vec![0u64; bytes / 8];
            let mut needed = 0u32;
            let status = query_processes(&mut buffer, &mut needed);
            if status >= 0 {
                let used = usize::try_from(needed).unwrap_or(bytes);
                if used.saturating_mul(2) > bytes {
                    buffer = vec![0u64; used.saturating_mul(2).div_ceil(8)];
                }
                return Ok(Self {
                    process_id,
                    current_thread,
                    buffer,
                    wine,
                });
            }
            if status != STATUS_INFO_LENGTH_MISMATCH {
                return Err(FreezeError::Enumerate);
            }
            bytes = usize::try_from(needed)
                .unwrap_or(0)
                .max(bytes)
                .saturating_mul(2);
        }
        Err(FreezeError::Enumerate)
    }
}

fn detect_wine() -> bool {
    // SAFETY: a C string literal and a GetProcAddress lookup; no memory preconditions.
    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return false;
        }
        GetProcAddress(ntdll, c"wine_get_version".as_ptr().cast()).is_some()
    }
}

fn query_processes(buffer: &mut [u64], needed: &mut u32) -> i32 {
    let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: `buffer` is writable for `length` bytes and `needed` is a valid out-pointer.
    unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr().cast(),
            length,
            needed,
        )
    }
}

fn teb(handle: HANDLE) -> Option<usize> {
    // x64 THREAD_BASIC_INFORMATION is 0x30 bytes; TebBaseAddress is at +8.
    let mut information = [0u64; 6];
    let mut returned = 0u32;
    // SAFETY: the handle has THREAD_QUERY_INFORMATION and the buffer is 0x30 bytes.
    let status = unsafe {
        NtQueryInformationThread(
            handle,
            ThreadBasicInformation,
            information.as_mut_ptr().cast(),
            u32::try_from(size_of_val(&information)).unwrap_or(u32::MAX),
            &raw mut returned,
        )
    };
    if status < 0 {
        return None;
    }
    usize::try_from(information[1]).ok()
}

fn read_words_raw(address: usize, out: &mut [u64]) -> bool {
    let bytes = size_of_val(out);
    let mut copied = 0usize;
    // SAFETY: ReadProcessMemory validates the source range and fails instead of
    // faulting; `out` is writable for `bytes` bytes.
    let read = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const c_void,
            out.as_mut_ptr().cast(),
            bytes,
            &raw mut copied,
        )
    };
    read != 0 && copied == bytes
}

// x64 `SYSTEM_PROCESS_INFORMATION` and `SYSTEM_THREAD_INFORMATION` layout.
const PROCESS_NEXT_OFFSET: usize = 0x00;
const PROCESS_THREAD_COUNT: usize = 0x04;
const PROCESS_ID: usize = 0x50;
const PROCESS_ENTRY_SIZE: usize = 0x100;
const THREAD_ENTRY_SIZE: usize = 0x50;
const THREAD_CLIENT_ID_THREAD: usize = 0x30;

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

/// Collects the thread ids of `process_id`, except `skip`, from a
/// `SystemProcessInformation` buffer. Every read is bounds-checked.
///
/// # Errors
///
/// Returns [`FreezeError::Enumerate`] if the buffer is malformed or truncated.
pub fn parse_process_threads(
    bytes: &[u8],
    process_id: u32,
    skip: u32,
    ids: &mut IdSet,
) -> Result<(), FreezeError> {
    let mut offset = 0usize;
    loop {
        let next = read_u32(bytes, offset + PROCESS_NEXT_OFFSET).ok_or(FreezeError::Enumerate)?;
        let count = read_u32(bytes, offset + PROCESS_THREAD_COUNT).ok_or(FreezeError::Enumerate)?;
        let pid = read_u64(bytes, offset + PROCESS_ID).ok_or(FreezeError::Enumerate)?;
        if pid == u64::from(process_id) {
            let count = usize::try_from(count).map_err(|_| FreezeError::Enumerate)?;
            for index in 0..count {
                let entry = offset + PROCESS_ENTRY_SIZE + index * THREAD_ENTRY_SIZE;
                let tid = read_u64(bytes, entry + THREAD_CLIENT_ID_THREAD)
                    .ok_or(FreezeError::Enumerate)?;
                let tid = u32::try_from(tid).map_err(|_| FreezeError::Enumerate)?;
                if tid != skip {
                    ids.insert(tid)?;
                }
            }
            return Ok(());
        }
        if next == 0 {
            return Err(FreezeError::Enumerate);
        }
        offset = offset
            .checked_add(usize::try_from(next).map_err(|_| FreezeError::Enumerate)?)
            .ok_or(FreezeError::Enumerate)?;
    }
}

impl ThreadOps for LiveOps {
    type Handle = usize;

    fn enumerate(&mut self, ids: &mut IdSet) -> Result<(), FreezeError> {
        let mut needed = 0u32;
        let status = query_processes(&mut self.buffer, &mut needed);
        if status == STATUS_INFO_LENGTH_MISMATCH {
            return Err(FreezeError::BufferTooSmall);
        }
        if status < 0 {
            return Err(FreezeError::Enumerate);
        }
        // SAFETY: the buffer is a live `Vec<u64>`, so its bytes are initialized.
        let bytes = unsafe {
            core::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), self.buffer.len() * 8)
        };
        parse_process_threads(bytes, self.process_id, self.current_thread, ids)
    }

    fn fingerprint(&mut self) -> Option<usize> {
        // A size-0 query never allocates a buffer on Wine's Unix side and returns the
        // length it would need, which is a function of every process and thread in
        // the prefix. STATUS_INFO_LENGTH_MISMATCH with a nonzero length is success.
        let mut needed = 0u32;
        let status = query_processes(&mut [], &mut needed);
        if status == STATUS_INFO_LENGTH_MISMATCH && needed != 0 {
            Some(needed as usize)
        } else {
            None
        }
    }

    fn walks_when_frozen(&self) -> bool {
        self.wine
    }

    fn open(&mut self, id: u32) -> Result<usize, OpenError> {
        // SAFETY: OpenThread has no memory preconditions.
        let handle = unsafe { OpenThread(THREAD_ACCESS, 0, id) };
        if handle.is_null() {
            // SAFETY: reads this thread's last-error value.
            let last = unsafe { GetLastError() };
            return if last == ERROR_INVALID_PARAMETER {
                Err(OpenError::Gone)
            } else {
                Err(OpenError::Failed)
            };
        }
        // SAFETY: the handle has THREAD_QUERY_INFORMATION.
        match unsafe { GetProcessIdOfThread(handle) } {
            owner if owner == self.process_id => Ok(handle as usize),
            0 => {
                self.close(handle as usize);
                Err(OpenError::Failed)
            }
            _ => {
                self.close(handle as usize);
                Err(OpenError::Gone)
            }
        }
    }

    fn suspend(&mut self, handle: usize) -> bool {
        // SAFETY: the handle has THREAD_SUSPEND_RESUME.
        unsafe { SuspendThread(handle as HANDLE) != SUSPEND_FAILED }
    }

    fn resume(&mut self, handle: usize) -> bool {
        // SAFETY: as above, and the thread was suspended by us.
        unsafe { ResumeThread(handle as HANDLE) != SUSPEND_FAILED }
    }

    fn liveness(&mut self, handle: usize) -> Liveness {
        // SAFETY: the handle has SYNCHRONIZE; a zero timeout never blocks.
        match unsafe { WaitForSingleObject(handle as HANDLE, 0) } {
            WAIT_OBJECT_0 => Liveness::Exited,
            WAIT_TIMEOUT => Liveness::Running,
            _ => Liveness::Unknown,
        }
    }

    fn started(&mut self, handle: usize) -> Option<bool> {
        teb(handle as HANDLE).map(|teb| teb != 0)
    }

    fn capture(&mut self, handle: usize, context: &mut Context) -> bool {
        // SAFETY: the thread is suspended and the buffer is aligned.
        unsafe { GetThreadContext(handle as HANDLE, &raw mut context.0.0) != 0 }
    }

    fn set_context(&mut self, handle: usize, context: &Context) -> bool {
        // SAFETY: as above.
        unsafe { SetThreadContext(handle as HANDLE, &raw const context.0.0) != 0 }
    }

    fn stack_base(&mut self, handle: usize) -> Option<usize> {
        let teb = teb(handle as HANDLE)?;
        if teb == 0 {
            return None;
        }
        // NT_TIB.StackBase is the second word of the TEB.
        let mut base = [0u64; 1];
        if !read_words_raw(teb.checked_add(8)?, &mut base) {
            return None;
        }
        usize::try_from(base[0]).ok()
    }

    fn read_words(&mut self, address: usize, out: &mut [u64]) -> bool {
        read_words_raw(address, out)
    }

    fn close(&mut self, handle: usize) {
        // SAFETY: every handle is opened by this ops and closed once.
        unsafe { CloseHandle(handle as HANDLE) };
    }

    fn pause(&mut self) {
        // SAFETY: Sleep takes a plain duration.
        unsafe { Sleep(1) };
    }

    fn next_thread(&mut self, cursor: Option<usize>) -> NextThread<usize> {
        let mut next: HANDLE = core::ptr::null_mut();
        // SAFETY: the process pseudo-handle is valid; `next` is a writable out-pointer.
        let status = unsafe {
            NtGetNextThread(
                GetCurrentProcess(),
                cursor.map_or(core::ptr::null_mut(), |handle| handle as HANDLE),
                WALK_ACCESS,
                0,
                0,
                &raw mut next,
            )
        };
        if status >= 0 && !next.is_null() {
            NextThread::Thread(next as usize)
        } else if status == STATUS_NO_MORE_ENTRIES {
            NextThread::Done
        } else {
            NextThread::Failed
        }
    }

    fn thread_id(&mut self, handle: usize) -> Option<u32> {
        // SAFETY: `handle` is an open thread handle.
        match unsafe { GetThreadId(handle as HANDLE) } {
            0 => None,
            id => Some(id),
        }
    }

    fn current_thread_id(&self) -> u32 {
        self.current_thread
    }
}

const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001A_u32.cast_signed();
