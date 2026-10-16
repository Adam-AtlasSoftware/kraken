use std::ffi::c_void;
use std::io;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SET_QUOTA, PROCESS_TERMINATE};

/// A job object that kills its processes when the last handle to it closes.
#[derive(Debug)]
pub struct ProcessGuard {
    job: HANDLE,
}

// SAFETY: a job handle is a kernel object reference; all the calls below are thread-safe.
unsafe impl Send for ProcessGuard {}
// SAFETY: see above.
unsafe impl Sync for ProcessGuard {}

impl ProcessGuard {
    /// Creates an unnamed job object with kill-on-close semantics.
    pub fn new() -> io::Result<Self> {
        // SAFETY: null attributes and name create a private anonymous job.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the structure is plain data; all-zero is a valid initial state.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `info` is valid for the stated size.
        let ok = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(info).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            let err = io::Error::last_os_error();
            // SAFETY: `job` is the handle created above.
            unsafe { CloseHandle(job) };
            return Err(err);
        }
        Ok(ProcessGuard { job })
    }

    /// Adds the live child `pid` to the job. The caller still owns the child, so its pid cannot
    /// have been reused.
    pub fn assign_pid(&self, pid: u32) -> io::Result<()> {
        // SAFETY: plain Win32 calls; the process handle is closed before returning.
        unsafe {
            let process = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid);
            if process.is_null() {
                return Err(io::Error::last_os_error());
            }
            let ok = AssignProcessToJobObject(self.job, process);
            let err = io::Error::last_os_error();
            CloseHandle(process);
            if ok == 0 { Err(err) } else { Ok(()) }
        }
    }

    /// Kills every process in the job immediately.
    pub fn terminate(&self) {
        // SAFETY: `self.job` is a live job handle.
        unsafe {
            TerminateJobObject(self.job, 1);
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        // SAFETY: closing the last handle triggers kill-on-close.
        unsafe {
            CloseHandle(self.job);
        }
    }
}

/// Total physical memory via `GlobalMemoryStatusEx`.
pub fn total_memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: the structure is plain data and `dwLength` is set as the API requires.
    unsafe {
        let mut st: MEMORYSTATUSEX = std::mem::zeroed();
        st.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        (GlobalMemoryStatusEx(&mut st) != 0).then_some(st.ullTotalPhys)
    }
}
