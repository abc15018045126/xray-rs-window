#[cfg(windows)]
mod win {
    use ipnet::IpNet;
    use std::ffi::c_void;
    use std::io;
    use std::net::SocketAddr;
    use windows::Win32::{
        Foundation::{CloseHandle, ERROR_OBJECT_ALREADY_EXISTS},
        NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
            GetExtendedTcpTable, GetExtendedUdpTable, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
            MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW, TCP_TABLE_OWNER_PID_CONNECTIONS,
            UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::{IpPrefixOriginManual, IpSuffixOriginManual, SOCKET, setsockopt},
        System::{
            ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS},
            Threading::{
                OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW,
            },
        },
    };

    pub fn setsockopt_raw(raw_socket: usize, proto: i32, opt: i32, bytes: &[u8]) -> io::Result<()> {
        let errno = unsafe { setsockopt(SOCKET(raw_socket), proto, opt, Some(bytes)) };
        if errno != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    pub fn add_ip_forward_entry(iface_index: u32, dest: &IpNet, next_hop: SocketAddr, metric: u32) -> io::Result<bool> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = iface_index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: SocketAddr::new(dest.addr(), 0).into(),
            PrefixLength: dest.prefix_len(),
        };
        row.NextHop = next_hop.into();
        row.Metric = metric;
        if let Err(e) = unsafe { CreateIpForwardEntry2(&row) }.to_hresult().ok() {
            if e.code().0 == ERROR_OBJECT_ALREADY_EXISTS.0 as i32 || e.code().0 as u32 == 0x80071392 {
                return Ok(false);
            }
            return Err(io::Error::other(e.to_string()));
        }
        Ok(true)
    }

    pub fn delete_ip_forward_entry(iface_index: u32, dest: &IpNet, next_hop: SocketAddr) -> io::Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = iface_index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: SocketAddr::new(dest.addr(), 0).into(),
            PrefixLength: dest.prefix_len(),
        };
        row.NextHop = next_hop.into();
        unsafe { DeleteIpForwardEntry2(&row) }.to_hresult().ok().map_err(|e| io::Error::other(e.to_string()))
    }

    pub fn add_unicast_ip_address(iface_index: u32, addr_net: IpNet) -> io::Result<()> {
        let row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: iface_index,
            Address: SocketAddr::new(addr_net.addr(), 0).into(),
            OnLinkPrefixLength: addr_net.prefix_len(),
            PrefixOrigin: IpPrefixOriginManual,
            SuffixOrigin: IpSuffixOriginManual,
            ValidLifetime: 0xffffffff,
            PreferredLifetime: 0xffffffff,
            SkipAsSource: false,
            ..Default::default()
        };
        let res = unsafe { CreateUnicastIpAddressEntry(&row) }.to_hresult();
        if res.is_ok() || res == ERROR_OBJECT_ALREADY_EXISTS.to_hresult() {
            Ok(())
        } else {
            Err(io::Error::other(format!("failed to add address to tun interface: {}", res.message())))
        }
    }

    pub fn get_extended_tcp_table(family: u32) -> Option<Vec<u8>> {
        let mut size: u32 = 0;
        unsafe { let _ = GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0); }
        if size == 0 { return None; }
        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut c_void), &mut size, false, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        };
        (ret == 0).then_some(buf)
    }

    pub fn get_extended_udp_table(family: u32) -> Option<Vec<u8>> {
        let mut size: u32 = 0;
        unsafe { let _ = GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0); }
        if size == 0 { return None; }
        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(Some(buf.as_mut_ptr() as *mut c_void), &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
        };
        (ret == 0).then_some(buf)
    }

    pub fn query_process_image_path(pid: u32) -> Option<String> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let res = QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buf.as_mut_ptr()), &mut len);
            let _ = CloseHandle(handle);
            (res.is_ok() && len > 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
        }
    }

    pub fn get_process_memory_mb(pid: u32) -> f64 {
        unsafe {
            let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) else { return 0.0; };
            let mut counters = PROCESS_MEMORY_COUNTERS {
                cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
                ..Default::default()
            };
            let ok = GetProcessMemoryInfo(handle, &mut counters, counters.cb).is_ok();
            let _ = CloseHandle(handle);
            if ok { counters.WorkingSetSize as f64 / (1024.0 * 1024.0) } else { 0.0 }
        }
    }
}

#[cfg(windows)]
mod telemetry {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    #[allow(non_snake_case, clippy::upper_case_acronyms)]
    struct FILETIME {
        dwLowDateTime: u32,
        dwHighDateTime: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    #[allow(non_snake_case)]
    struct PROCESS_MEMORY_COUNTERS_EX {
        cb: u32,
        PageFaultCount: u32,
        PeakWorkingSetSize: usize,
        WorkingSetSize: usize,
        QuotaPeakPagedPoolUsage: usize,
        QuotaPagedPoolUsage: usize,
        QuotaPeakNonPagedPoolUsage: usize,
        QuotaNonPagedPoolUsage: usize,
        PagefileUsage: usize,
        PeakPagefileUsage: usize,
        PrivateUsage: usize,
    }

    #[repr(C)]
    #[derive(Default)]
    #[allow(non_snake_case)]
    struct THREADENTRY32 {
        dwSize: u32,
        cntUsage: u32,
        th32ThreadID: u32,
        th32OwnerProcessID: u32,
        tpBasePri: i32,
        tpDeltaPri: i32,
        dwFlags: u32,
    }

    const TH32CS_SNAPTHREAD: u32 = 0x0000_0004;
    const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
    const INVALID_HANDLE_VALUE: isize = -1;

    #[link(name = "kernel32")]
    #[link(name = "psapi")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn GetProcessTimes(hProcess: isize, lpCreationTime: *mut FILETIME, lpExitTime: *mut FILETIME, lpKernelTime: *mut FILETIME, lpUserTime: *mut FILETIME) -> i32;
        fn GetProcessMemoryInfo(hProcess: isize, ppsmemCounters: *mut PROCESS_MEMORY_COUNTERS_EX, cb: u32) -> i32;
        fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> isize;
        fn Thread32First(hSnapshot: isize, lpte: *mut THREADENTRY32) -> i32;
        fn Thread32Next(hSnapshot: isize, lpte: *mut THREADENTRY32) -> i32;
        fn OpenThread(dwDesiredAccess: u32, bInheritHandle: i32, dwThreadId: u32) -> isize;
        fn GetThreadTimes(hThread: isize, lpCreationTime: *mut FILETIME, lpExitTime: *mut FILETIME, lpKernelTime: *mut FILETIME, lpUserTime: *mut FILETIME) -> i32;
        fn GetThreadDescription(hThread: isize, ppszThreadDescription: *mut *mut u16) -> i32;
        fn LocalFree(hMem: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
        fn CloseHandle(hObject: isize) -> i32;
    }

    fn filetime_to_u64(ft: FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }

    pub fn read_process_cpu_100ns() -> (u64, u64) {
        let (mut creation, mut exit, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        unsafe {
            if GetProcessTimes(GetCurrentProcess(), &mut creation, &mut exit, &mut kernel, &mut user) != 0 {
                (filetime_to_u64(kernel), filetime_to_u64(user))
            } else {
                (0, 0)
            }
        }
    }

    pub fn read_threads_cpu_100ns() -> Vec<(u32, String, u64, u64)> {
        let mut out = Vec::new();
        let pid = std::process::id();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE || snap == 0 {
                return out;
            }
            let mut te = THREADENTRY32 { dwSize: std::mem::size_of::<THREADENTRY32>() as u32, ..Default::default() };
            if Thread32First(snap, &mut te) != 0 {
                loop {
                    if te.th32OwnerProcessID == pid {
                        let tid = te.th32ThreadID;
                        let h = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, 0, tid);
                        if h != 0 {
                            let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
                            let (k_ns, u_ns) = if GetThreadTimes(h, &mut c, &mut e, &mut k, &mut u) != 0 {
                                (filetime_to_u64(k), filetime_to_u64(u))
                            } else {
                                (0, 0)
                            };
                            let mut desc_ptr: *mut u16 = std::ptr::null_mut();
                            let name = if GetThreadDescription(h, &mut desc_ptr) >= 0 && !desc_ptr.is_null() {
                                let mut len = 0usize;
                                while *desc_ptr.add(len) != 0 && len < 256 {
                                    len += 1;
                                }
                                let s = String::from_utf16_lossy(std::slice::from_raw_parts(desc_ptr, len));
                                LocalFree(desc_ptr as *mut core::ffi::c_void);
                                if s.is_empty() { format!("thread-{}", tid) } else { s }
                            } else {
                                format!("thread-{}", tid)
                            };
                            CloseHandle(h);
                            out.push((tid, name, k_ns, u_ns));
                        }
                    }
                    if Thread32Next(snap, &mut te) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        out
    }

    pub fn read_process_memory_mb() -> (f64, f64, f64) {
        let mut counters = PROCESS_MEMORY_COUNTERS_EX { cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32, ..Default::default() };
        unsafe {
            if GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) != 0 {
                let mb = 1024.0 * 1024.0;
                (counters.WorkingSetSize as f64 / mb, counters.PrivateUsage as f64 / mb, counters.PeakWorkingSetSize as f64 / mb)
            } else {
                (0.0, 0.0, 0.0)
            }
        }
    }
}

#[cfg(windows)]
pub use telemetry::*;
#[cfg(windows)]
pub use win::*;
