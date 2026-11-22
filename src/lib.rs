#[cfg(windows)]
mod win {
    use ipnet::IpNet;
    use std::ffi::c_void;
    use std::io;
    use std::net::SocketAddr;
    use windows::Win32::{
        Foundation::{CloseHandle, ERROR_OBJECT_ALREADY_EXISTS, FILETIME, HLOCAL, LocalFree},
        NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
            GetExtendedTcpTable, GetExtendedUdpTable, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
            MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_ROW, TCP_TABLE_OWNER_PID_CONNECTIONS,
            UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::{IpPrefixOriginManual, IpSuffixOriginManual, SOCKET, setsockopt},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                Thread32Next,
            },
            ProcessStatus::{
                GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
            },
            Threading::{
                GetCurrentProcess, GetProcessTimes, GetThreadDescription, GetThreadTimes,
                OpenProcess, OpenThread, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
                PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW,
                THREAD_QUERY_LIMITED_INFORMATION,
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
        let _ = unsafe { GetExtendedTcpTable(None, &mut size, false, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0) };
        if size == 0 { return None; }
        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedTcpTable(Some(buf.as_mut_ptr() as *mut c_void), &mut size, false, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0)
        };
        (ret == 0).then_some(buf)
    }

    pub fn get_extended_udp_table(family: u32) -> Option<Vec<u8>> {
        let mut size: u32 = 0;
        let _ = unsafe { GetExtendedUdpTable(None, &mut size, false, family, UDP_TABLE_OWNER_PID, 0) };
        if size == 0 { return None; }
        let mut buf = vec![0u8; size as usize];
        let ret = unsafe {
            GetExtendedUdpTable(Some(buf.as_mut_ptr() as *mut c_void), &mut size, false, family, UDP_TABLE_OWNER_PID, 0)
        };
        (ret == 0).then_some(buf)
    }

    pub fn query_process_image_path(pid: u32) -> Option<String> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let res = unsafe {
            QueryFullProcessImageNameW(handle, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buf.as_mut_ptr()), &mut len)
        };
        let _ = unsafe { CloseHandle(handle) };
        (res.is_ok() && len > 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }

    pub fn get_process_memory_mb(pid: u32) -> f64 {
        let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }) else {
            return 0.0;
        };
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        let ok = unsafe { GetProcessMemoryInfo(handle, &mut counters, counters.cb) }.is_ok();
        let _ = unsafe { CloseHandle(handle) };
        if ok { counters.WorkingSetSize as f64 / (1024.0 * 1024.0) } else { 0.0 }
    }

    fn filetime_to_u64(ft: FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }

    pub fn read_process_cpu_100ns() -> (u64, u64) {
        let (mut creation, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        let handle = unsafe { GetCurrentProcess() };
        if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }.is_ok() {
            (filetime_to_u64(kernel), filetime_to_u64(user))
        } else {
            (0, 0)
        }
    }

    pub fn read_threads_cpu_100ns() -> Vec<(u32, String, u64, u64)> {
        let mut out = Vec::new();
        let pid = std::process::id();
        let Ok(snap) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }) else {
            return out;
        };
        let mut te = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        if unsafe { Thread32First(snap, &mut te) }.is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    let tid = te.th32ThreadID;
                    if let Ok(h) = unsafe { OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) } {
                        let (mut c, mut e, mut k, mut u) = (
                            FILETIME::default(),
                            FILETIME::default(),
                            FILETIME::default(),
                            FILETIME::default(),
                        );
                        let (k_ns, u_ns) = if unsafe { GetThreadTimes(h, &mut c, &mut e, &mut k, &mut u) }.is_ok() {
                            (filetime_to_u64(k), filetime_to_u64(u))
                        } else {
                            (0, 0)
                        };
                        let name = match unsafe { GetThreadDescription(h) } {
                            Ok(pwstr) if !pwstr.is_null() => {
                                let s = unsafe { pwstr.to_string() }.unwrap_or_default();
                                let _ = unsafe { LocalFree( Some(HLOCAL(pwstr.0 as *mut c_void)) ) };
                                if s.is_empty() { format!("thread-{}", tid) } else { s }
                            }
                            _ => format!("thread-{}", tid),
                        };
                        let _ = unsafe { CloseHandle(h) };
                        out.push((tid, name, k_ns, u_ns));
                    }
                }
                if unsafe { Thread32Next(snap, &mut te) }.is_err() {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snap) };
        out
    }

    pub fn read_process_memory_mb() -> (f64, f64, f64) {
        let mut counters = PROCESS_MEMORY_COUNTERS_EX {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
            ..Default::default()
        };
        let handle = unsafe { GetCurrentProcess() };
        let ok = unsafe {
            GetProcessMemoryInfo(
                handle,
                (&mut counters as *mut PROCESS_MEMORY_COUNTERS_EX).cast::<PROCESS_MEMORY_COUNTERS>(),
                counters.cb,
            )
        }
        .is_ok();
        if ok {
            let mb = 1024.0 * 1024.0;
            (
                counters.WorkingSetSize as f64 / mb,
                counters.PrivateUsage as f64 / mb,
                counters.PeakWorkingSetSize as f64 / mb,
            )
        } else {
            (0.0, 0.0, 0.0)
        }
    }
}

#[cfg(windows)]
pub use win::*;
