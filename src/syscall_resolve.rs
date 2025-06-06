use std::ptr::addr_of;
use std::arch::asm;
use core::slice;
use ntapi::ntldr::PLDR_DATA_TABLE_ENTRY;
use ntapi::FIELD_OFFSET;
use ntapi::ntpebteb::{PPEB, TEB};
use ntapi::ntpsapi::PPEB_LDR_DATA;

use winapi::shared::minwindef::{PWORD, PUSHORT};
use winapi::shared::ntdef::{NULL, PVOID, ULONG, PUCHAR, PLIST_ENTRY};
use winapi::um::winnt::{
    PIMAGE_DOS_HEADER, PIMAGE_DATA_DIRECTORY, PIMAGE_NT_HEADERS, PIMAGE_EXPORT_DIRECTORY,
    IMAGE_DATA_DIRECTORY
};

use crate::obf::dbj2_hash;

#[cfg(target_arch = "x86_64")]
pub unsafe fn __readgsqword(offset: u32) -> u64 {
    let out: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

#[cfg(target_arch = "x86")]
pub unsafe fn __readfsdword(offset: u32) -> u32 {
    let out: u32;
    asm!(
        "mov {:e}, fs:[{:e}]",
        lateout(reg) out,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    out
}

#[cfg(target_arch = "x86")]
pub unsafe fn is_wow64() -> bool {
    let addr = __readfsdword(0xC0);
    if addr != 0 {
        return true
    }
    false
}

pub unsafe fn nt_current_teb() -> *mut TEB {
    use winapi::um::winnt::NT_TIB;
    let teb_offset = FIELD_OFFSET!(NT_TIB, _Self) as u32;
    #[cfg(target_arch = "x86_64")] {
        __readgsqword(teb_offset) as *mut TEB
    }
    #[cfg(target_arch = "x86")] {
        __readfsdword(teb_offset) as *mut TEB
    }
}

pub unsafe fn nt_current_peb() -> PPEB {
    (*nt_current_teb()).ProcessEnvironmentBlock
}



pub fn get_module_addr(hash: ULONG) -> PVOID {
    let ldr: PPEB_LDR_DATA;
    let header: PLIST_ENTRY;
    let mut dt_entry: PLDR_DATA_TABLE_ENTRY;
    let mut entry: PLIST_ENTRY;
    let peb = unsafe { nt_current_peb() };

    unsafe {
        ldr = (*peb).Ldr;
        header = addr_of!((*ldr).InLoadOrderModuleList) as PLIST_ENTRY;
        entry = (*header).Flink;

        while entry != header {
            dt_entry = entry as PLDR_DATA_TABLE_ENTRY;
            let base_dll_name = &(*dt_entry).BaseDllName;
            let mod_name_ptr = base_dll_name.Buffer as *const u8;
            let mod_len = base_dll_name.Length as usize;
            let mod_name = slice::from_raw_parts(mod_name_ptr, mod_len);
            let mod_hash = dbj2_hash(mod_name) as ULONG;

            if mod_hash == hash {
                return (*dt_entry).DllBase;
            }

            entry = (*entry).Flink;
        }
    }
    NULL
}

pub fn get_function_addr(module_addr: PVOID, hash: u32) -> PVOID {
    let dos_header: PIMAGE_DOS_HEADER = module_addr as PIMAGE_DOS_HEADER;
    let mut nt_header: PIMAGE_NT_HEADERS;
    let data_dir: *const IMAGE_DATA_DIRECTORY;
    let exp_dir: PIMAGE_EXPORT_DIRECTORY;
    let addr_funcs: *const u32;
    let addr_names: *const u32;
    let addr_ords: *const u16;

    unsafe {
        // Verify DOS header magic number
        if (*dos_header).e_magic != 0x5A4D { // "MZ"
            return NULL;
        }

        nt_header = (dos_header as u64 + (*dos_header).e_lfanew as u64) as PIMAGE_NT_HEADERS;
        
        // Verify PE header signature
        if (*nt_header).Signature != 0x00004550 { // "PE\0\0"
            return NULL;
        }

        data_dir = &(*nt_header).OptionalHeader.DataDirectory[0];

        if (*data_dir).VirtualAddress == 0 || (*data_dir).Size == 0 {
            return NULL;
        }

        exp_dir = (dos_header as u64 + (*data_dir).VirtualAddress as u64) as PIMAGE_EXPORT_DIRECTORY;
        addr_funcs = (dos_header as u64 + (*exp_dir).AddressOfFunctions as u64) as *const u32;
        addr_names = (dos_header as u64 + (*exp_dir).AddressOfNames as u64) as *const u32;
        addr_ords = (dos_header as u64 + (*exp_dir).AddressOfNameOrdinals as u64) as *const u16;

        let num_names = (*exp_dir).NumberOfNames as usize;
        let name_list = slice::from_raw_parts(addr_names, num_names);
        let ord_list = slice::from_raw_parts(addr_ords, num_names);
        let func_list = slice::from_raw_parts(addr_funcs, (*exp_dir).NumberOfFunctions as usize);

        // Search by name
        for i in 0..num_names {
            let name_rva = name_list[i];
            let name_ptr = (dos_header as u64 + name_rva as u64) as *const u8;
            let name_len = get_cstr_len(name_ptr);
            let name = slice::from_raw_parts(name_ptr, name_len);
            
            if dbj2_hash(name) == hash {
                let ordinal = ord_list[i] as usize;
                if ordinal >= func_list.len() {
                    return NULL;
                }

                let func_rva = func_list[ordinal];
                let exp_dir_end = (*data_dir).VirtualAddress + (*data_dir).Size;

                // Check if this is a forwarded export
                if func_rva >= (*data_dir).VirtualAddress && func_rva < exp_dir_end {
                    // Handle forwarded export
                    let forward_str = (dos_header as u64 + func_rva as u64) as *const u8;
                    let forward_len = get_cstr_len(forward_str);
                    let forward_slice = slice::from_raw_parts(forward_str, forward_len);
                    let forward_str = match std::str::from_utf8(forward_slice) {
                        Ok(s) => s,
                        Err(_) => return NULL,
                    };

                    println!("{forward_str}");
                    let parts: Vec<&str> = forward_str.splitn(2, '.').collect();
                    if parts.len() != 2 {
                        return NULL;
                    }

                    let (dll_name, func_part) = (parts[0], parts[1]);

                    // Get target DLL
                    let dll_name_utf16: Vec<u16> = dll_name.encode_utf16().collect();
                    let dll_hash = dbj2_hash(unsafe {
                        slice::from_raw_parts(dll_name_utf16.as_ptr() as *const u8, dll_name_utf16.len() * 2)
                    }) as ULONG;

                    let mut target_dll = get_module_addr(dll_hash);
                    if target_dll.is_null() {
                        // Try to load the DLL if not found
                        let kernel32 = get_module_addr(dbj2_hash(b"kernel32.dll") as ULONG);
                        if kernel32.is_null() {
                            return NULL;
                        }

                        let load_library = get_function_addr(kernel32, dbj2_hash(b"LoadLibraryW") as u32);
                        if load_library.is_null() {
                            return NULL;
                        }

                        let load_library: unsafe extern "system" fn(*const u16) -> PVOID = std::mem::transmute(load_library);
                        target_dll = load_library(dll_name_utf16.as_ptr());
                        if target_dll.is_null() {
                            return NULL;
                        }
                    }

                    // Resolve function in target DLL
                    if func_part.starts_with('#') {
                        // By ordinal
                        let ordinal_str = &func_part[1..];
                        let ordinal = match ordinal_str.parse::<u16>() {
                            Ok(o) => o,
                            Err(_) => return NULL,
                        };

                        // Get function by ordinal from target DLL
                        let target_exp_dir = get_export_directory(target_dll);
                        if target_exp_dir.is_null() {
                            return NULL;
                        }

                        let ordinal_base = (*target_exp_dir).Base;
                        if u32::from(ordinal) < ordinal_base {
                            return NULL;
                        }

                        let func_index = (u32::from(ordinal) - ordinal_base) as usize;
                        let func_list = get_export_function_list(target_dll, target_exp_dir);
                        if func_index >= func_list.len() {
                            return NULL;
                        }

                        let func_rva = func_list[func_index];
                        return (target_dll as u64 + func_rva as u64) as PVOID;
                    } else {
                        // By name
                        let func_hash = dbj2_hash(func_part.as_bytes());
                        return get_function_addr(target_dll, func_hash);
                    }
                } else {
                    // Normal export
                    return (dos_header as u64 + func_rva as u64) as PVOID;
                }
            }
        }

        // If we get here, the function wasn't found by name, try by ordinal
        // (Note: This part would need the original ordinal-to-hash mapping)
    }
    NULL
}

unsafe fn get_export_directory(module_addr: PVOID) -> PIMAGE_EXPORT_DIRECTORY {
    let dos_header = module_addr as PIMAGE_DOS_HEADER;
    if (*dos_header).e_magic != 0x5A4D {
        return std::ptr::null_mut();
    }

    let nt_header = (dos_header as u64 + (*dos_header).e_lfanew as u64) as PIMAGE_NT_HEADERS;
    if (*nt_header).Signature != 0x00004550 {
        return std::ptr::null_mut();
    }

    let data_dir = &(*nt_header).OptionalHeader.DataDirectory[0];
    if data_dir.VirtualAddress == 0 || data_dir.Size == 0 {
        return std::ptr::null_mut();
    }

    (dos_header as u64 + data_dir.VirtualAddress as u64) as PIMAGE_EXPORT_DIRECTORY
}

unsafe fn get_export_function_list(module_addr: PVOID, exp_dir: PIMAGE_EXPORT_DIRECTORY) -> &'static [u32] {
    let dos_header = module_addr as PIMAGE_DOS_HEADER;
    let funcs = (dos_header as u64 + (*exp_dir).AddressOfFunctions as u64) as *const u32;
    slice::from_raw_parts(funcs, (*exp_dir).NumberOfFunctions as usize)
}

// Corrected get_cstr_len to use *const u8
pub fn get_cstr_len(pointer: *const u8) -> usize {
    let mut len = 0;
    unsafe {
        while *pointer.add(len) != 0 {
            len += 1;
        }
    }
    len
}
#[cfg(target_arch = "x86_64")]
#[cfg(all(feature = "_DIRECT_", not(feature = "_INDIRECT_")))]
pub fn get_ssn(hash: u32) -> u16 {
    let ntdll_addr : PVOID;
    let funct_addr : PVOID;
    let ssn        : u16;

    ntdll_addr = get_module_addr(crate::obf!("ntdll.dll"));
    funct_addr = get_function_addr(ntdll_addr, hash);
    unsafe {
        ssn = *((funct_addr as u64 + 4) as *const u16);
    }
    ssn
}

#[cfg(target_arch = "x86_64")]
#[cfg(all(feature = "_INDIRECT_", not(feature = "_DIRECT_")))]
pub fn get_ssn(hash: u32) -> (u16, u64) {
    let ntdll_addr : PVOID;
    let funct_addr : PVOID;
    let ssn_addr   : u64;
    let ssn        : u16;

    ntdll_addr = get_module_addr(crate::obf!("ntdll.dll"));
    funct_addr = get_function_addr(ntdll_addr, hash);
    unsafe {
        ssn = *((funct_addr as u64 + 4) as *const u16);
    }
    ssn_addr = funct_addr as u64 + 0x12;

    (ssn, ssn_addr)
}



#[cfg(target_arch = "x86")]
#[cfg(all(feature = "_DIRECT_", not(feature = "_INDIRECT_")))]
pub fn get_ssn(hash: u32) -> u16 {
    let ntdll_addr : PVOID;
    let funct_addr : PVOID;
    let ssn        : u16;

    ntdll_addr = get_module_addr(crate::obf!("ntdll.dll"));
    funct_addr = get_function_addr(ntdll_addr, hash);
    unsafe {
        ssn = *((funct_addr as u64 + 1) as *const u16);
    }
    ssn
}

#[cfg(target_arch = "x86")]
#[cfg(all(feature = "_INDIRECT_", not(feature = "_DIRECT_")))]
pub fn get_ssn(hash: u32) -> (u16, u32) {
    let ntdll_addr : PVOID;
    let funct_addr : PVOID;
    let ssn_addr   : u32;
    let ssn        : u16;

    ntdll_addr = get_module_addr(crate::obf!("ntdll.dll"));
    funct_addr = get_function_addr(ntdll_addr, hash);
    unsafe {
        ssn = *((funct_addr as u64 + 1) as *const u16);
    
        if is_wow64(){
            ssn_addr = funct_addr as u32 + 0x0A;
        } 
        else {
            ssn_addr = funct_addr as u32 + 0x0F;
        }
    }
    (ssn, ssn_addr)
}

