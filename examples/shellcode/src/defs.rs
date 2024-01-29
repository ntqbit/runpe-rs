#![allow(non_camel_case_types, non_snake_case)]
#![allow(dead_code)]

use core::ffi::c_void;

pub type DWORD = u32;
pub type WORD = u16;
pub type PVOID = *const c_void;
pub type ULONG = u32;
pub type USHORT = u16;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: *mut u16,
}

#[derive(Debug)]
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub DllBase: PVOID,
    pub EntryPoint: PVOID,
    pub SizeOfImage: ULONG,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: ULONG,
    pub LoadCount: USHORT,
    pub TlsIndex: USHORT,
    pub HashLinks: LIST_ENTRY,
    pub LoadedImports: PVOID,
    pub EntryPointActivationContext: PVOID,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}

pub type LPCSTR = *const i8;
pub type LPSTR = *mut i8;
pub type LPVOID = PVOID;
pub type BOOL = i32;
pub type LPBYTE = *const u8;
pub type HANDLE = PVOID;

#[derive(Debug, Clone)]
#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct STARTUPINFOA {
    pub cb: DWORD,
    pub lpReserved: LPCSTR,
    pub lpDesktop: LPCSTR,
    pub lpTitle: LPCSTR,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: WORD,
    pub cbReserved2: WORD,
    pub lpReserved2: LPBYTE,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
}

pub type CreateProcessA_fn = extern "system" fn(
    lpApplicationName: LPCSTR,
    lpCommandLine: LPSTR,
    lpProcessAttributes: *const SECURITY_ATTRIBUTES,
    lpThreadAttributes: *const SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: LPVOID,
    lpCurrentDirectory: LPCSTR,
    lpStartupInfo: *mut STARTUPINFOA,
    lpProcessInformation: *mut PROCESS_INFORMATION,
) -> BOOL;

pub type Sleep_fn = extern "system" fn(DWORD);
