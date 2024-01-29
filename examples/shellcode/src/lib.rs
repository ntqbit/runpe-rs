#![no_std]
#![no_main]

use core::ffi::CStr;

use ldr::find_ldr_entry;
use wchar::wch;

use crate::{defs::HANDLE, ldr::find_symbols};

mod crt;
mod defs;
mod ldr;

#[panic_handler]
fn panic_handler(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

macro_rules! sym {
    ($sym:expr) => {
        CStr::from_bytes_with_nul_unchecked($sym.as_bytes())
    };
}

type EntryPoint = unsafe extern "C" fn(*mut ()) -> *mut ();

#[repr(C)]
#[allow(dead_code)]
struct CustomArgument {
    entry_point: u64,
    entry_point_argument: u64,
    argument: u64,
    argument_length: u64,
}

#[inline]
unsafe fn call_original_ep(arg: &CustomArgument) -> *mut () {
    let ep: EntryPoint = unsafe { core::mem::transmute(arg.entry_point) };
    ep(arg.entry_point_argument as *mut ())
}

#[no_mangle]
#[link_section = ".entry"]
unsafe extern "C" fn _start(arg: *mut CustomArgument) -> *mut () {
    let arg = &*arg;

    // Find LoadLibraryA in kernel32.dll.
    let kernel32 = find_ldr_entry(wch!("kernel32.dll")).unwrap();
    let loadlib = find_symbols(kernel32.DllBase as usize, &[sym!("LoadLibraryA\0")])[0].unwrap();

    // Load user32.dll.
    type LoadLibraryA = unsafe extern "C" fn(*const i8) -> HANDLE;
    let loadlib: LoadLibraryA = core::mem::transmute(loadlib);

    let user32 = loadlib("user32.dll\0".as_ptr() as _);
    assert!(!user32.is_null());

    // Find MessageBoxA.
    let messagebox = find_symbols(user32 as usize, &[sym!("MessageBoxA\0")])[0].unwrap();

    type MessageBoxA = unsafe extern "C" fn(*mut (), *const i8, *const i8, i32) -> i32;
    let messagebox: MessageBoxA = core::mem::transmute(messagebox);

    // Get argument if present.
    let text = if arg.argument != 0 {
        arg.argument as *const i8
    } else {
        "Hello!\0".as_ptr() as _
    };

    // Show message.
    messagebox(core::ptr::null_mut(), text, core::ptr::null(), 0);

    // Call original entry point.
    call_original_ep(arg)
}
