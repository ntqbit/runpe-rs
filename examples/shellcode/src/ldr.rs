use core::{arch::asm, ffi::CStr};

use crate::defs::{DWORD, IMAGE_EXPORT_DIRECTORY, LDR_DATA_TABLE_ENTRY, UNICODE_STRING, WORD};

// Only x64 for now.

#[inline]
fn get_peb() -> usize {
    let peb: usize;
    unsafe {
        asm!("mov {}, gs:[0x60]", out(reg) peb);
    }
    peb
}

#[inline]
fn get_ldr(peb: usize) -> usize {
    unsafe { *((peb + 0x18) as *const usize) }
}

pub struct NtListIterator {
    start: usize,
    current: usize,
}

impl NtListIterator {
    pub fn new(start: usize) -> Self {
        Self {
            start,
            current: start,
        }
    }
}

impl Iterator for NtListIterator {
    type Item = *mut ();

    fn next(&mut self) -> Option<Self::Item> {
        let ldr_ptr = unsafe { *(self.current as *const usize) };

        if ldr_ptr == self.start {
            // End reached.
            return None;
        }

        self.current = ldr_ptr;

        Some(ldr_ptr as *mut ())
    }
}

pub fn traverse_ldr(pldr: usize) -> NtListIterator {
    let in_load_order_links_ptr = pldr + 0x10;
    NtListIterator::new(in_load_order_links_ptr)
}

#[inline]
fn unicode_string_as_slice(s: &UNICODE_STRING) -> &[u16] {
    unsafe { core::slice::from_raw_parts(s.buffer, (s.length as usize) / 2) }
}

#[inline]
fn cmpi(a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for i in 0..a.len() {
        if a[i] | 0x20 != b[i] | 0x20 {
            return false;
        }
    }

    return true;
}

#[inline]
pub fn find_ldr_entry(name: &[u16]) -> Option<&'static LDR_DATA_TABLE_ENTRY> {
    let ldr_iterator = traverse_ldr(get_ldr(get_peb()));

    for it in ldr_iterator {
        let entry = unsafe { &*(it as *const LDR_DATA_TABLE_ENTRY) };

        if cmpi(unicode_string_as_slice(&entry.BaseDllName), name) {
            return Some(entry);
        }
    }

    None
}

#[inline]
unsafe fn mem_read<T: Copy>(addr: usize) -> T {
    *(addr as *const T)
}

#[inline]
pub unsafe fn find_symbols<const N: usize>(image: usize, names: &[&CStr; N]) -> [Option<usize>; N] {
    const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
    const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

    if mem_read::<u16>(image) != IMAGE_DOS_SIGNATURE {
        return [None; N];
    }

    // e_lfanew
    // Offsets: http://www.sunshine2k.de/reversing/tuts/tut_pe.htm
    let ntheaders_offset: u32 = mem_read(image + 0x3C);
    let ntheader = image + ntheaders_offset as usize;
    if mem_read::<u32>(ntheader) != IMAGE_NT_SIGNATURE {
        return [None; N];
    }

    // Offset for x64.
    let export_va: u32 = mem_read(ntheader + 0x88);
    if export_va == 0 {
        // No exports because no export directory.
        return [None; N];
    }

    let export_dir = &*((image + export_va as usize) as *const IMAGE_EXPORT_DIRECTORY);

    macro_rules! slice_table {
        ($rva:ident, $number:ident, $ty:ty) => {
            core::slice::from_raw_parts(
                (image + export_dir.$rva as usize) as *const $ty,
                export_dir.$number as usize,
            )
        };
    }

    // Read tables
    let name_tbl = slice_table!(AddressOfNames, NumberOfNames, DWORD);
    let ord_tbl = slice_table!(AddressOfNameOrdinals, NumberOfNames, WORD);
    let sym_tbl = slice_table!(AddressOfFunctions, NumberOfFunctions, DWORD);

    let mut result = [None; N];

    for (&name_rva, &ordinal) in name_tbl.iter().zip(ord_tbl.iter()) {
        let sym_name = CStr::from_ptr((image + name_rva as usize) as *const i8);
        for (i, &name) in names.iter().enumerate() {
            if sym_name == name {
                let symbol_rva = *sym_tbl.get(ordinal as usize).unwrap();
                result[i] = Some(image + symbol_rva as usize);
            }
        }
    }

    result
}
