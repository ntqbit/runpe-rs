use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE,
    IMAGE_SECTION_HEADER,
};

pub enum PeParseError {
    WrongDosMagic,
    WrongNtMagic,
}

pub struct ParsedPe<'a> {
    pub dos: &'a IMAGE_DOS_HEADER,
    pub nt: &'a IMAGE_NT_HEADERS,
    pub sections: Vec<&'a IMAGE_SECTION_HEADER>,
}

impl<'a> ParsedPe<'a> {
    pub fn offset<T>(&self, offset: usize) -> *const T {
        unsafe { (self.dos as *const IMAGE_DOS_HEADER as *const u8).add(offset) as *const T }
    }
}

// Marked unsafe because boundaries are not checked.
// Invalid PE may cause a crash.
// TODO: check boundaries & alignment.
// SAFETY: must be a valid pe image.
pub unsafe fn basic_parse_pe(pe_image: &[u8]) -> Result<ParsedPe, PeParseError> {
    let ptr = pe_image.as_ptr();
    let dos_image = &*(ptr as *const IMAGE_DOS_HEADER);
    if dos_image.e_magic != IMAGE_DOS_SIGNATURE {
        return Err(PeParseError::WrongDosMagic);
    }

    let ntheader_ptr = ptr.offset(dos_image.e_lfanew as isize) as *const IMAGE_NT_HEADERS;
    let ntheader = &*ntheader_ptr;
    if ntheader.Signature != IMAGE_NT_SIGNATURE {
        return Err(PeParseError::WrongNtMagic);
    }

    let section_headers = core::slice::from_raw_parts(
        ntheader_ptr.add(1) as *const IMAGE_SECTION_HEADER,
        ntheader.FileHeader.NumberOfSections as usize,
    );

    let sections = section_headers.iter().map(|x| x).collect();

    Ok(ParsedPe {
        dos: dos_image,
        nt: ntheader,
        sections,
    })
}
