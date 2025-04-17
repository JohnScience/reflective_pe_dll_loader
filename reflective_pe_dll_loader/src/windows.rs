use std::mem::MaybeUninit;
use std::ptr;

use winapi::ctypes::c_void;
use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID};

pub(crate) type DllEntryProc =
    unsafe extern "system" fn(hinstDLL: HINSTANCE, fdwReason: DWORD, lpReserved: LPVOID) -> BOOL;

pub(crate) const IMAGE_SIZEOF_BASE_RELOCATION: usize = 8;

#[derive(Debug, thiserror::Error)]
#[error("Unsupported relocation type: {0}")]
pub(crate) struct UnsupportedRelocationType(u8);

#[derive(Debug)]
#[repr(u8)]
pub(crate) enum BaseRelocationType {
    #[doc(alias = "IMAGE_REL_BASED_ABSOLUTE")]
    Absolute = 0,
    #[doc(alias = "IMAGE_REL_BASED_HIGHLOW")]
    HighLow = 3,
    #[doc(alias = "IMAGE_REL_BASED_DIR64")]
    Dir64 = 10,
}

#[repr(transparent)]
pub(crate) struct BaseRelocationEntry(u16);

#[doc(alias = "IMAGE_BASE_RELOCATION")]
#[derive(Debug)]
#[repr(C)]
pub(crate) struct BaseRelocationBlock {
    pub(crate) virtual_address: u32,
    pub(crate) size_of_block: u32,
}

#[doc(alias = "DUMMYSTRUCTNAME")]
#[derive(Clone, Copy)]
#[repr(C)]
pub struct DummyStructName {
    #[doc(alias = "wProcessorArchitecture")]
    pub processor_architecture: u16,
    #[doc(alias = "wReserved")]
    pub reserved: u16,
}

#[doc(alias = "DUMMYUNIONNAME")]
#[repr(C)]
pub union DummyUnionName {
    #[doc(alias = "dwOemId")]
    pub oem_id: u32,
    #[doc(alias = "DUMMYSTRUCTNAME")]
    pub dummy_struct: DummyStructName,
}

#[doc(alias = "_SYSTEM_INFO")]
#[repr(C)]
pub(crate) struct SystemInfo {
    #[doc(alias = "DUMMYUNIONNAME")]
    pub u: DummyUnionName,

    #[doc(alias = "dwPageSize")]
    pub page_size: u32,

    #[doc(alias = "lpMinimumApplicationAddress")]
    pub minimum_application_address: *mut c_void,

    #[doc(alias = "lpMaximumApplicationAddress")]
    pub maximum_application_address: *mut c_void,

    #[doc(alias = "dwActiveProcessorMask")]
    pub active_processor_mask: usize,

    #[doc(alias = "dwNumberOfProcessors")]
    pub number_of_processors: u32,

    #[doc(alias = "dwProcessorType")]
    pub processor_type: u32,

    #[doc(alias = "dwAllocationGranularity")]
    pub allocation_granularity: u32,

    #[doc(alias = "wProcessorLevel")]
    pub processor_level: u16,

    #[doc(alias = "wProcessorRevision")]
    pub processor_revision: u16,
}

impl std::fmt::Debug for BaseRelocationEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(BaseRelocationEntry))
            .field(
                "base_relocation_type_nibble",
                &self.base_relocation_type_nibble(),
            )
            // .field("base_relocation_type", &self.base_relocation_type())
            .field("va_offset", &self.va_offset())
            .finish()
    }
}

impl BaseRelocationEntry {
    fn base_relocation_type_nibble(&self) -> u8 {
        (self.0 >> 12) as u8
    }

    pub(crate) fn base_relocation_type(
        &self,
    ) -> Result<BaseRelocationType, UnsupportedRelocationType> {
        let base_relocation_type_nibble = self.base_relocation_type_nibble();
        let base_relocation_type = match base_relocation_type_nibble {
            0 => BaseRelocationType::Absolute,
            3 => BaseRelocationType::HighLow,
            10 => BaseRelocationType::Dir64,
            _ => return Err(UnsupportedRelocationType(base_relocation_type_nibble)),
        };
        Ok(base_relocation_type)
    }

    // The offset from the virtal address of the IMAGE_BASE_RELOCATION structure
    pub(crate) fn va_offset(&self) -> u16 {
        self.0 & 0x0FFF
    }

    pub(crate) fn perform_single_relocation(&self, dest: ptr::NonNull<c_void>, delta: isize) {
        let relocation_type = self.base_relocation_type().unwrap();
        let offset = self.va_offset();
        match relocation_type {
            BaseRelocationType::Absolute => {
                // Skip
            }
            BaseRelocationType::HighLow => {
                let dest = unsafe { dest.as_ptr().byte_add(offset as usize) } as *mut u32;
                let value = unsafe { dest.read() };
                unsafe {
                    dest.write(value.wrapping_add(delta as u32));
                }
            }
            BaseRelocationType::Dir64 => {
                let dest = unsafe { dest.as_ptr().byte_add(offset as usize) } as *mut u64;
                let value = unsafe { dest.read() };
                unsafe {
                    dest.write(value.wrapping_add(delta as u64));
                }
            }
        }
    }
}

/// Converts a relative virtual address (RVA) to a virtual address (VA) in the image.
pub(crate) fn rva_to_va(image_base: ptr::NonNull<c_void>, rva: u32) -> ptr::NonNull<c_void> {
    let va = (image_base.as_ptr() as usize + rva as usize) as *mut c_void;
    unsafe { ptr::NonNull::new_unchecked(va) }
}

pub(crate) fn section_size(section: &goblin::pe::section_table::SectionTable) -> usize {
    section.size_of_raw_data as usize
}

pub(crate) fn section_file_ptr_range(
    section: &goblin::pe::section_table::SectionTable,
) -> std::ops::Range<usize> {
    section.pointer_to_raw_data as usize
        ..section.pointer_to_raw_data as usize + section_size(section) as usize
}

pub(crate) fn section_va_range(
    image_base: ptr::NonNull<c_void>,
    section: &goblin::pe::section_table::SectionTable,
) -> std::ops::Range<ptr::NonNull<c_void>> {
    let start = rva_to_va(image_base, section.virtual_address);

    let end = unsafe { start.as_ptr().byte_add(section_size(section)) };

    debug_assert!(!end.is_null());

    let end = unsafe { ptr::NonNull::new_unchecked(end) };
    start..end
}

pub(crate) fn virtual_protect(
    address: ptr::NonNull<c_void>,
    size: usize,
    perms: u32, // old perms is not used
) -> Result<(), std::io::Error> {
    let mut old_perms = 0;
    let result = unsafe {
        winapi::um::memoryapi::VirtualProtect(address.as_ptr(), size, perms, &mut old_perms)
    };
    if result == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn get_system_info() -> SystemInfo {
    let mut system_info: MaybeUninit<SystemInfo> = MaybeUninit::uninit();
    let out_ptr = system_info.as_mut_ptr() as *mut _;
    unsafe { winapi::um::sysinfoapi::GetSystemInfo(out_ptr) };
    let system_info: SystemInfo = unsafe { system_info.assume_init() };
    system_info
}
