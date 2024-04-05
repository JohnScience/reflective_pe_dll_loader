#![doc = include_str!("../README.md")]

use core::panic;
use core::ptr;
use core::ptr::NonNull;
use goblin::pe::data_directories::DataDirectory;
use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::HINSTANCE;
use winapi::um::memoryapi::VirtualAlloc;
use winapi::um::winnt::{
    DLL_THREAD_ATTACH, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
};

mod parsed_dll;
mod windows;

use parsed_dll::ParsedDll;
use windows::*;

// The code below is written based on <https://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/>

// Note (JohnScience): the code assumes that the DLL is already in memory, so why not change the memory
// protections appropriately and modify the DLL in memory? This implementation doesn't do that but that's
// an interesting direction of development.

/// A Windows PECOFF DLL loaded into memory.
pub struct PeDll {
    /// The base address of the image in memory.
    pub image_base: ptr::NonNull<c_void>,
    export_symbols: Vec<ExportSymbol>,
}

/// A symbol exported by a DLL.
pub struct Symbol<'a, T = ptr::NonNull<c_void>> {
    // The type of `value` field is not ptr::NonNull<T> because we want to support function pointers
    value: T,
    phantom: core::marker::PhantomData<&'a PeDll>,
}

impl<'a> Symbol<'a, ptr::NonNull<c_void>> {
    /// Cast the symbol to a known type, e.g. a function pointer.
    ///
    /// # Safety
    ///
    /// * The size of the type `T` must be equal to the size of a pointer.
    /// * The type `T` must be the correct type of the symbol.
    pub unsafe fn assume_type<T>(self) -> Symbol<'a, T> {
        debug_assert_eq!(
            core::mem::size_of::<T>(),
            core::mem::size_of::<ptr::NonNull<c_void>>()
        );
        Symbol {
            value: unsafe { core::mem::transmute_copy(&self.value) },
            phantom: core::marker::PhantomData,
        }
    }
}

impl<'a, T> core::ops::Deref for Symbol<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

// The export symbol stored in the PeDll instance. Not intended to be exposed to the user.
// TODO: consider adding "forwarding symbols"
struct ExportSymbol {
    name: Option<String>,
    va: ptr::NonNull<c_void>,
}

/// Error type for loading a PE DLL.
#[derive(Debug, thiserror::Error)]
pub enum PeDllLoadError {
    /// The file couldn't be parsed as a PE file.
    #[error("PE parsing error: {0}")]
    PeParsingError(#[from] goblin::error::Error),
    /// The file is in PE format but is not a DLL.
    #[error("The file is in PE format but is not a DLL")]
    PeButNotDll,
    /// The DLL does not have an optional header.
    #[error("The file does not have an optional header")]
    NoOptionalHeader,
    /// The DLL does not have a data directory.
    #[error("The file does not have a base relocation table")]
    NoBaseRelocationTable,
    /// An error occured while allocating the memory for loading a DLL.
    #[error("Memory allocation error. {0}")]
    MemoryAllocationError(#[from] MemoryAllocationError),
    /// An error occured while committing memory for a section.
    #[error("Memory commit error while loading the DLL. {0}")]
    MemoryCommitError(#[from] MemoryCommitError),
    /// An error occured while protecting memory.
    #[error("VirtualProtect error while loading the DLL. {0}")]
    VirtualProtectError(#[from] VirtualProtectError),
}

/// An error occured while allocating the memory for loading a DLL.
#[derive(Debug, thiserror::Error)]
#[error("Failed to allocate memory for {dll_name}: {inner}.")]
pub struct MemoryAllocationError {
    inner: std::io::Error,
    dll_name: String,
}

/// An error occured while committing memory for a section.
#[derive(Debug, thiserror::Error)]
#[error("Failed to commit memory for a section while loading {dll_name}: {inner}.")]
pub struct MemoryCommitError {
    inner: std::io::Error,
    dll_name: String,
}

/// An error occured while protecting memory.
#[derive(Debug, thiserror::Error)]
#[error("Failed to protect memory while loading {dll_name}: {inner}.")]
pub struct VirtualProtectError {
    inner: std::io::Error,
    dll_name: String,
}

impl PeDll {
    // Allocate memory for the image
    fn allocate_memory(dll: &ParsedDll) -> Result<ptr::NonNull<c_void>, MemoryAllocationError> {
        let image_size: usize = dll.image_size();

        let preferred_base: *mut c_void = dll.image_base();

        let image_base: *mut c_void =
            unsafe { VirtualAlloc(preferred_base, image_size, MEM_RESERVE, PAGE_READWRITE) };
        match ptr::NonNull::new(image_base) {
            Some(image_base) => Ok(image_base),
            None => Err(MemoryAllocationError {
                inner: std::io::Error::last_os_error(),
                dll_name: dll.name().to_string(),
            }),
        }
    }

    #[inline]
    fn commit_mem_for_section_with_rw_protection(
        image_base: ptr::NonNull<c_void>,
        section: &goblin::pe::section_table::SectionTable,
    ) -> Result<ptr::NonNull<c_void>, MemoryCommitError> {
        let section_size: usize = section_size(section);

        // debug_assert!(section_size > 0);

        let va_range = section_va_range(image_base, section);

        let ret = unsafe {
            // The call below commits already reserved memory
            VirtualAlloc(
                va_range.start.as_ptr(),
                section_size,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
        };

        if ret.is_null() {
            return Err(MemoryCommitError {
                inner: std::io::Error::last_os_error(),
                dll_name: "the DLL".to_string(),
            });
        }

        Ok(va_range.start)
    }

    fn copy_sections(
        dll: &ParsedDll,
        image_base: ptr::NonNull<c_void>,
        bytes: &[u8],
    ) -> Result<(), MemoryCommitError> {
        for section in dll.sections() {
            let section_size: usize = section_size(section);

            if section_size == 0 {
                continue;
            }

            let section_dest: ptr::NonNull<c_void> =
                Self::commit_mem_for_section_with_rw_protection(image_base, section)?;

            let section_data: &[u8] = &bytes[section_file_ptr_range(section)];
            unsafe {
                core::ptr::copy_nonoverlapping(
                    section_data.as_ptr(),
                    section_dest.as_ptr().cast(),
                    section_size,
                );
            }
        }
        Ok(())
    }

    // The delta between the image base of the the DLL and the preferred base
    fn delta(dll: &ParsedDll, image_base: ptr::NonNull<c_void>) -> isize {
        image_base.as_ptr() as isize - dll.image_base() as isize
    }

    // See https://github.com/HotKeyIt/ahkdll/blob/818386f5af7e6000d945801838d4e80a9e530c0d/source/MemoryModule.cpp#L476
    fn perform_base_relocation(dll: &ParsedDll, image_base: ptr::NonNull<c_void>, delta: isize) {
        let DataDirectory {
            virtual_address: base_relocation_table_rva,
            // It is unused because we rely on the sentinel value of the size_of_block field
            size: _base_relocation_table_size,
        } = dll.base_relocation_table();

        let mut base_relocation_block_ptr: *mut BaseRelocationBlock =
            rva_to_va(image_base, base_relocation_table_rva).as_ptr() as *mut BaseRelocationBlock;

        loop {
            let base_relocation_block = unsafe { base_relocation_block_ptr.read() };
            if base_relocation_block.size_of_block == 0 {
                break;
            }
            let dest = rva_to_va(image_base, base_relocation_block.virtual_address);
            let mut rel_info =
                unsafe { base_relocation_block_ptr.byte_add(IMAGE_SIZEOF_BASE_RELOCATION) }
                    as *mut BaseRelocationEntry;
            let mut i = 0;
            let rel_count =
                (base_relocation_block.size_of_block as usize - IMAGE_SIZEOF_BASE_RELOCATION) / 2;
            while i < rel_count {
                let rel_entry = unsafe { rel_info.read() };
                rel_entry.perform_single_relocation(dest, delta);
                i += 1;
                rel_info = unsafe { rel_info.add(1) };
            }

            // Q: do we really need to flush the instruction cache here as done in
            // https://github.com/HotKeyIt/ahkdll/blob/818386f5af7e6000d945801838d4e80a9e530c0d/source/MemoryModule.cpp#L527
            // FlushInstructionCache(GetCurrentProcess(), dest, module->pageSize);

            base_relocation_block_ptr = unsafe {
                base_relocation_block_ptr.byte_add(base_relocation_block.size_of_block as usize)
            };
        }
    }

    // TODO: learn more about implicit and explicit linking, especially about delayed-loaded DLL option for implicit linking
    fn resolve_imports(dll: &ParsedDll, image_base: ptr::NonNull<c_void>) {
        let Some(import_data_iter) = dll.import_data() else {
            return;
        };

        for synthetic_import_directory_entry in import_data_iter {
            let import_directory_entry = &synthetic_import_directory_entry.import_directory_entry;
            let import_lookup_table: *mut u32 = {
                let rva = import_directory_entry.import_lookup_table_rva;
                rva_to_va(image_base, rva).as_ptr() as *mut u32
            };
            let import_address_table: *mut *mut c_void =
                rva_to_va(image_base, import_directory_entry.import_address_table_rva).as_ptr()
                    as *mut *mut c_void;

            let mut i = 0;
            loop {
                let import_lookup_entry = unsafe { import_lookup_table.add(i).read() };
                if import_lookup_entry == 0 {
                    break;
                }

                let import_name: *const i8 =
                    rva_to_va(image_base, import_lookup_entry as u32 + 2).as_ptr() as *const i8;
                let import_name: &str = unsafe {
                    core::ffi::CStr::from_ptr(import_name)
                        .to_str()
                        .unwrap_or("{anonymous import}")
                };

                let import_address: *mut c_void = unsafe {
                    winapi::um::libloaderapi::GetProcAddress(
                        image_base.as_ptr() as HINSTANCE,
                        import_name.as_ptr() as *const i8,
                    )
                } as *mut c_void;

                unsafe {
                    *import_address_table.add(i) = import_address;
                }

                i += 1;
            }
        }
    }

    fn protect_memory(
        dll: &ParsedDll,
        image_base: ptr::NonNull<c_void>,
    ) -> Result<(), VirtualProtectError> {
        // We sort the sections by their privileges to avoid depriving pages of their privileges.
        // Even though sections themselves do not overlap, their pages might.
        let mut sections: Vec<_> = dll
            .sections()
            .filter(|section| section_size(section) > 0)
            .collect();
        sections.sort_by(|a, b| {
            // pv stands for "privilege value"
            let [pv_a, pv_b] = [a, b]
                .map(|section| {
                    let r: bool = section.characteristics & IMAGE_SCN_MEM_READ != 0;
                    let w: bool = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
                    let e: bool = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
                    [r, w, e]
                })
                .map(|privileges| {
                    privileges
                        .iter()
                        .enumerate()
                        .map(|(i, &p)| if p { 1 << (i + 1) } else { 0 })
                        .sum::<u8>()
                });
            pv_a.cmp(&pv_b)
        });
        for section in sections.iter() {
            let r: bool = section.characteristics & IMAGE_SCN_MEM_READ != 0;
            let w: bool = section.characteristics & IMAGE_SCN_MEM_WRITE != 0;
            let e: bool = section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

            let section_size = section_size(section);

            // TODO: account for other section characteristics

            let perms = match (r, w, e) {
                (false, false, false) => PAGE_NOACCESS,
                (false, false, true) => PAGE_EXECUTE,
                (false, true, false) => panic!("Invalid section permissions"),
                (false, true, true) => PAGE_EXECUTE_WRITECOPY,
                (true, false, false) => PAGE_READONLY,
                (true, false, true) => PAGE_EXECUTE_READ,
                (true, true, false) => PAGE_READWRITE,
                (true, true, true) => PAGE_EXECUTE_READWRITE,
            };

            let section_va = rva_to_va(image_base, section.virtual_address);

            windows::virtual_protect(section_va, section_size, perms).map_err(|e| {
                VirtualProtectError {
                    inner: e,
                    dll_name: dll.name().to_string(),
                }
            })?;
        }
        Ok(())
    }

    fn notify_dll(dll: &ParsedDll, image_base: ptr::NonNull<c_void>) {
        let entrypoint: DllEntryProc = {
            let address_of_entrypoint = dll.address_of_entry_point();

            if address_of_entrypoint == 0 {
                return;
            }

            let entrypoint_va: *const c_void =
                (image_base.as_ptr() as usize + address_of_entrypoint) as *const c_void;

            unsafe { core::mem::transmute(entrypoint_va) }
        };

        // https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain#parameters
        // https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain
        // DLL_PROCESS_ATTACH doesn't actually work
        unsafe {
            entrypoint(
                image_base.as_ptr() as HINSTANCE,
                DLL_THREAD_ATTACH,
                core::ptr::null_mut(),
            );
        }
    }

    /// Load a PE DLL from memory.
    pub fn new(bytes: &[u8]) -> Result<Self, PeDllLoadError> {
        let dll = ParsedDll::new(bytes)?;
        let image_base: NonNull<c_void> = Self::allocate_memory(&dll)?;
        Self::copy_sections(&dll, image_base, &bytes)?;
        let delta = Self::delta(&dll, image_base);
        Self::perform_base_relocation(&dll, image_base, delta);
        Self::resolve_imports(&dll, image_base);
        Self::protect_memory(&dll, image_base)?;
        Self::notify_dll(&dll, image_base);

        // TODO: find a way to avoid collecting the symbols

        let export_symbols = dll
            .exports()
            .map(|export| {
                let name = export.name.map(ToString::to_string);
                let va = rva_to_va(image_base, export.rva as u32);
                ExportSymbol { name, va }
            })
            .collect();

        let dll = Self {
            image_base,
            export_symbols,
        };
        Ok(dll)
    }

    /// Get a symbol exported by the DLL, by name.
    pub fn get_symbol_by_name<'a, 'b>(
        &'a self,
        name: &'b str,
    ) -> Option<Symbol<'a, ptr::NonNull<c_void>>> {
        self.export_symbols
            .iter()
            .find(|export_symbol| export_symbol.name.as_deref() == Some(name))
            .map(|export_symbol| Symbol {
                value: export_symbol.va,
                phantom: core::marker::PhantomData,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_dll() {
        let bytes = std::fs::read("test-dlls/hello_world_lib.dll").unwrap();
        let pe_dll = PeDll::new(&bytes).unwrap();

        let add: Symbol<extern "C" fn(i32, i32) -> i32> = {
            let symbol = pe_dll.get_symbol_by_name("add").unwrap();
            unsafe { symbol.assume_type() }
        };

        assert_eq!(add(1, 2), 3);
    }
}
