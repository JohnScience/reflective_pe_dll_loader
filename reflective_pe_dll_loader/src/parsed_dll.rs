use goblin::pe::{data_directories::DataDirectory, PE};
use winapi::ctypes::c_void;

use crate::PeDllLoadError;

pub(crate) struct ParsedDll<'a>(PE<'a>);

impl<'a> ParsedDll<'a> {
    fn validate(pe: &PE) -> Result<(), PeDllLoadError> {
        if !pe.is_lib {
            return Err(PeDllLoadError::PeButNotDll);
        }

        let Some(optional_header) = pe.header.optional_header.as_ref() else {
            return Err(PeDllLoadError::NoOptionalHeader);
        };

        if optional_header
            .data_directories
            .get_base_relocation_table()
            .is_none()
        {
            return Err(PeDllLoadError::NoBaseRelocationTable);
        }

        Ok(())
    }

    // checked during validation
    fn optional_header(&self) -> &goblin::pe::optional_header::OptionalHeader {
        match self.0.header.optional_header {
            Some(ref optional_header) => optional_header,
            // TODO: make this assertion enabled by a feature flag
            #[cfg(debug_assertions)]
            None => unreachable!(),
            #[cfg(not(debug_assertions))]
            None => unsafe { core::hint::unreachable_unchecked() },
        }
    }

    pub(crate) fn new(bytes: &'a [u8]) -> Result<Self, PeDllLoadError> {
        let dll = PE::parse(&bytes)?;

        Self::validate(&dll)?;

        Ok(Self(dll))
    }

    pub(crate) fn image_size(&self) -> usize {
        self.optional_header().windows_fields.size_of_image as usize
    }

    pub(crate) fn image_base(&self) -> *mut c_void {
        let image_base: u64 = self.optional_header().windows_fields.image_base;
        image_base as *mut c_void
    }

    pub(crate) fn name(&self) -> &str {
        self.0.name.as_deref().unwrap_or("the DLL")
    }

    pub(crate) fn sections(
        &self,
    ) -> impl Iterator<Item = &goblin::pe::section_table::SectionTable> {
        self.0.sections.iter()
    }

    // checked during validation
    pub(crate) fn base_relocation_table(&self) -> DataDirectory {
        match self
            .optional_header()
            .data_directories
            .get_base_relocation_table()
        {
            // the clone is cheap
            Some(base_relocation_table) => base_relocation_table.clone(),
            #[cfg(debug_assertions)]
            None => unreachable!(),
            #[cfg(not(debug_assertions))]
            None => unsafe { core::hint::unreachable_unchecked() },
        }
    }

    pub(crate) fn import_data(
        &self,
    ) -> Option<impl Iterator<Item = &goblin::pe::import::SyntheticImportDirectoryEntry>> {
        let r = self.0.import_data.as_ref()?;
        Some(r.import_data.iter())
    }

    pub(crate) fn exports(&self) -> impl Iterator<Item = &goblin::pe::export::Export> {
        self.0.exports.iter()
    }

    pub(crate) fn address_of_entry_point(&self) -> usize {
        self.optional_header()
            .standard_fields
            .address_of_entry_point as usize
    }
}
