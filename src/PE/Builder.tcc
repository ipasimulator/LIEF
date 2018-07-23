/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
namespace LIEF {
namespace PE {

/*********************************

          PE Import

    +-----------------------+
    | ILT RVA               | --+
    +-----------------------+   |
    | Name RVA              |   |
    +-----------------------+   |
 ---| IAT RVA               |   |
 |  +-----------------------+   |
 |  |                       |   |
 |  |                       |   |
 |  |                       |   |
 |  +-----------------------+   |
 |  | 000000000000000000000 |   |
 |  +-----------------------+   |
 |                              |
 |   +---- Ordinal Flag         |
 |   v                          |
 |  +-+---------------------+ <-+-------- ILT
 |  | | Hint/Name RVA       |---+
 |  +-+---------------------+   |
 |  | | ....                |   |
 |  +-+---------------------+   |
 |                              |
 |            IAT               |
 +->+-+---------------------+   |
    | | Same Value as ILT[0]|   |
    +-+---------------------+   |
    | |                     |   |
    +-+---------------------+   |
                                |
                                |
    +---+---------------+---+   |
    | 9 | LoadLibrary   | 0 | <-+
    +---+---------------+---+
      ^         ^         ^
      |         |         |
     Hint      Name     Padding

*********************************/




template<typename PE_T>
void Builder::build_import_table(void) {
  using uint__ = typename PE_T::uint;

  /**************************************

   +----------------------------------+
   | pe_import[0]                     |
   +----------------------------------+
   | pe_import[1]                     |
   +----------------------------------+
   |                                  |
   | Import Lookup Tables             |
   |                                  |
   +----------------------------------+
   | Library Names                    |
   +----------------------------------+
   |                                  |
   | Hint/Names table                 |
   |                                  |
   +----------------------------------+
   |                                  |
   |                                  |
   | New IAT (For new imports)        |
   |                                  |
   |                                  |
   +----------------------------------+

  **************************************/

  it_imports imports = this->binary_->imports();

  uint32_t import_table_size  = static_cast<uint32_t>((imports.size() + 1) * sizeof(pe_import)); // +1 for the null entry
  uint32_t ilt_size           = 0;
  uint32_t library_names_size = 0;
  uint32_t hint_name_sizes    = 0;
  uint32_t new_iat_size       = 0;
  for (const Import& import : imports) {

    library_names_size  += import.name().size() + 1;
    ilt_size            += (import.entries().size() + 1) * sizeof(uint__);

    // Added by the user
    if (import.import_address_table_rva() == 0) {
      new_iat_size += (import.entries().size() + 1) * sizeof(uint__);
    }

    for (const ImportEntry& entry : import.entries()) {
      if (not entry.is_ordinal()) {
        hint_name_sizes += sizeof(uint16_t) + entry.name().size() + 1;
        hint_name_sizes += hint_name_sizes % 2;
      }

    }
  }
  uint32_t import_table_offset  = 0;
  uint32_t ilt_offset           = import_table_offset + import_table_size;
  uint32_t library_names_offset = ilt_offset + ilt_size;
  uint32_t hint_names_offset    = library_names_offset + library_names_size;
  uint32_t new_iat_offset       = align(hint_names_offset + hint_name_sizes, 4);
  uint32_t end_off              = new_iat_offset + new_iat_size;


  std::vector<uint8_t> new_imports(end_off, 0);
  size_t content_size_aligned = align(new_imports.size(), this->binary_->optional_header().file_alignment());
  new_imports.insert(std::end(new_imports), content_size_aligned - new_imports.size(), 0);

  // Create a new section to handle imports
  Section new_import_section{".l" + std::to_string(static_cast<uint32_t>(DATA_DIRECTORY::IMPORT_TABLE))};
  new_import_section.content(new_imports);

  //new_import_section.add_characteristic(SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_CODE);

  auto&& it_import_section = std::find_if(
      std::begin(this->binary_->sections_),
      std::end(this->binary_->sections_),
      [] (const Section* section) {
        return section != nullptr and section->is_type(PE_SECTION_TYPES::IMPORT);
      });

  // Remove 'import' type from the original section
  if (it_import_section != std::end(this->binary_->sections_)) {
    (*it_import_section)->remove_type(PE_SECTION_TYPES::IMPORT);
  }

  Section& import_section = this->binary_->add_section(new_import_section, PE_SECTION_TYPES::IMPORT);


  // Process libraries
  for (const Import& import : imports) {
    uint32_t iat_rva = import.import_address_table_rva();

    // If IAT is 0 it means that it's a user import
    if (import.import_address_table_rva() == 0) {
      iat_rva = import_section.virtual_address() + new_iat_offset;
    }
    // Header
    pe_import header;
    header.ImportLookupTableRVA  = static_cast<uint32_t>(import_section.virtual_address() + ilt_offset);
    header.TimeDateStamp         = static_cast<uint32_t>(import.timedatestamp());
    header.ForwarderChain        = static_cast<uint32_t>(import.forwarder_chain());
    header.NameRVA               = static_cast<uint32_t>(import_section.virtual_address() + library_names_offset);
    header.ImportAddressTableRVA = static_cast<uint32_t>(iat_rva);

    // Copy the header in the "header section"
    std::copy(
        reinterpret_cast<uint8_t*>(&header),
        reinterpret_cast<uint8_t*>(&header) + sizeof(pe_import),
        new_imports.data() + import_table_offset);

    import_table_offset += sizeof(pe_import);

    // Copy the name in the "string section"
    const std::string& import_name = import.name();
    std::copy(
        std::begin(import_name),
        std::end(import_name),
        new_imports.data() + library_names_offset);

    library_names_offset += import_name.size() + 1; // +1 for '\0'
    uint__ ilt_value = 0;

    // Process imported functions
    for (const ImportEntry& entry : import.entries()) {
      // Default: ordinal case
      ilt_value = entry.data();

      if (not entry.is_ordinal()) {
        ilt_value = import_section.virtual_address() + hint_names_offset;

        // Insert entry in hint/name table
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // First: hint
        const uint16_t hint = entry.hint();

        std::copy(
            reinterpret_cast<const uint8_t*>(&hint),
            reinterpret_cast<const uint8_t*>(&hint) + sizeof(uint16_t),
            new_imports.data() + hint_names_offset); //hintIdx

        hint_names_offset += sizeof(uint16_t);

        // Then: name
        const std::string& name = entry.name();
        std::copy(
            std::begin(name),
            std::end(name),
            new_imports.data() + hint_names_offset);

        hint_names_offset += name.size() + 1; // +1 for \0
        hint_names_offset += hint_names_offset % 2; //Require to be even
      } // is_ordinal

      // Write ILT Value
      std::copy(
        reinterpret_cast<const uint8_t*>(&ilt_value),
        reinterpret_cast<const uint8_t*>(&ilt_value) + sizeof(uint__),
        new_imports.data() + ilt_offset);

      // Patch IAT value
      if (import.import_address_table_rva() == 0) {
        uint32_t off = iat_rva - import_section.virtual_address();

        std::copy(
          reinterpret_cast<const uint8_t*>(&ilt_value),
          reinterpret_cast<const uint8_t*>(&ilt_value) + sizeof(uint__),
          new_imports.data() + off);
        new_iat_offset += sizeof(uint__);
      } else {
        this->binary_->patch_address(iat_rva, ilt_value, sizeof(uint__), LIEF::Binary::VA_TYPES::RVA);
      }

      ilt_offset += sizeof(uint__);
      iat_rva    += sizeof(uint__);
    } // </end> ImportEntry iterator

    // Null value at the end
    ilt_value = 0;

    std::copy(
      reinterpret_cast<const uint8_t*>(&ilt_value),
      reinterpret_cast<const uint8_t*>(&ilt_value) + sizeof(uint__),
      new_imports.data() + ilt_offset);

    // Patch IAT value
    if (import.import_address_table_rva() == 0) {
      uint32_t off = iat_rva - import_section.virtual_address();

      std::copy(
        reinterpret_cast<const uint8_t*>(&ilt_value),
        reinterpret_cast<const uint8_t*>(&ilt_value) + sizeof(uint__),
        new_imports.data() + off);
      new_iat_offset += sizeof(uint__);
    } else {
      this->binary_->patch_address(iat_rva, ilt_value, sizeof(uint__), LIEF::Binary::VA_TYPES::RVA);
    }
    ilt_offset += sizeof(uint__);
    iat_rva    += sizeof(uint__);

  } // </end> Import Iterator

  // Insert null entry at the end
  std::fill(
    new_imports.data() + import_table_offset,
    new_imports.data() + import_table_offset + sizeof(pe_import),
    0);

  import_table_offset += sizeof(pe_import);
  import_section.content(std::move(new_imports));

}

template<typename PE_T>
std::vector<uint8_t> Builder::build_jmp(uint64_t from, uint64_t address) {
  std::vector<uint8_t> instruction;

  // call $+5
  instruction.push_back(0xe8);
  instruction.push_back(0x00);
  instruction.push_back(0x00);
  instruction.push_back(0x00);
  instruction.push_back(0x00);

  // pop eax/pop rax
  instruction.push_back(0x58); // eax/rax holds the current PC

  // add rax/eax (signed)
  if (std::is_same<PE_T, PE64>::value) {
    instruction.push_back(0x48); //x64
  }
  instruction.push_back(0x05);

  uint64_t diff = address - (from + 5);

  for (size_t i = 0; i < sizeof(uint32_t); ++i) {
    instruction.push_back(static_cast<uint8_t>((diff >> (8 * i)) & 0xFF));
  }
  // jmp [rax/eax]
  instruction.push_back(0xff);
  instruction.push_back(0x20);

  return instruction;
}


template<typename PE_T>
std::vector<uint8_t> Builder::build_jmp_hook(uint64_t from, uint64_t address) {
  std::vector<uint8_t> instruction;
  instruction.push_back(0xe9); // jmp xxxx
  uint64_t disp = address - from - 5;

  for (size_t i = 0; i < sizeof(uint32_t); ++i) {
    instruction.push_back(static_cast<uint8_t>((disp >> (8 * i)) & 0xFF));
  }

  return instruction;
}



template<typename PE_T>
void Builder::build_optional_header(const OptionalHeader& optional_header) {
  using uint__             = typename PE_T::uint;
  using pe_optional_header = typename PE_T::pe_optional_header;

  // Build optional header
  this->binary_->optional_header().sizeof_image(static_cast<uint32_t>(this->binary_->virtual_size()));
  this->binary_->optional_header().sizeof_headers(static_cast<uint32_t>(this->binary_->sizeof_headers()));

  pe_optional_header optional_header_raw;
  optional_header_raw.Magic                   = static_cast<uint16_t>(optional_header.magic());
  optional_header_raw.MajorLinkerVersion      = static_cast<uint8_t> (optional_header.major_linker_version());
  optional_header_raw.MinorLinkerVersion      = static_cast<uint8_t> (optional_header.minor_linker_version());
  optional_header_raw.SizeOfCode              = static_cast<uint32_t>(optional_header.sizeof_code());
  optional_header_raw.SizeOfInitializedData   = static_cast<uint32_t>(optional_header.sizeof_initialized_data());
  optional_header_raw.SizeOfUninitializedData = static_cast<uint32_t>(optional_header.sizeof_uninitialized_data());
  optional_header_raw.AddressOfEntryPoint     = static_cast<uint32_t>(optional_header.addressof_entrypoint());
  optional_header_raw.BaseOfCode              = static_cast<uint32_t>(optional_header.baseof_code());

  if (std::is_same<PE_T, PE32>::value) {
    // Trick to avoid compilation error
    reinterpret_cast<pe32_optional_header*>(&optional_header_raw)->BaseOfData = static_cast<uint32_t>(optional_header.baseof_data());
  }
  optional_header_raw.ImageBase                    = static_cast<uint__>(optional_header.imagebase());
  optional_header_raw.SectionAlignment             = static_cast<uint32_t>(optional_header.section_alignment());
  optional_header_raw.FileAlignment                = static_cast<uint32_t>(optional_header.file_alignment());
  optional_header_raw.MajorOperatingSystemVersion  = static_cast<uint16_t>(optional_header.major_operating_system_version());
  optional_header_raw.MinorOperatingSystemVersion  = static_cast<uint16_t>(optional_header.minor_operating_system_version());
  optional_header_raw.MajorImageVersion            = static_cast<uint16_t>(optional_header.major_image_version());
  optional_header_raw.MinorImageVersion            = static_cast<uint16_t>(optional_header.minor_image_version());
  optional_header_raw.MajorSubsystemVersion        = static_cast<uint16_t>(optional_header.major_subsystem_version());
  optional_header_raw.MinorSubsystemVersion        = static_cast<uint16_t>(optional_header.minor_subsystem_version());
  optional_header_raw.Win32VersionValue            = static_cast<uint16_t>(optional_header.win32_version_value());
  optional_header_raw.SizeOfImage                  = static_cast<uint32_t>(optional_header.sizeof_image());
  optional_header_raw.SizeOfHeaders                = static_cast<uint32_t>(optional_header.sizeof_headers());
  optional_header_raw.CheckSum                     = static_cast<uint32_t>(optional_header.checksum());
  optional_header_raw.Subsystem                    = static_cast<uint16_t>(optional_header.subsystem());
  optional_header_raw.DLLCharacteristics           = static_cast<uint16_t>(optional_header.dll_characteristics());
  optional_header_raw.SizeOfStackReserve           = static_cast<uint__>(optional_header.sizeof_stack_reserve());
  optional_header_raw.SizeOfStackCommit            = static_cast<uint__>(optional_header.sizeof_stack_commit());
  optional_header_raw.SizeOfHeapReserve            = static_cast<uint__>(optional_header.sizeof_heap_reserve());
  optional_header_raw.SizeOfHeapCommit             = static_cast<uint__>(optional_header.sizeof_heap_commit());
  optional_header_raw.LoaderFlags                  = static_cast<uint32_t>(optional_header.loader_flags());
  optional_header_raw.NumberOfRvaAndSize           = static_cast<uint32_t>(optional_header.numberof_rva_and_size());


  const uint32_t address_next_header = this->binary_->dos_header().addressof_new_exeheader() + sizeof(pe_header);
  this->ios_.seekp(address_next_header);
  this->ios_.write(reinterpret_cast<const uint8_t*>(&optional_header_raw), sizeof(pe_optional_header));

}


template<typename PE_T>
void Builder::build_tls(void) {
  using uint__ = typename PE_T::uint;
  using pe_tls = typename PE_T::pe_tls;

  auto&& it_tls = std::find_if(
    std::begin(this->binary_->sections_),
    std::end(this->binary_->sections_),
    [] (const Section* section)
    {
      const std::set<PE_SECTION_TYPES>& types = section->types();
      return types.size() == 1 and types.find(PE_SECTION_TYPES::TLS) != std::end(types);
    });

  Section *tls_section = nullptr;

  pe_tls tls_raw;
  const TLS& tls_obj = this->binary_->tls();

  // No .tls section register in the binary. We have to create it
  if (it_tls == std::end(this->binary_->sections_)) {
    Section new_section{".l" + std::to_string(static_cast<uint32_t>(DATA_DIRECTORY::TLS_TABLE))}; // .l9 -> lief.tls
    new_section.characteristics(0xC0300040);
    uint64_t tls_section_size = sizeof(pe_tls);

    const uint64_t offset_callbacks = this->binary_->va_to_offset(tls_obj.addressof_callbacks());
    const uint64_t offset_rawdata   = this->binary_->va_to_offset(tls_obj.addressof_raw_data().first);

    try {
      const Section& _ [[gnu::unused]] = this->binary_->section_from_offset(offset_callbacks);
    } catch (const not_found&) { // Callbacks will be in our section (not present yet)
      tls_section_size += tls_obj.callbacks().size() * sizeof(uint__);
    }


    try {
      const Section& _ [[gnu::unused]] = this->binary_->section_from_offset(offset_rawdata);
    } catch (const not_found&) { // data_template will be in our section (not present yet)
      tls_section_size += tls_obj.data_template().size();
    }

    tls_section_size = align(tls_section_size, this->binary_->optional_header().file_alignment());
    new_section.content(std::vector<uint8_t>(tls_section_size, 0));

    tls_section = &(this->binary_->add_section(new_section, PE_SECTION_TYPES::TLS));
  } else {
    tls_section = *it_tls;
  }

  tls_raw.RawDataStartVA    = static_cast<uint__>(tls_obj.addressof_raw_data().first);
  tls_raw.RawDataEndVA      = static_cast<uint__>(tls_obj.addressof_raw_data().second);
  tls_raw.AddressOfIndex    = static_cast<uint__>(tls_obj.addressof_index());
  tls_raw.AddressOfCallback = static_cast<uint__>(tls_obj.addressof_callbacks());
  tls_raw.SizeOfZeroFill    = static_cast<uint32_t>(tls_obj.sizeof_zero_fill());
  tls_raw.Characteristics   = static_cast<uint32_t>(tls_obj.characteristics());

  std::vector<uint8_t> data(sizeof(pe_tls), 0);

  std::copy(
      reinterpret_cast<uint8_t*>(&tls_raw),
      reinterpret_cast<uint8_t*>(&tls_raw) + sizeof(pe_tls),
      data.data());

  const uint64_t offset_callbacks = this->binary_->va_to_offset(tls_obj.addressof_callbacks());
  const uint64_t offset_rawdata   = this->binary_->va_to_offset(tls_obj.addressof_raw_data().first);
  try {
    Section& section_callbacks = this->binary_->section_from_offset(offset_callbacks);

    const uint64_t size_needed = (tls_obj.callbacks().size()) * sizeof(uint__);

    if (section_callbacks == *tls_section) {
      // Case where the section where callbacks are located is the same
      // than the current .tls section

      uint64_t relative_offset = offset_callbacks - tls_section->offset();

      for (uint__ callback : tls_obj.callbacks()) {
        data.insert(
            std::begin(data) + relative_offset,
            reinterpret_cast<uint8_t*>(&callback),
            reinterpret_cast<uint8_t*>(&callback) + sizeof(uint__));
        relative_offset += sizeof(uint__);
      }

      //data.insert(std::begin(data) + relative_offset + sizeof(uint__), sizeof(uint__), 0);

    } else {
      // Case where the section where callbacks are located is **not** in the same
      // current .tls section

      uint64_t relative_offset = offset_callbacks - section_callbacks.offset();
      std::vector<uint8_t> callback_data = section_callbacks.content();

      if (callback_data.size() < (relative_offset + size_needed)) {
        throw builder_error("Don't have enough space to write callbacks");
      }

      for (uint__ callback : tls_obj.callbacks()) {
        std::copy(
          reinterpret_cast<uint8_t*>(&callback),
          reinterpret_cast<uint8_t*>(&callback) + sizeof(uint__),
          callback_data.data() + relative_offset);
        relative_offset += sizeof(uint__);
      }
      section_callbacks.content(callback_data);

    }
  } catch (const not_found&) {
    throw builder_error("Can't find the section which holds callbacks.");
  }


  try {
    Section& section_rawdata = this->binary_->section_from_offset(offset_rawdata);

    const std::vector<uint8_t>& data_template = tls_obj.data_template();
    const uint64_t size_needed = data_template.size();

    if (section_rawdata == *tls_section) {
      // Case where the section where data templates are located in the same
      // than the current .tls section

      const uint64_t relative_offset = offset_rawdata - tls_section->offset();

      data.insert(
          std::begin(data) + relative_offset,
          std::begin(data_template),
          std::end(data_template));

    } else {
      const uint64_t relative_offset = offset_rawdata - section_rawdata.offset();
      std::vector<uint8_t> section_data = section_rawdata.content();
      const std::vector<uint8_t>& data_template = tls_obj.data_template();
      if (section_data.size() < (relative_offset + size_needed)) {
        throw builder_error("Don't have enough space to write data template.");
      }

      std::copy(
          std::begin(data_template),
          std::end(data_template),
          section_data.data() + relative_offset);
      section_rawdata.content(section_data);

    }
  } catch (const not_found&) {
    throw builder_error("Can't find the section which holds 'data_template'.");
  }


  if (data.size() > tls_section->size()) {
    throw builder_error("Builder constructed a bigger section that the original one.");
  }

  data.insert(std::end(data), tls_section->size() - data.size(), 0);
  tls_section->content(data);

}

}
}
