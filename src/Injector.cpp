#include <Injector.hpp>

#include <algorithm> // std::lock_guard
#include <iostream>  // std::cout
#include <sstream>   // std::ostringstream
#include <utility>   // std::pair
#include <fstream>   // std::fstream::open / std::fstream::close
#include <random>    // std::random_device

using namespace peparse;

namespace pe_injector {

Injector::Injector(const std::string &input_path,
                   const std::string &middleware_path,
                   const std::string &output_path,
                   const uint        &n_bytes)
: m_input(input_path),
  m_output(output_path),
  m_middleware(middleware_path),
  m_pe(nullptr),
  m_number_of_injected_bytes(n_bytes),
  m_injection_info({0}),
  m_pe_info({0}),
  m_replaced_section({0})
{

}

Injector::Injector(const std::string &input_path,
                   const std::string &output_path,
                   const uint        &n_bytes)
  : Injector(input_path,
             std::string(""),
             output_path,
             n_bytes)
{ }

Injector::~Injector()
{
  DestructParsedPE(m_pe);
}

void
Injector::run(const bool &use_random_position)
{
  std::lock_guard<std::mutex> g(m_mutex);

  std::cout << m_input << " => " << m_output << std::endl;

  if (!m_middleware.empty())
    std::cout << "Using " << m_middleware << " as middleware." << std::endl;

  /* Parse input file */
  m_pe = peparse::ParsePEFromFile(m_input.c_str());

  if (m_pe == nullptr)
  {
    std::cout
      << "Error: " << peparse::GetPEErr()
      << " (" << peparse::GetPEErrString() << ")"
      << std::endl;

    std::cout
      << "Location: " << peparse::GetPEErrLoc()
    << std::endl;

    return;
  }

  std::cout << "\n\t\t[*] @@@@@@@ BEFORE INJECTION @@@@@@@" << std::endl;
  getPEInfo(m_pe, m_pe_info, m_injection_info);

  /**
   * TODO: test edge case
   *
   * We get the miminum between NumberOfSections and the size of the
   * sections array read by pefile becuse for some malware examles with too many
   * virtual sections, this injection process is not working properly (after
   * sucessfuly adding one section, trying to add the second). The bytes
   * are added, the NumberOfSections increases, but the header is lost.
   */
  m_injection_info.number_of_sections
    = std::min(m_pe->peHeader.nt.FileHeader.NumberOfSections,
               m_injection_info.number_of_sections);

  /**
   * To avoid using null bytes, the injected section will have a number of
   * bytes multiple of the section alignment flag.
   */
  m_injection_info.length = m_pe_info.FileAlignment * m_number_of_injected_bytes;

  if (use_random_position)
  {
    // We randomly get the position of the new section

    // https://stackoverflow.com/questions/5008804/generating-random-integer-from-a-range/19728404#19728404

    // only used once to initialise (seed) engine
    std::random_device rd;
    // random-number engine used (Mersenne-Twister in this case)
    std::mt19937 rng(rd());
    // guaranteed unbiased
    std::uniform_int_distribution<uint>
      dist(0, m_injection_info.number_of_sections);

    m_injection_info.injected_section_idx = dist(rng);
  }
  else
  {
    // We insert at the end
    m_injection_info.injected_section_idx = m_injection_info.number_of_sections;
  }

  const bool injecting_at_the_end
    = (m_injection_info.injected_section_idx == m_injection_info.number_of_sections);

  if (injecting_at_the_end)
  {
    /**
     * If we are injecting at the end, we don't need to replace
     * anything. We just set the raw offset to be after every byte of the file.
     * Header still needs to be at the right place, tough.
     */
    if (getSectionInfo(m_injection_info.number_of_sections-1,
                       m_replaced_section))
    {
      m_injection_info.injected_section_data_offset
        = m_replaced_section.PointerToRawData + m_replaced_section.SizeOfRawData;
    }
  }
  else
  {
    /**
     * We need to check if the section being replaced is virtual or misaligned,
     * so we can put our section at the right offset. This is done by
     * checking if the PointerToRawData is a multiple of FileAlignment.
     */
    if (getSectionInfo(m_injection_info.injected_section_idx,
                       m_replaced_section))
    {
      const uint section_raw_size   = m_replaced_section.SizeOfRawData;
      const uint section_raw_offset = m_replaced_section.PointerToRawData;

      if (
        section_raw_size == 0 || ((section_raw_offset % m_pe_info.FileAlignment) != 0)
      ) {
        uint correct_idx = m_injection_info.injected_section_idx;

        if (m_injection_info.injected_section_idx == 0)
        {
          // If the first section is being replaced, get the one right after
          correct_idx = m_injection_info.injected_section_idx+1;
        }
        else if (m_injection_info.injected_section_idx == m_injection_info.number_of_sections-1)
        {
          /// If the last section is being replaced, get the one before
          correct_idx = m_injection_info.injected_section_idx-1;
        }
        else
        {
          // If something in the middle, just loop through all sections and
          // get the first aligned one
          for (int idx = 0; idx < m_injection_info.number_of_sections; idx++)
          {
            peparse::image_section_header tmp_section = {0};
            if (
              getSectionInfo(idx, tmp_section) &&
              ((tmp_section.PointerToRawData % m_pe_info.FileAlignment) == 0) &&
              (tmp_section.SizeOfRawData != 0)
            ) {
              correct_idx = idx;
            }
          }
        }

        std::cout << "\n[*] Changing from idx " << m_injection_info.injected_section_idx << " to " << correct_idx << " because it is virtual." << std::endl;

        m_injection_info.injected_section_idx = correct_idx;
        getSectionInfo(m_injection_info.injected_section_idx,
                       m_replaced_section);
      }

      // We set the data offset in the file at the same position of the
      // section being replaced
      m_injection_info.injected_section_data_offset
        = m_replaced_section.PointerToRawData;
    }
  }

  /// In the header, our injected section will always be the last one, even
  /// if the order on disk is different (to avoid moving header bytes when
  /// saving the file).
  m_injection_info.injected_section_header_offset = getSectionHeaderOffset();

  // New section will be placed after the last one in memory, to preserve
  // functionality
  peparse::image_section_header last_section = {0};
  if (!getSectionInfo(m_injection_info.number_of_sections-1, last_section))
  {
    throw std::runtime_error("Could not get last section.");
  }
  m_injection_info.Virtual_Offset = last_section.VirtualAddress + last_section.Misc.VirtualSize;


  dumpReplacedSectionInfo();

  // If a middleware is given, use it as source for the data of the new section,
  // use random bytes otherwise
  if (m_middleware.empty())
  {
    m_injected_section = std::make_unique<Section>(
      Section(m_injection_info.length,
              m_pe_info.FileAlignment,
              m_pe_info.SectionAlignment,
              m_injection_info.injected_section_data_offset,
              m_injection_info.Virtual_Offset
              ));
  }
  else
  {
    std::vector<std::uint8_t> payload(m_injection_info.length);

    /* Parse middleware file */
    auto middleware = peparse::ParsePEFromFile(m_input.c_str());

    if (middleware == nullptr)
    {
      std::cout
        << "Error: " << peparse::GetPEErr()
        << " (" << peparse::GetPEErrString() << ")"
        << std::endl;

      std::cout
        << "Location: " << peparse::GetPEErrLoc()
      << std::endl;

      return;
    }

    // only used once to initialise (seed) engine
    std::random_device rd;
    // random-number engine used (Mersenne-Twister in this case)
    std::mt19937 rng(rd());
    // guaranteed unbiased
    std::uniform_int_distribution<uint>
      dist(0, middleware->fileBuffer->bufLen - m_injection_info.length - 1);

    const auto r_idx = dist(rng);

    for (uint j = 0; j < m_injection_info.length; j++)
    {
      payload[j] = middleware->fileBuffer->buf[r_idx + j];
    }

    m_injected_section = std::make_unique<Section>(
      Section(payload,
              m_pe_info.FileAlignment,
              m_pe_info.SectionAlignment,
              m_injection_info.injected_section_data_offset,
              m_injection_info.Virtual_Offset
              ));
  }

  write_injected_file();

  fix_file();

  /* Dump output info */

  std::cout << "\n\t\t[*] @@@@@@@ AFTER INJECTION @@@@@@@" << std::endl;

  const auto output_pe = peparse::ParsePEFromFile(m_output.c_str());
  FileInfo output_pe_info = {0};
  InjectionInfo _t = {0};
  if (output_pe == nullptr)
  {
    std::cout
      << "Error: " << peparse::GetPEErr()
      << " (" << peparse::GetPEErrString() << ")"
      << std::endl;

    std::cout
      << "Location: " << peparse::GetPEErrLoc()
    << std::endl;

    return;
  }

  getPEInfo(output_pe, output_pe_info, _t);

}

std::uint32_t
Injector::getSectionHeaderOffset(const int &index)
{
  std::uint32_t offset = 0x0;

  // get the offset to the NT headers
  // "At location 0x3c, the stub has the file offset to the PE signature." [1]
  offset += m_pe->peHeader.dos.e_lfanew;

  // "After the MS-DOS stub, at the file offset specified at offset 0x3c, is a
  //  4-byte signature that identifies the file as a PE format image file."
  offset += 4;

  // "At the beginning of an object file, or immediately after the signature
  //  of an image file, is a standard COFF file header (...) "
  offset += sizeof(file_header);

  /**
   * "Each row of the section table is, in effect, a section header. This table
   *  immediately follows the optional header, if any. This positioning is
   *  required because the file header does not contain a direct pointer to the
   *  section table. Instead, the location of the section table is determined
   *  by calculating the location of the first byte after the headers. Make
   *  sure to use the size of the optional header as specified in the file
   *  header." [1]
   */
  offset += m_pe->peHeader.nt.FileHeader.SizeOfOptionalHeader;

  if (index == -1)
  {
    offset += (SECTION_HEADER_SIZE * m_injection_info.number_of_sections);
  }
  else if (index >= 0 && index < m_injection_info.number_of_sections)
  {
    offset += (SECTION_HEADER_SIZE * index);
  }
  else
  {
    throw std::runtime_error("Invalid index");
  }

  return offset;
}

bool
Injector::getSectionInfo(const uint &index,
                         peparse::image_section_header &target_section)
{
  struct LookupTable final {
    uint target_idx;
    uint current_idx;
    peparse::image_section_header section;
    bool found;
  };

  LookupTable lt = {index, 0, {0}, false};

  peparse::IterSec(m_pe,
    [] (void *N,
        const VA &secBase,
        const std::string &secName,
        const image_section_header &s,
        const bounded_buffer *data
    ) -> int
    {
      static_cast<void>(s);

      LookupTable* lt = static_cast<LookupTable *>(N);

      if (lt->current_idx == lt->target_idx)
      {
        lt->section = s;
        lt->found = true;
      }

      lt->current_idx++;

      return 0;
    },
    &lt); // the address we put as the last argument to IterSec is passes as the first arg to our callback

  target_section = lt.section;

  return lt.found;
}


void
Injector::dumpReplacedSectionInfo()
{

  std::cout << "\n\t\t[*] @@@@@@@ COMPUTED INJECTION DATA! @@@@@@@" << std::endl;

  std::cout
    << "\t [@] Injecting section at index " << m_injection_info.injected_section_idx
    << "/" << m_injection_info.number_of_sections-1
    << ": { HeaderOffset: 0x"
    << std::hex << m_injection_info.injected_section_header_offset
    << " | PointerToRawData: 0x" << m_injection_info.injected_section_data_offset
    << " | SizeOfRawData: " << std::dec << m_injection_info.length
    << " | VirtualAddress: 0x" << std::hex << m_injection_info.Virtual_Offset
  << "};" << std::endl;

  std::ostringstream name;
  for (auto i: m_replaced_section.Name)
  {
    name << i;
  }

  if (m_injection_info.injected_section_idx == m_injection_info.number_of_sections)
  {
    std::cout << "\t [*] Injecting after last section: {";
  } else {
    std::cout << "\t [*] Replacing section: {";
  }

  std::cout
    << " Name: " << name.str()
    << " | Misc_VirtualSize: 0x" << std::hex << m_replaced_section.Misc.VirtualSize
    << " | VirtualAddress: 0x" << m_replaced_section.VirtualAddress
    << " | SizeOfRawData: 0x" << m_replaced_section.SizeOfRawData
    << " | PointerToRawData: 0x" << m_replaced_section.PointerToRawData
    << " | NextSectionExpectedOffset: 0x"
      << m_replaced_section.SizeOfRawData + m_replaced_section.PointerToRawData
  << "};" << std::endl;
}

void
Injector::getPEInfo(peparse::parsed_pe *pe,
                    FileInfo           &pe_info,
                    InjectionInfo      &injection_info)
{
  pe_info.AddressOfEntryPoint
    = (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint
    : pe->peHeader.nt.OptionalHeader64.AddressOfEntryPoint;
  pe_info.FileAlignment
    = (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? pe->peHeader.nt.OptionalHeader.FileAlignment
    : pe->peHeader.nt.OptionalHeader64.FileAlignment;
  pe_info.SectionAlignment
    = (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? pe->peHeader.nt.OptionalHeader.SectionAlignment
    : pe->peHeader.nt.OptionalHeader64.SectionAlignment;
  pe_info.SizeOfHeaders
    = (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? pe->peHeader.nt.OptionalHeader.SizeOfHeaders
    : pe->peHeader.nt.OptionalHeader64.SizeOfHeaders;
  pe_info.SizeOfImage
    = (pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? pe->peHeader.nt.OptionalHeader.SizeOfImage
    : pe->peHeader.nt.OptionalHeader64.SizeOfImage;

  std::cout
    << "[+] AddressOfEntryPoint: 0x"
      << std::hex << pe_info.AddressOfEntryPoint
    << " | NumberOfSections: "
      << pe->peHeader.nt.FileHeader.NumberOfSections
    << " | FileAlignment: "
      << std::dec << pe_info.FileAlignment
    << " | SectionAlignment: "
      << pe_info.SectionAlignment
    << " | SizeOfImage: "
      << pe_info.SizeOfImage
  << std::endl;

  peparse::IterSec(pe,
    [] (void *N,
        const VA &secBase,
        const std::string &secName,
        const image_section_header &s,
        const bounded_buffer *data
    ) -> int
    {
      // cast to int and count the number of sections
      int* n = static_cast<int *>(N);
      static_cast<void>(s);

      // dereference pointer and add to it
      (*n)++;

      std::cout
        << "\t [*] Name: " << secName
        << " | Misc_VirtualSize: 0x" << std::hex << s.Misc.VirtualSize
        << " | VirtualAddress: 0x" << s.VirtualAddress
        << " | SizeOfRawData: 0x" << s.SizeOfRawData
        << " | PointerToRawData: 0x" << s.PointerToRawData
        // << "| HeaderOffset: 0x" << getSectionHeaderOffset(*n)
        << " | NextSectionExpectedOffset: 0x"
          << s.SizeOfRawData + s.PointerToRawData
        << " | Data: 0x" << ((data) ? data->bufLen : 0)
      << std::endl;

      return 0;
    },
    &injection_info.number_of_sections); // the address we put as the last argument to IterSec is passes as the first arg to our callback
}

void
Injector::write_injected_file()
{
  std::lock_guard<std::mutex> g(m_mutex);

  const uint old_sections_offset
    = m_injection_info.injected_section_data_offset + m_injection_info.length;

  std::fstream output_file;
  output_file.open (m_output,
                std::fstream::out | std::fstream::binary |std::fstream::trunc);

  if (!output_file.is_open())
  {
    throw std::runtime_error("Could not open output file.");
  }

  output_file.write(reinterpret_cast<const char*>(m_pe->fileBuffer->buf),
                    m_pe->fileBuffer->bufLen);

  const auto generated_bytes
    = m_injected_section->gen_padding_bytes(m_injection_info.length + SECTION_HEADER_SIZE);
  output_file.write(reinterpret_cast<const char*>(&generated_bytes),
                    generated_bytes.size());

  /* Inject HEADER */

  std::cout
    << "\t[@@] Injecting " << std::dec << m_injected_section->getHeaderSize()
    << " bytes long header at 0x" << std::hex << m_injection_info.injected_section_header_offset
    << std::endl;

  output_file.seekp(m_injection_info.injected_section_header_offset);
  const auto header_data =  m_injected_section->getHeaderData();
  output_file.write(reinterpret_cast<const char*>(&header_data),
                    header_data.size());

  // Add old stuff after new header
  std::cout << "\t[@@] From OLD at 0x"
    << std::hex << m_injection_info.injected_section_header_offset
    << " to NEW at 0x" << output_file.tellp()
  << std::endl;

  // output_file
  //   << m_pe->fileBuffer->buf + m_injection_info.injected_section_header_offset;
  output_file.write(reinterpret_cast<const char*>(m_pe->fileBuffer->buf + m_injection_info.injected_section_header_offset),
                    m_pe->fileBuffer->bufLen - + m_injection_info.injected_section_header_offset);


  /* Inject SECTION DATA */

  std::cout
    << "\t[@@] Injecting section data at 0x"
      << std::hex << m_injection_info.injected_section_data_offset
  << std::endl;

  output_file.seekp(m_injection_info.injected_section_data_offset);
  const auto section_data = m_injected_section->getData();
  output_file.write(reinterpret_cast<const char*>(&section_data),
                    section_data.size());

  // Slide old data back
  std::cout
    << "\t[@@] From OLD at 0x"
      <<  std::hex << m_injection_info.injected_section_data_offset
    << " to NEW at 0x" << old_sections_offset // We get bytes from the old offset
  << std::endl;

  /**
   * We get bytes from the old offset
   * If we are injecting at the end, 'self.injected_section_data_offset' is
   * greater than 'input_file' size. Consequently, 'input_file.read()' will
   * return a null byte.
   */
  output_file.seekp(old_sections_offset);

  auto data_offset
    = m_pe->fileBuffer->buf + m_injection_info.injected_section_data_offset;
  auto n_read
    = m_pe->fileBuffer->bufLen - m_injection_info.injected_section_data_offset;

  // output_file
  //   << data_offset;

  output_file.write(reinterpret_cast<const char*>(data_offset),
                    n_read);

  // Close file
  output_file.close();
}


void
Injector::fix_file()
{
  std::lock_guard<std::mutex> g(m_mutex);

  /* If we are injecting after the last section we don't need to fix anything */
  if (m_injection_info.injected_section_idx ==
      m_injection_info.number_of_sections)
  {
    return;
  }

  std::fstream output_file;
  output_file.open (m_output, std::fstream::in | std::fstream::out | std::fstream::binary);

  if (!output_file.is_open())
  {
    throw std::runtime_error("Could not open output file.");
  }

  std::cout << "\n\t\t[*] @@@@@@@ FIXING FILE! @@@@@@@" << std::endl;

  /**
   * "At location 0x3c, the stub has the file offset to the PE signature. This
   *  information enables Windows to properly execute the image file, even
   *  though it has an MS-DOS stub. This file offset is placed at location 0x3c
   *  during linking." [1]
   *
   * "After the MS-DOS stub, at the file offset specified at offset 0x3c, is a
   *  4-byte signature that identifies the file as a PE format image file." [1]
   *
   * NumberOfSections is at offset 2
   */
  const auto NoS_offset = m_pe->fileBuffer->buf[0x3c] + 6;

  // buffer to NumberOfSections offset
  char NoS_buf[2];
  output_file.seekp(NoS_offset);
  output_file.read(NoS_buf, 2);

  const std::uint16_t _NoS = NoS_buf[0] | NoS_buf[1] << 8;

  const std::uint16_t f_NumberOfSections
    = m_pe->peHeader.nt.FileHeader.NumberOfSections + 1;

  std::cout << "\t[+] [0x" << std::hex << NoS_offset << "] | NumberOfSections: 0x" << _NoS << " => 0x" << f_NumberOfSections << std::endl;

  output_file.seekp(NoS_offset);
  output_file.write(reinterpret_cast<const char*>(&f_NumberOfSections),
                      sizeof(f_NumberOfSections));

  /**
   * Skip the remainder od the FileHeader to get into the OptionalHeader (+18)
   * and get to the SizeOfImage offset (+56)
   */
  const auto SoI_offset = NoS_offset + 18 + 56;

  // buffer to SizeOfImage offset
  char SoI_buf[4];
  output_file.seekp(SoI_offset);
  output_file.read(SoI_buf, 4);

  const std::uint32_t _SoI
    = SoI_buf[0] | SoI_buf[1] << 8 | SoI_buf[2] << 16 | SoI_buf[3] << 24;

   const std::uint32_t _SoI_Original
    =  m_pe->fileBuffer->buf[SoI_offset+0]      |
      m_pe->fileBuffer->buf[SoI_offset+1] << 8  |
      m_pe->fileBuffer->buf[SoI_offset+2] << 16 |
      m_pe->fileBuffer->buf[SoI_offset+3] << 24;

  /**
   * "The size (in bytes) of the image, including all headers, as the image is
   *  loaded in memory. It must be a multiple of SectionAlignment." [3]
   */
  const std::uint32_t f_SizeOfImage
    = Section::align(m_injection_info.Virtual_Offset,
                     m_pe_info.SectionAlignment);

  std::cout << "\t[+] [0x" << std::hex << SoI_offset << "] | SizeOfImage: " << std::dec << _SoI << " => " << _SoI_Original << std::endl;

  output_file.seekp(SoI_offset);
  output_file.write(reinterpret_cast<const char*>(&f_SizeOfImage),
                      sizeof(f_SizeOfImage));

  /**
   * "The combined size of an MS-DOS stub, PE header, and section headers
   *  rounded up to a multiple of FileAlignment." [3]
   */
  const std::uint32_t f_SizeOfHeaders
    = Section::align(m_pe_info.SizeOfHeaders+SECTION_HEADER_SIZE,
                     m_pe_info.FileAlignment);

  const auto SoH_offset = SoI_offset + 4;

  // buffer to NumberOfSections offset
  char SoH_buf[4];
  output_file.seekp(SoH_offset);
  output_file.read(SoH_buf, 4);

  const std::uint32_t _SoH = SoH_buf[0] | SoH_buf[1] << 8 | SoH_buf[2] << 16 | SoH_buf[3] << 24;

  std::cout << "\t[+] [0x" << std::hex << SoH_offset << "] | SizeOfHeaders: 0x" << _SoH << " => 0x" << f_SizeOfHeaders << std::endl;

  output_file.seekp(SoH_offset);
  output_file.write(reinterpret_cast<const char*>(&f_SizeOfHeaders),
                      sizeof(f_SizeOfHeaders));

  /* Fix remainder sections */

  /**
   * Iterate all sections but the last one (the one just injected).
   *
   * TODO: Perform a check to see  how many bytes are there between the last
   * section header and the start of the data. Sometimes, there's not enough
   * room to hold all headers
   */

  for (int k = 0; k < m_injection_info.number_of_sections; k++)
  {
    const auto offset = getSectionHeaderOffset(k);

    std::cout << "[" << k << "] | 0x" << std::hex << offset << " | ";

    for (int j = 0; j < 8; j++)
    {
      std::cout << m_pe->fileBuffer->buf[offset+j];
    }
    output_file.seekp(offset+20);

    char buffer[4] = {0};
    output_file.read(buffer, 4);

    std::uint32_t _PTRD
      = (u_char) buffer[0] | (u_char) buffer[1] << 8 | (u_char) buffer[2] << 16 | (u_char) buffer[3] << 24;
    std::cout << " | PointerToRawData: 0x" << _PTRD;

    auto fixed_PTRD = _PTRD;

    if (_PTRD >= m_injection_info.injected_section_data_offset)
    {
      fixed_PTRD += m_injection_info.length;
      std::cout << " => 0x" << std::hex << fixed_PTRD;
    }

    output_file.seekp(offset+20);
    output_file.write(reinterpret_cast<const char*>(&fixed_PTRD),
                      sizeof(fixed_PTRD));

    std::cout << std::endl;

  }

  output_file.close();

}

}; // end namespacepe_injector
