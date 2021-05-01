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

  std::cout << "\t\t[*] @@@@@@@ BEFORE INJECTION @@@@@@@" << std::endl;
  dumpPEInfo();

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

  std::uint32_t s_FileAlignment
    = (m_pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? m_pe->peHeader.nt.OptionalHeader.FileAlignment
    : m_pe->peHeader.nt.OptionalHeader64.FileAlignment;

  std::uint32_t s_SectionAlignment
    = (m_pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? m_pe->peHeader.nt.OptionalHeader.SectionAlignment
    : m_pe->peHeader.nt.OptionalHeader64.SectionAlignment;

  /**
   * To avoid using null bytes, the injected section will have a number of
   * bytes multiple of the section alignment flag.
   */
  m_injection_info.length = s_FileAlignment * m_number_of_injected_bytes;

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
        section_raw_size == 0 || ((section_raw_offset % s_FileAlignment) != 0)
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
              ((tmp_section.PointerToRawData % s_FileAlignment) == 0) &&
              (tmp_section.SizeOfRawData != 0)
            ) {
              correct_idx = idx;
            }
          }
        }

        std::cout << "[*] Fixxing idx " << correct_idx << std::endl;
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

  dumpReplacedSectionInfo();

  // New section will be placed after the last one in memory, to preserve
  // functionality
  auto s_Virtual_Offset = m_replaced_section.VirtualAddress + m_replaced_section.Misc.VirtualSize;

  // If a middleware is given, use it as source for the data of the new section,
  // use random bytes otherwise
  if (m_middleware.empty())
  {
    m_injected_section = std::make_unique<Section>(
      Section(m_injection_info.length,
              s_FileAlignment,
              s_SectionAlignment,
              m_injection_info.injected_section_data_offset,
              s_Virtual_Offset
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
              s_FileAlignment,
              s_SectionAlignment,
              m_injection_info.injected_section_data_offset,
              s_Virtual_Offset
              ));
  }


  write_injected_file();

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
    offset += (SECTION_HEADER_SIZE * ((index) + 1));
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

  std::cout << "\t\t[*] @@@@@@@ COMPUTED INJECTION DATA! @@@@@@@" << std::endl;

  std::cout
    << "\t [@] Injecting section at index " << m_injection_info.injected_section_idx
    << "/" << m_injection_info.number_of_sections-1
    << ": { HeaderOffset: 0x"
    << std::hex << m_injection_info.injected_section_header_offset
    << " | PointerToRawData: 0x" << m_injection_info.injected_section_data_offset
    << " | SizeOfRawData: " << std::dec << m_injection_info.length
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
Injector::dumpPEInfo()
{
  std::uint32_t entryPoint
    = (m_pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? m_pe->peHeader.nt.OptionalHeader.AddressOfEntryPoint
    : m_pe->peHeader.nt.OptionalHeader64.AddressOfEntryPoint;
  std::uint32_t fileAlignment
    = (m_pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? m_pe->peHeader.nt.OptionalHeader.FileAlignment
    : m_pe->peHeader.nt.OptionalHeader64.FileAlignment;
  std::uint32_t sectionAlignment
    = (m_pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? m_pe->peHeader.nt.OptionalHeader.SectionAlignment
    : m_pe->peHeader.nt.OptionalHeader64.SectionAlignment;
  std::uint32_t imageSize
    = (m_pe->peHeader.nt.OptionalMagic == NT_OPTIONAL_32_MAGIC)
    ? m_pe->peHeader.nt.OptionalHeader.SizeOfImage
    : m_pe->peHeader.nt.OptionalHeader64.SizeOfImage;

  std::cout
    << "[+] AddressOfEntryPoint: 0x"
      << std::hex << entryPoint
    << " | NumberOfSections: "
      << m_pe->peHeader.nt.FileHeader.NumberOfSections
    << " | FileAlignment: "
      << std::dec << fileAlignment
    << " | SectionAlignment: "
      << sectionAlignment
    << " | SizeOfImage: "
      << imageSize
  << std::endl;

  peparse::IterSec(m_pe,
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
    &m_injection_info.number_of_sections); // the address we put as the last argument to IterSec is passes as the first arg to our callback
}

void
Injector::write_injected_file()
{
  std::lock_guard<std::mutex> g(m_mutex);

  const uint old_sections_offset
    = m_injection_info.injected_section_data_offset + m_injection_info.length;

  std::fstream output_file;
  output_file.open (m_output, std::fstream::out | std::fstream::trunc);

  if (!output_file.is_open())
  {
    throw std::runtime_error("Could not open output file.");
  }

  output_file.write(reinterpret_cast<const char*>(m_pe->fileBuffer->buf),
                    m_pe->fileBuffer->bufLen);

  const auto generated_bytes
    = m_injected_section->gen_padding_bytes(m_injection_info.length + SECTION_HEADER_SIZE);
  for (auto &b : generated_bytes)
  {
    output_file << b;
  }

  /* Inject HEADER */

  std::cout
    << "\t\t[@@] Injecting " << m_injected_section->getHeaderSize()
    << " bytes long header at 0x" << m_injection_info.injected_section_header_offset
    << std::endl;

  output_file.seekp(m_injection_info.injected_section_header_offset);
  const auto header_data =  m_injected_section->getHeaderData();
  for (auto &b : header_data)
  {
    output_file << b;
  }

  // Add old stuff after new header
  std::cout << "\t\t[@@] From OLD at 0x"
    << std::hex << m_injection_info.injected_section_header_offset
    << " to NEW at 0x" << output_file.tellp()
  << std::endl;

  // output_file
  //   << m_pe->fileBuffer->buf + m_injection_info.injected_section_header_offset;
  output_file.write(reinterpret_cast<const char*>(m_pe->fileBuffer->buf + m_injection_info.injected_section_header_offset),
                    m_pe->fileBuffer->bufLen - + m_injection_info.injected_section_header_offset);


  /* Inject SECTION DATA */

  std::cout
    << "\t\t[@@] Injecting section data at 0x"
      << std::hex << m_injection_info.injected_section_data_offset
  << std::endl;

  output_file.seekp(m_injection_info.injected_section_data_offset);
  const auto section_data = m_injected_section->getData();
  for (auto &b : section_data)
  {
    output_file << b;
  }

  // Slide old data back
  std::cout
    << "\t\t[@@] From OLD at 0x"
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

  output_file
    << data_offset;

  output_file.write(reinterpret_cast<const char*>(data_offset),
                    n_read);

  // Close file
  output_file.close();
}

}; // end namespacepe_injector
