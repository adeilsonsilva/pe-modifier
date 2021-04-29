#include <Injector.hpp>

#include <algorithm>
#include <iostream>
#include <sstream>
#include <utility>      // std::pair
#include <cstring>      // std::memcpy

using namespace peparse;

namespace pe_injector {

Injector::Injector(const std::string &input_path,
                   const std::string &output_path,
                   const uint        &n_bytes)
  : m_input(input_path),
    m_output(output_path),
    m_pe(nullptr),
    m_number_of_injected_bytes(n_bytes),
    m_injection_info({0}),
    m_replaced_section({0})
{ }

Injector::~Injector()
{
  DestructParsedPE(m_pe);
}

void
Injector::run(const bool &use_random_position)
{
  std::cout << m_input << " => " << m_output << std::endl;

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

  /**
   * To avoid using null bytes, the injected section will have a number of
   * bytes multiple of the section alignment flag.
   */
  const uint section_data_size
    = s_FileAlignment * m_number_of_injected_bytes;

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
  /// TODO: find out how to get header offset using peparser
  // m_injection_info.injected_section_header_offset = (
  //     self.pe.sections[-1].get_file_offset()
  // ) + SECTION_HEADER_SIZE

  dumpReplacedSectionInfo();


  Section test(1,2,3,4,5);

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
   std::cout
    << "[@] Injecting section at index " << m_injection_info.injected_section_idx
    << " out of [0, " << m_injection_info.number_of_sections-1
    << "] on offset 0x" << std::hex << m_injection_info.injected_section_data_offset
  << std::endl;

  std::ostringstream name;
  for (auto i: m_replaced_section.Name)
  {
    name << i;
  }

  std::cout
    << "\t [*] Name: " << name.str()
    << " | Misc_VirtualSize: 0x" << std::hex << m_replaced_section.Misc.VirtualSize
    << " | VirtualAddress: 0x" << m_replaced_section.VirtualAddress
    << " | SizeOfRawData: 0x" << m_replaced_section.SizeOfRawData
    << " | PointerToRawData: 0x" << m_replaced_section.PointerToRawData
    << " | NextSectionExpectedOffset: 0x"
      << m_replaced_section.SizeOfRawData + m_replaced_section.PointerToRawData
  << std::endl;
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
        // << "| HeaderOffset: 0x" << s.HeaderOffset
        << " | NextSectionExpectedOffset: 0x"
          << s.SizeOfRawData + s.PointerToRawData
        << " | Data: 0x" << ((data) ? data->bufLen : 0)
      << std::endl;

      return 0;
    },
    &m_injection_info.number_of_sections); // the address we put as the last argument to IterSec is passes as the first arg to our callback
}

}; // end namespacepe_injector
