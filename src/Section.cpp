#include <Section.hpp>
#include <iostream> // std::cout
#include <cmath>    // std::ceil

namespace pe_injector
{

Section::Section(const uint     &payload_size,
                 const uint32_t &file_alignment,
                 const uint32_t &section_alignment,
                 const uint     &raw_offset,
                 const uint32_t &virtual_offset,
                 const bool     &generate_data)
  : m_payload(payload_size),
    m_distribution(0, 255)

{
  // Make name a bit more random
  auto name = generate_payload(3, 33, 126);
  m_Name[4] = name[0];
  m_Name[5] = name[1];
  m_Name[6] = name[2];

  std::random_device rd;
  m_rng.seed(rd());

  m_SizeOfRawData = align(payload_size, file_alignment);

  std::cout
    << "\t [*] align ("
    << payload_size
    << ", " << file_alignment
    << ") => " << m_SizeOfRawData
  << std::endl;

  m_PointerToRawData = raw_offset;

  // it will be placed after the last section in memory
  m_VirtualAddress = align(virtual_offset, section_alignment);

  setHeader();

  if (generate_data)
  {
    m_payload = generate_payload(payload_size);
    setData();
  }
}

Section::Section(const std::vector<std::uint8_t>   &payload,
                 const uint32_t                    &file_alignment,
                 const uint32_t                    &section_alignment,
                 const uint                        &raw_offset,
                 const uint32_t                    &virtual_offset)
  : Section(payload.size(),
            file_alignment,
            section_alignment,
            raw_offset,
            virtual_offset,
            false)
{
  m_payload = payload;
  setData();
}


uint
Section::align(const uint &src,
               const uint &target)
{
  return std::ceil((double) src / (double) target) * target;
}

void
Section::setHeader()
{
  // Copy section Name
  std::copy(m_Name.begin(), m_Name.end(), m_Header.begin());

  // Copy section VirtualSize
  std::copy(m_VirtualSize.begin(),
            m_VirtualSize.end(),
            m_Header.begin() + 8);

  /* Copy uint values converting to little endian */

  m_Header.at(12) = (m_VirtualAddress >> (8*0)) & 0xff;
  m_Header.at(13) = (m_VirtualAddress >> (8*1)) & 0xff;
  m_Header.at(14) = (m_VirtualAddress >> (8*2)) & 0xff;
  m_Header.at(15) = (m_VirtualAddress >> (8*3)) & 0xff;

  m_Header.at(16) = (m_SizeOfRawData >> (8*3)) & 0xff;
  m_Header.at(17) = (m_SizeOfRawData >> (8*2)) & 0xff;
  m_Header.at(18) = (m_SizeOfRawData >> (8*1)) & 0xff;
  m_Header.at(19) = (m_SizeOfRawData >> (8*0)) & 0xff;

  m_Header.at(20) = (m_PointerToRawData >> (8*3)) & 0xff;
  m_Header.at(21) = (m_PointerToRawData >> (8*2)) & 0xff;
  m_Header.at(22) = (m_PointerToRawData >> (8*1)) & 0xff;
  m_Header.at(23) = (m_PointerToRawData >> (8*0)) & 0xff;

  std::copy(m_PointerToRelocations.begin(),
            m_PointerToRelocations.end(),
            m_Header.begin() + 24);

  std::copy(m_PointerToLinenumbers.begin(),
            m_PointerToLinenumbers.end(),
            m_Header.begin() + 28);

  std::copy(m_NumberOfRelocations.begin(),
            m_NumberOfRelocations.end(),
            m_Header.begin() + 32);

  std::copy(m_NumberOfLinenumbers.begin(),
            m_NumberOfLinenumbers.end(),
            m_Header.begin() + 34);

  std::copy(m_Characteristics.begin(),
            m_Characteristics.end(),
            m_Header.begin() + 36);
}

void
Section::setData()
{
  auto padding = gen_padding_bytes(m_SizeOfRawData - m_payload.size());

  m_Data.clear();
  m_Data.reserve(m_payload.size() + padding.size());
  m_Data.insert( m_Data.begin(), m_payload.begin(), m_payload.end() );
  m_Data.insert( m_Data.end(), padding.begin(), padding.end() );
}

void
Section::setData(const std::vector<std::uint8_t> &data)
{
  m_Data = data;
}

std::vector<std::uint8_t>
Section::generate_payload(const uint &size,
                          const uint &low,
                          const uint &high)
{
  std::vector<std::uint8_t> result(size);

  for (int n = 0; n < size; n++)
  {
    const uint number = m_distribution(m_rng);
    if (number >= low && number <= high)
    {
      result.at(n) = number;
    }
  }

  return result;
}

std::vector<std::uint8_t>
Section::gen_padding_bytes(const uint &size)
{
  std::vector<std::uint8_t> result(size);

  for (int n = 0; n < size; n++)
  {
    result.at(n) = 0;
  }

  return result;
}

} // end pe_injector namespace
