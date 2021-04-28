#include <Section.hpp>
#include <iostream>
#include <cmath>

namespace pe_injector
{

Section::Section(const uint &payload_size,
                 const uint &file_alignment,
                 const uint &section_alignment,
                 const uint &raw_offset,
                 const uint &virtual_offset,
                 const bool &generate_data)
{
  // TODO: generate name randomly
  // self.Name = b'.cnn\x00\x00\x00\x00'

  m_SizeOfRawData = align(payload_size, file_alignment);

  std::cout
    << "\n\n\t\t[*]align ( "
    << payload_size
    << ", " << file_alignment
    << ") => " << m_SizeOfRawData
  << std::endl;

  m_PointerToRawData = raw_offset;

  // it will be placed after the last section in memory
  m_VirtualAddress = align(virtual_offset, section_alignment);

  setHeader();

  if (generate_data)
    setData();
}

Section::Section(const std::vector<std::byte> &payload,
                 const uint                    &file_alignment,
                 const uint                    &section_alignment,
                 const uint                    &raw_offset,
                 const uint                    &virtual_offset)
  : Section(payload.size(),
            file_alignment,
            section_alignment,
            raw_offset,
            virtual_offset,
            false)
{
  setData(payload);
}


uint
Section::align(const uint &src,
               const uint &target)
{
  return std::ceil((double) src/ (double) target) * target;
}

void
Section::setHeader()
{}

void
Section::setData()
{}

void
Section::setData(const std::vector<std::byte> &data)
{
  m_Data = data;
}

} // end pe_injector namespace
