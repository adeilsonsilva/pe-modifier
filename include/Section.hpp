/**
 * @file Section.hpp
 * @author Adeilson Silva (adeilson@protonmail.com)
 * @brief
 * @version 0.1
 * @date 2021-04-27
 *
 * @copyright Copyright (c) 2021
 *
 */

#pragma once

#ifndef SECTION_HPP
#define SECTION_HPP

#include <array>
#include <vector>
#include <cstddef>

/// The header of a section is 40 bytes long. [1]
#define SECTION_HEADER_SIZE 40

namespace pe_injector {

/**
 * @brief This class defines a Section to be injected into a PE32 file.
 *
 * [1] https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
 * [2] https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
 */
class Section
{

public:

  /**
   * @brief Construct a new Section object with a random payload
   *
   * @param payload_size      Size of the randomly generated payload
   * @param file_alignment
   * @param section_alignment
   * @param raw_offset
   * @param virtual_offset
   */
  Section(const uint &payload_size,
          const uint &file_alignment,
          const uint &section_alignment,
          const uint &raw_offset,
          const uint &virtual_offset,
          const bool &generate_data=true);

  /**
   * @brief Construct a new Section object with a given payload.
   *
   * @param payload           Data to be used as payload.
   * @param file_alignment
   * @param section_alignment
   * @param raw_offset
   * @param virtual_offset
   */
  Section(const std::vector<std::byte> &payload,
          const uint                    &file_alignment,
          const uint                    &section_alignment,
          const uint                    &raw_offset,
          const uint                    &virtual_offset);

  /**
   * @brief Destroy the Section object
   */
  ~Section() {};

private:

  /**
   * @brief The set of bytes that representing this section's header.
   */
  std::array<std::byte, SECTION_HEADER_SIZE> m_Header;

  /**
   * @brief The set of bytes representing this section's data.
   */
  std::vector<std::byte> m_Data;
  /**
   * @brief The set of bytes representing some of the bytes in this section's
   * data array. It can be either randomly generated or set with data from
   * other files.
   */
  std::vector<std::byte> m_payload;

  /**
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
   @@@@@@@@ PE32 HEADER INFO @@@@@@@@
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
   */


  /// Section name must be equal to 8 (ASCII) bytes
  std::array<std::byte, 8> m_Name = { std::byte{42}, std::byte{99}, std::byte{110}, std::byte{110}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0} };

  /**
   * "For executable images, this must be a multiple of FileAlignment
   * from the optional header. If this is less than VirtualSize, the
   * remainder of the section is zero-filled." [1]
   *
   * The size (in bytes) of the section in the disk.
   * We might need to pad with zeros to match the FileAlignment.
   */
  uint m_SizeOfRawData;

  /**
   * "If a section contains only uninitialized data, set this member is zero."[2]
   *
   * Address of section data in file, we just set it to the same value as the
   * section we are replacing (then we fix that later).
   */
  uint m_PointerToRawData;

  /**
   * "For executable images, the address of the first byte of the section
   * relative to the image base when the section is loaded into memory." [1]
   *
   * We will copy it from the section we are "replacing". It is the virtual
   * offset from the last section when loaded to memory
   * (last_section.VirtualAddress + last_section.VirtualSize)
   */
  uint m_VirtualAddress;

  /// The amount of memory the loader will allocate for this section. As
  /// we don't want it to be executed, we can set it to 0 and it won't take
  /// space in memory
  uint m_VirtualSize = 0;

  /// "The flags that describe the characteristics of the section.".
  /// (it is 4 bytes long).
  std::array<std::byte, 8> m_characteristics
    = { std::byte{static_cast<unsigned char>(0x40000000 | 0x00000040)} }; // IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA

  /**
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
   @@@@@@@ UNUSED HEADER INFO @@@@@@@
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
   */

  /// "This is set to zero for executable images or if there are no
  /// relocations." (it is 4 bytes long)
  std::array<std::byte, 4> m_PointerToRelocations
    = { std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};

  /// "This value should be zero for an image because COFF debugging
  /// information is deprecated." (it is 4 bytes long)
  std::array<std::byte, 4> m_PointerToLinenumbers = { std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};

  /// "The number of relocation entries for the section. This is set to zero
  /// for executable images." (it is 2 bytes long)
  std::array<std::byte, 2> m_NumberOfRelocations = { std::byte{0}, std::byte{0} };

  /// "The number of line-number entries for the section. This value should be
  /// zero for an image because COFF debugging information is deprecated."
  /// (it is 2 bytes long)
  std::array<std::byte, 2> m_NumberOfLinenumbers = { std::byte{0}, std::byte{0} };


  /**
   * @brief Method to compute section alignments.
   *
   * @param src    Value to be aligned.
   * @param target Target value of the alignment.
   *
   * @return uint
   */
  uint align(const uint &src,
             const uint &target);

  void setHeader();

  void setData();

  void setData(const std::vector<std::byte> &data);

};// end Section class
} // end namespace pe_injector

#endif // SECTION_HPP
