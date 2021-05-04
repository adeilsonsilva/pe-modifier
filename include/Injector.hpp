/**
 * @file PEInjector.hpp
 * @author your name (you@domain.com)
 * @brief
 * @version 0.1
 * @date 2021-04-27
 *
 * @copyright Copyright (c) 2021
 *
 */

#pragma once

#ifndef INJECTOR_HPP
#define INJECTOR_HPP

#include <Section.hpp>
#include <parser-library/parse.h>

#include <string> // std::string
#include <memory> // std::unique_ptr
#include <mutex>  // std::mutex

namespace pe_injector {

/**
 * @brief We use the following struct to save injection information computed
 * before the new section is generated.
 */
struct InjectionInfo
{
  /// Computed number of sections in the parsed file
  uint16_t number_of_sections;

  /// Index of the injected section in the sections array
  uint injected_section_idx;

  /// Offset in the raw file of the injected HEADER
  uint injected_section_header_offset;

  /// Offset in the raw file of the injected SECTION DATA
  uint injected_section_data_offset;

  /// Size of the data of the injected section
  uint length;

  std::uint32_t Virtual_Offset;
};

/**
 * @brief Some info on the OPTIONAL_HEADER are dependent on the image file
 *        type (PE/PE32+). We use the following struct to make things a bit
 *        easier, as the peparse library handles them eparately.
 */
struct FileInfo
{
  std::uint32_t AddressOfEntryPoint;
  std::uint32_t FileAlignment;
  std::uint32_t SectionAlignment;
  std::uint32_t SizeOfHeaders;
  std::uint32_t SizeOfImage;
};


/**
 * @brief Main class responsible for managing the data injection.
 */
class Injector
{

public:
  Injector(const std::string &input_path,
           const std::string &output_path,
           const uint        &n_bytes=1);

  Injector(const std::string &input_path,
           const std::string &middleware_path,
           const std::string &output_path,
           const uint        &n_bytes=1);

  ~Injector();

  void run(const bool &use_random_position=true);

  std::uint32_t getSectionHeaderOffset(const int &index=-1);

  void getPEInfo(peparse::parsed_pe *pe,
                 FileInfo           &pe_info,
                 InjectionInfo      &injection_info);

  void dumpReplacedSectionInfo();

  bool computeInjectionInfo();

  bool getSectionInfo(const uint &index,
                      peparse::image_section_header &target);

  void write_injected_file();

  /**
   * @brief As the original file was changed, we need to fix its flags and
   *        structure required by the operating system. If a section is being
   *        injected between existing ones we need to fix the offset of those
   *        after the injected one;
   */
  void fix_file();

private:

  /// Path to exe file to be read as input
  std::string m_input;

  /// Path to exe file to be written
  std::string m_output;

  /// Path to exe to be used as source of data to be injected
  std::string m_middleware;

  /// Multiplier of `FileAlignment` to be injected into the file
  uint m_number_of_injected_bytes;

  /// Pointer to the pe file after being parsed
  peparse::parsed_pe *m_pe;

  InjectionInfo  m_injection_info;

  FileInfo m_pe_info;

  peparse::image_section_header m_replaced_section;

  std::unique_ptr<Section> m_injected_section;

  std::mutex m_mutex;

};// end Section class
} // end namespace pe_injector

#endif // INJECTOR_HPP
