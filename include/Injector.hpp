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

#include <string>
#include <random>

namespace pe_injector {

class Injector
{

public:
  Injector(const std::string &input_path,
           const std::string &output_path,
           const uint        &n_bytes=1);

  ~Injector();

  void run(const bool &use_random_position=true);

  void dumpPEInfo();

  void dumpReplacedSectionInfo();

  bool computeInjectionInfo();

  bool getSectionInfo(const uint &index,
                      peparse::image_section_header &target);

private:

  /// Path to exe file to be read as input
  std::string m_input;

  /// Path to exe file to be written
  std::string m_output;

  /// Multiplier of `FileAlignment` to be injected into the file
  uint m_number_of_injected_bytes;

  /// Pointer to the pe file after being parsed
  peparse::parsed_pe *m_pe;

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

  } m_injection_info;

  peparse::image_section_header m_replaced_section;

};// end Section class
} // end namespace pe_injector

#endif // INJECTOR_HPP
