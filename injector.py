# The header of a section is 40 bytes long

"""
Two options, regarding updating the sections references:

- Parse the file and ask user to confirm the changes
- Parse the file changing all references (it might break functionality)

It is possible that adding to the beginning (or middle) of the file
exploits another vulnerability of Nataraj's method, as it discards
bytes from the end of the file when transforming them into images
"""

from .section import InjectedSection

import io
import numpy as np
import os
import pefile
import random

# The size of a section header in the file
SECTION_HEADER_SIZE = 40

class PEInjector:

  def __init__(self,
               input_path,
               n_bytes,
               n_sections_to_inject=1,
               middleware_path=None,
               output_path=None,
               verbose=False):

    self.input_path           = input_path
    self.middleware_path      = middleware_path
    self.output_path          = output_path
    self.n_bytes              = n_bytes
    self.n_sections_to_inject = n_sections_to_inject
    self.buffer               = io.BytesIO()
    self.verbose              = verbose

    return

  def run(self, randomly=True):
    # Load input file and set basic file info
    self.pe = pefile.PE(name=self.input_path, fast_load=True)

    # Inject first section
    pe_data = self.__inject(randomly)

    injections = 1

    while injections < self.n_sections_to_inject:
      self.pe = pefile.PE(data=pe_data) # Reload pe info using injection result
      pe_data = self.__inject(randomly) # Run injection again

      injections += 1

    return pe_data

  def __inject(self, randomly=True):
    """
        Main method to inject new sections at the file.
    """

    if self.verbose:
      print("\t\t[*] @@@@@@@ BEFORE INJECTION @@@@@@@")
      self.print_debug_info()

    # TODO: test edge case
    # We get the miminum between NumberOfSections and the size of the
    # sections array read by pefile becuse for some malware examles with too many
    # virtual sections, this injection process is not working properly (after
    # sucessfuly adding one section, trying to add the second). The bytes
    # are added, the NumberOfSections increases, but the header is lost.
    self.n_sections = min(self.pe.FILE_HEADER.NumberOfSections,
                          len(self.pe.sections))

    """
        To avoid using null bytes, the injected section will have a number of
        bytes multiple of the section alignment flag.
    """
    self.injected_section_length = self.pe.OPTIONAL_HEADER.FileAlignment * self.n_bytes

    if randomly:
        # We randomly get the position of the new section
        self.injected_section_idx = random.randint(0, self.n_sections)
    else:
        # We insert at the end
        self.injected_section_idx = self.n_sections

    injecting_at_the_end = (self.injected_section_idx == self.n_sections)

    if injecting_at_the_end:
      """
          If we are injecting at the end, we don't need to replace
          anything. We just set the raw offset to after every byte of the file. Header still needs to be at the right place, tough
      """
      self.replaced_section = self.pe.sections[-1]
      self.injected_section_data_offset = self.replaced_section.PointerToRawData + self.replaced_section.SizeOfRawData
    else:
      """
          We need to check if the section being replaced is virtual or desaligned,
          so we can put our section at the right offset. This is done by looking if
          the PointerToRawData is a multiple of FileAlignment.
      """
      section_raw_size = self.pe.sections[self.injected_section_idx].SizeOfRawData
      section_raw_offset = self.pe.sections[self.injected_section_idx].PointerToRawData
      file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
      if (
          (section_raw_size == 0)
          or ((section_raw_offset % file_alignment) != 0)
      ):
          correct_idx = self.injected_section_idx

          if self.injected_section_idx == 0:
              # If the first section is being replaced, get the one right after
              correct_idx = self.injected_section_idx+1
          elif (self.injected_section_idx == self.n_sections-1):
              # If the last section is being replaced, get the one before
              correct_idx = self.injected_section_idx-1
          else:
              # If something in the middle, just loop through all sections and
              # get the first aligned one
              for section_idx in range(self.n_sections):
                  if (
                      (self.pe.sections[section_idx].PointerToRawData % self.pe.OPTIONAL_HEADER.FileAlignment) == 0
                      and (self.pe.sections[section_idx].SizeOfRawData != 0)
                  ):
                      correct_idx = section_idx
          if self.verbose:
            print("\n[*] Changing from idx {} to {} because it is virtual".format(self.injected_section_idx, correct_idx))
          self.injected_section_idx = correct_idx

      # We set the data offset in the file at the same position of the
      # section being replaced
      self.replaced_section = self.pe.sections[self.injected_section_idx]
      self.injected_section_data_offset = self.replaced_section.PointerToRawData

    # In the header, our injected section will always be the last one, even
    # if the order on disk is different (to avoid moving header bytes when
    # saving the file).
    self.injected_section_header_offset = (
        self.pe.sections[-1].get_file_offset()
    ) + SECTION_HEADER_SIZE

    # New section will be placed after the last one in memory, to preserve
    # functionality
    self.injected_section_virtual_offset = self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize

    if self.verbose:
      print("\n\t\t[*] @@@@@@@ COMPUTED INJECTION DATA! @@@@@@@")
      print(
        "\t [@] Injecting section at index {}/{}:{{ HeaderOffset: {} | " \
        "PointerToRawData: {} | SizeOfRawData: {} | VirtualAddress: {} }}"
        .format(
            self.injected_section_idx,
            self.pe.FILE_HEADER.NumberOfSections-1,
            hex(self.injected_section_header_offset),
            hex(self.injected_section_data_offset),
            self.injected_section_length,
            hex(self.injected_section_virtual_offset)
        )
      )

      if (injecting_at_the_end):
        print("\t [*] Injecting after last section: { ", end='')
      else:
        print("\t [*] Replacing section: { ", end='')

      print(
        "Name: {} | " \
        "VirtualSize: {} | " \
        "VirtualAddress: {} | " \
        "SizeOfRawData: {} | " \
        "PointerToRawData: {} | " \
        "NextSectionExpectedOffset: {} }}\n" \
        .format(
            self.replaced_section.Name.decode('utf-8') \
            , self.replaced_section.Misc_VirtualSize \
            , self.replaced_section.VirtualAddress \
            , self.replaced_section.SizeOfRawData \
            , self.replaced_section.PointerToRawData \
            , hex(self.replaced_section.PointerToRawData + self.replaced_section.SizeOfRawData)
        )
      )

    # Get a random chunk of data from middleware if one is given
    payload = None
    if (self.middleware_path is not None):
      middleware_data = np.fromfile(self.middleware_path, dtype='uint8')
      offset = random.randint(0,
                              middleware_data.shape[0] - self.injected_section_length - 1)
      payload = middleware_data[offset:offset+self.injected_section_length]

    # Compute section data
    self.injected_section = InjectedSection(
      self.injected_section_length,
      self.pe.OPTIONAL_HEADER.FileAlignment,
      self.pe.OPTIONAL_HEADER.SectionAlignment,
      self.injected_section_data_offset,
      # New section will be placed after the last one in memory, to keep functionality
      self.pe.sections[-1].VirtualAddress + self.pe.sections[-1].Misc_VirtualSize,
      payload,
      verbose=self.verbose
    )


    # Create output file
    self.write_buffer()

    # Fix sections offset
    self.fix_file()

    self.buffer.seek(0)
    final_data = self.buffer.read()

    if (self.output_path is not None):
      output_file = open(self.output_path, 'wb')
      output_file.write(final_data)
      output_file.close()

    # Show after save
    self.pe = pefile.PE(data=final_data)

    if self.verbose:
      print("\n\t\t[*] @@@@@@@ AFTER INJECTION @@@@@@@@")
      self.print_debug_info()

    return final_data

  def write_buffer(self):
    """
        Creates new file with more bytes to support new section
    """

    old_sections_offset = self.injected_section_data_offset + self.injected_section.SizeOfRawData

    input_file = open(self.input_path, 'rb')

    # Copy contents from original file
    self.buffer.write(input_file.read())
    # Append new bytes to increase file size
    self.buffer.write(
        self.injected_section.gen_padding_bytes(
            self.injected_section.SizeOfRawData +
            SECTION_HEADER_SIZE
        )
    )

    # Inject HEADER
    if self.verbose:
      print("\t[@@] Injecting {} bytes long header at {}.".format(
          len(self.injected_section.header),
          hex(self.injected_section_header_offset)
      ))
    self.buffer.seek(self.injected_section_header_offset)
    self.buffer.write(self.injected_section.header)

    # Add old stuff after new header
    if self.verbose:
      print("\t[@@] From OLD at {} to NEW at {}.".format(
          hex(self.injected_section_header_offset),
          hex(self.buffer.tell())
      ))
    input_file.seek(self.injected_section_header_offset)
    self.buffer.write(input_file.read())

    # Inject NEW SECTION
    if self.verbose:
      print("\t[@@] Injecting section data at {}.".format(
          hex(self.injected_section_data_offset)
      ))
    self.buffer.seek(self.injected_section_data_offset)
    self.buffer.write(self.injected_section.data)

    # Slide old data back
    if self.verbose:
      print("\t[@@] From OLD at {} to NEW at {}.".format(
          # We get bytes from the old offset
          hex(self.injected_section_data_offset),
          hex(old_sections_offset)
      ))
    # We get bytes from the old offset
    # If we are injecting at the end, 'self.injected_section_data_offset' is
    # greater than 'input_file' size. Consequently, 'input_file.read()' will
    # return a null byte.
    input_file.seek(self.injected_section_data_offset)
    self.buffer.seek(old_sections_offset)
    self.buffer.write(input_file.read())

    # Close files
    input_file.close()

    return

  def fix_file(self):
    """
        As the original file was changed, we need to fix its flags and
        structure required by the operating system.
    """

    if self.verbose:
      print("\n\t\t[*] @@@@@@@ FIXING FILE! @@@@@@@")

    #"At location 0x3c, the stub has the file offset to the PE signature. This
    # information enables Windows to properly execute the image file, even
    # though it has an MS-DOS stub. This file offset is placed at location 0x3c
    # during linking." [1]
    #
    # "After the MS-DOS stub, at the file offset specified at offset 0x3c, is a
    # 4-byte signature that identifies the file as a PE format image file." [1]
    #
    # NumberOfSections is at offset 2
    NoS_offset = self.pe.get_dword_from_offset(0x3c) + 6

    self.buffer.seek(NoS_offset)
    _NoS               = int.from_bytes(self.buffer.read(2), 'little')
    f_NumberOfSections = self.pe.FILE_HEADER.NumberOfSections + 1

    if self.verbose:
      print("\t[+] [{}] | NumberOfSections: {} => {}".format(hex(NoS_offset), _NoS, f_NumberOfSections))

    self.buffer.seek(NoS_offset)
    self.buffer.write(f_NumberOfSections.to_bytes(2, 'little'))


    # Skip the remainder od the FileHeader to get into the OptionalHeader (+18)
    # and get to the SizeOfImage offset (+56)
    SoI_offset = NoS_offset + 18 + 56

    self.buffer.seek(SoI_offset)
    _SoI               = int.from_bytes(self.buffer.read(4), 'little')

    # "The size (in bytes) of the image, including all headers, as the image is
    # loaded in memory. It must be a multiple of SectionAlignment." [3]
    f_SizeOfImage = self.injected_section.align(
      self.injected_section.VirtualSize + self.injected_section.VirtualAddress, self.pe.OPTIONAL_HEADER.SectionAlignment
    )

    if self.verbose:
      print("\t[+] [{}] | SizeOfImage: {} => {}".format(hex(SoI_offset), _SoI, f_SizeOfImage))

    self.buffer.seek(SoI_offset)
    self.buffer.write(f_SizeOfImage.to_bytes(4, 'little'))


    # "The combined size of an MS-DOS stub, PE header, and section headers
    #  rounded up to a multiple of FileAlignment." [3]
    f_SizeOfHeaders = self.injected_section.align(
      self.pe.OPTIONAL_HEADER.SizeOfHeaders+SECTION_HEADER_SIZE,
      self.pe.OPTIONAL_HEADER.FileAlignment
    )

    SoH_offset = SoI_offset + 4
    self.buffer.seek(SoH_offset)
    _SoH = int.from_bytes(self.buffer.read(4), 'little')

    if self.verbose:
      print("\t[+] [{}] | SizeOfHeaders: {} => {}".format(hex(SoH_offset), _SoH, f_SizeOfHeaders))

    self.buffer.seek(SoH_offset)
    self.buffer.write(f_SizeOfHeaders.to_bytes(4, 'little'))

    # Iterate all sections but the last one (the one just injected)
    #
    # TODO: Perform a check to see  how many bytes are there between the last
    # section header and the start of the data. Sometimes, there's not enough
    # room to hold all headers
    n_sections = min(self.pe.FILE_HEADER.NumberOfSections, len(self.pe.sections))
    for section_idx in range(n_sections):
      section = self.pe.sections[section_idx]
      offset  = section.get_file_offset()

      self.buffer.seek(offset+20)
      _PTRD = int.from_bytes(self.buffer.read(4), 'little')

      if self.verbose:
        print("[{}] | {} | {} | PointerToRawData: {}".format(section_idx, hex(offset), section.Name.decode('utf-8'), hex(_PTRD)), end='')

      fixed_PTRD = _PTRD

      if _PTRD >= self.injected_section_data_offset:
        fixed_PTRD += self.injected_section_length
        if self.verbose:
          print(" => {}".format(hex(fixed_PTRD)), end='')

      self.buffer.seek(offset+20)
      self.buffer.write(fixed_PTRD.to_bytes(4, 'little'))

      print()

    return

  def get_injected_payload(self):

    data = self.injected_section.payload

    print(
        "Size: {} | Raw Data: {}"
        .format(
            len(data),
            data
        )
    )

    return

  def print_debug_info(self):

    print(
        "[+] AddressOfEntryPoint: {} | "\
        "NumberOfSections: {} | "\
        "FileAlignment: {} | "\
        "SectionAlignment: {} | " \
        "SizeOfImage: {} | " \
        .format(
            hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            self.pe.FILE_HEADER.NumberOfSections,
            self.pe.OPTIONAL_HEADER.FileAlignment,
            self.pe.OPTIONAL_HEADER.SectionAlignment,
            self.pe.OPTIONAL_HEADER.SizeOfImage,
        )
    )

    for section in self.pe.sections:
        print(
            "\t [*] Name: {} | " \
            "Misc_VirtualSize: {} | " \
            "VirtualAddress: {} | " \
            "SizeOfRawData: {} | " \
            "PointerToRawData: {} | " \
            "HeaderOffset: {} | " \
            "NextSectionExpectedOffset: {} " \
            # "data: {}" \
            .format(
                section.Name.decode('utf-8'),
                hex(section.Misc_VirtualSize),
                hex(section.VirtualAddress),
                hex(section.SizeOfRawData),
                hex(section.PointerToRawData),
                hex(section.get_file_offset()),
                hex(section.SizeOfRawData + section.PointerToRawData),
                # len(section.get_data())
            )
        )
