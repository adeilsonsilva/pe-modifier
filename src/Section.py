import math
import numpy as np
import random

class InjectedSection:
  """
      This class represents a section of a PE32 executable file.
      Here we define all necessary bytes to construct a new section.

      SOURCES:
      [1] https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
      [2]https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers
      [2] https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
  """

  def __init__ (self,
                payload_size,
                file_alignment,
                section_alignment,
                raw_offset,
                virtual_offset,
                payload=None):
    """
      Section constructor.

      Keyword arguments:
      payload_size  --
    """

    # Generate random payload if none is given
    self.payload_size = payload_size
    if (payload is None):
      self.payload = self.generate_payload(payload_size)
    else:
      print("\t[@@] Using {} bytes long payload".format(payload.shape[0]))
      self.payload = payload.tobytes()


    #######################################
    ### Section Table (Section Headers) ###
    #######################################

    # "An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8
    # characters long, there is no terminating null. " [1]
    self.Name = b'.cnn' + self.generate_payload(3, start=33, stop=126) + b'\x00'

    """
      'For executable images, this must be a multiple of FileAlignment
      from the optional header. If this is less than VirtualSize, the
      remainder of the section is zero-filled.'

      SOURCES:
      https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

      The size (in bytes) of the section in the disk
      We might need to pad with zeros to match the FileAlignment
    """
    self.SizeOfRawData = self.align(self.payload_size, file_alignment)

    """
      "If a section contains only uninitialized data, set this member is zero."

      SOURCES:
      https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header

      Address of section data in file, we just set it to the same
      value as the section we are replacing (then we fix that later).
    """
    self.PointerToRawData = raw_offset

    """
      'For executable images, the address of the first byte of the section
      relative to the image base when the section is loaded into memory.'

      SOURCES:
      https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers

      We will copy it from the section we are "replacing"
      It is the virtual offset from the last section when loaded to memory
      (last_section.VirtualAddress + last_section.VirtualSize)
    """
    self.VirtualAddress = self.align(virtual_offset, section_alignment) # it will be placed after the last section in memory

    # The amount of memory the loader will allocate for this section. As
    # we don't want it to be executed, we can set it to 0 and it won't take
    # space in memory
    self.VirtualSize = 0

    # "The flags that describe the characteristics of the section.".
    # (it is 4 bytes long)
    # self.characteristics = 0x40000000 	# READ
    # self.characteristics = bytes.fromhex('40000000') 	# READ
    flags = 0x40000000 | 0x00000040 # IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
    self.characteristics = flags.to_bytes(4, 'little')

    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ #
    # @@@@@@@ UNUSED HEADER INFO @@@@@@@ #
    # @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ #

    # "This is set to zero for executable images or if there are no relocations."
    # (it is 4 bytes long)
    self.PointerToRelocations = b'\x00\x00\x00\x00'

    # "This value should be zero for an image because COFF debugging information is deprecated."
    # (it is 4 bytes long)
    self.PointerToLinenumbers = b'\x00\x00\x00\x00'

    # "The number of relocation entries for the section. This is set to zero for executable images."
    # (it is 2 bytes long)
    self.NumberOfRelocations = b'\x00\x00'

    # "The number of line-number entries for the section. This value should be zero for an image because COFF debugging information is deprecated."
    # (it is 2 bytes long)
    self.NumberOfLinenumbers = b'\x00\x00'

    #############################

    # Generate data
    self.set_header()
    self.set_data()

    return

  def align(self, val_to_align, alignment):
    """
      Method to calculate section alignments.
    """
    return math.ceil(val_to_align/alignment) * alignment

  def generate_payload(self, n_bytes, start=0, stop=255):
    """
      Generate random payload with 'n_bytes' size.
    """
    return bytes([random.randint(start, stop) for b in range(n_bytes)])

  def gen_padding_bytes(self, n_bytes):
    """
      To align a section to the alignment size, we
      might need to pad it with zero bytes
    """
    return bytes(n_bytes)

  def get_full_section(self):
    """
      Get all bytes representing a section, including header
    """
    return self.header + self.data

  def get_size(self):
    """
      Get all bytes representing a section, including header
    """
    return len(self.get_full_section())

  def set_header(self):
    print(
        "\n\t [+] InjectedSection: {{ Name: {} | " \
        "VirtualSize: {} | " \
        "VirtualAddress: {} | " \
        "SizeOfRawData: {} | " \
        "PointerToRawData: {} | " \
        "PointerToRelocations: {} | " \
        "PointerToLinenumbers: {} | " \
        "NumberOfRelocations: {} | " \
        "NumberOfLinenumbers: {} | " \
        "Characteristics: {} }}\n" \
        .format(
            self.Name \
            , self.VirtualSize.to_bytes(4, 'little') \
            , self.VirtualAddress.to_bytes(4, 'little') \
            , self.SizeOfRawData.to_bytes(4, 'little') \
            , self.PointerToRawData.to_bytes(4, 'little') \
            , self.PointerToRelocations \
            , self.PointerToLinenumbers \
            , self.NumberOfRelocations \
            , self.NumberOfLinenumbers \
            , self.characteristics
        )
    )

    self.header = self.Name \
        + self.VirtualSize.to_bytes(4, 'little') \
        + self.VirtualAddress.to_bytes(4, 'little') \
        + self.SizeOfRawData.to_bytes(4, 'little') \
        + self.PointerToRawData.to_bytes(4, 'little') \
        + self.PointerToRelocations \
        + self.PointerToLinenumbers \
        + self.NumberOfRelocations \
        + self.NumberOfLinenumbers \
        + self.characteristics

    return 0

  def set_data(self):
    self.data = self.payload + self.gen_padding_bytes(self.SizeOfRawData - self.payload_size)

    return

