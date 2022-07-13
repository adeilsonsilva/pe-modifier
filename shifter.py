import io
import itertools
import numpy as np
import os
import pefile
import random


class PEShifter:
  """
    This class receives a PE file as input and operates on it by reordering
    its sections.
  """

  def __init__(self,
               _input,
               output_path=None,
               verbose=False):

    # Check if input is a path to a file or raw data
    if isinstance(_input, str) and os.path.isfile(_input):
      self.pe           = pefile.PE(name=_input, fast_load=True)
      self.input_buffer = open(_input, 'rb')
    elif isinstance(_input, np.ndarray):
      self.pe           = pefile.PE(data=_input.tobytes())
      self.input_buffer = io.BytesIO(_input)
    else:
      raise ValueError(f"Input has unknown type {type(_input)}.")

    self.output_path   = output_path
    self.output_buffer = io.BytesIO()
    self.verbose       = verbose

    return

  def combine(self, offsets, data):
    """
      Returns combination of two lists without repetition (kind of a cartesian product)
      https://www.adamsmith.haus/python/answers/how-to-get-all-unique-combinations-of-two-lists-in-python
    Args:
      offsets (list): List with PointerToRawData offsets
      data (bytes): Section data

    Returns:
      list: List of combinations
    """

    all_combinations = []

    list1_permutations = itertools.permutations(offsets, len(data))

    for each_permutation in list1_permutations:
      zipped = zip(each_permutation, data)
      all_combinations.append(list(zipped))

    return all_combinations

  def run(self):
    # Copy raw data to output
    self.input_buffer.seek(0)
    self.output_buffer.write(self.input_buffer.read())
    self.input_buffer.seek(0)
    self.output_buffer.seek(0)

    # Read sections info
    orig = []
    offsets = []
    data    = []
    i = 0
    for s in self.pe.sections:
      if s.PointerToRawData > 0:
        orig.append(i)
        # Tuple with offset where PointerToRawData is written at and its actual value
        offsets.append([s.get_file_offset() + 20, s.PointerToRawData])
        data.append(s.get_data())
      i += 1
    combinations = self.combine(offsets, data)

    # We randomly get the combination
    n_valid_combinations = len(combinations)
    combination_idx    = random.randint(0, n_valid_combinations-1)
    chosen_combination = combinations[combination_idx]
    if self.verbose:
      print(f"\n\t[*] File has {len(n_valid_combinations)} combinations. {combination_idx} idx was chosen;")

    final_data = None
    for o, d in chosen_combination:

      # Update PointerToRawData
      self.output_buffer.seek(o[0])
      self.output_buffer.write(o[1].to_bytes(4, 'little'))

      # Update data
      self.output_buffer.seek(o[1])
      # self.output_buffer.write(os.urandom(8192))
      self.output_buffer.write(d)

      self.output_buffer.seek(0)
      final_data = self.output_buffer.read()

      # Write output path
      if self.output_path is not None:
        out_file_path = f"{self.output_path}_comb_{i}.exe"
        out_file      = open(out_file_path, 'wb')
        out_file.write(final_data)
        if self.verbose:
          pe = pefile.PE(data=final_data)
          print(f"{len(final_data)} bytes written to => {out_file_path}")
          print(f"Final data: {pe.sections}")

    self.input_buffer.close()
    self.output_buffer.close()

    return final_data
