#!/usr/bin/env python3
''' Will disassemble a list of executables at their entry points and ouput to seperate disassembly files. '''

import sys
from capstone import *
from elftools.elf.elffile import ELFFile

# Convert from ELF tools to constants used by Capstone.
decoder_ring = {
  'EM_386': CS_ARCH_X86,
  'EM_X86_64': CS_ARCH_X86,
  'ELFCLASS32': CS_MODE_32,
  'ELFCLASS64': CS_MODE_64
}

OUTFILE = "disassembly"
EXT = ".txt"

def main():
  # Command line argument error checking.
  if(len(sys.argv) < 2):
    print("Expected at least one executable (binary file) as an input argument.")
    exit()

  file_count = 0 # counter for list of command line arguments

  for filename in sys.argv[1:]:
    file_count += 1 # disassembling the next executable argument
    outfile_name = OUTFILE + str(file_count) + EXT # form unique disassembly output file name

    print("\nDisassembling: %s..." % filename)
    with open(filename, "rb") as f:
    # Try to decode as ELF.
      try:
        elf = ELFFile(f)
      except:
        print("Could not parse the file as ELF; cannot continue.")
        exit()

      # Convert and check to see if we support the file.
      bits = decoder_ring.get(elf['e_ident']['EI_CLASS'], None)
      arch = decoder_ring.get(elf['e_machine'], None)
      if arch is None:
        print("Unsupported architecture: %s" % elf['e_machine'])
        exit()
      if bits is None:
        print("Unsupported bit width: %s" % elf['e_ident']['EI_CLASS'])
        exit()

      # Get the .text segment's data.
      section_name = ".text"
      section = elf.get_section_by_name(section_name)
      if not section:
        print("No", section_name, "section found in file; file may be stripped or obfuscated.")
        exit()
      code = section.data()

      # Set up options for disassembly of the text segment.
      md = Cs(arch, bits)
      md.skipdata = True
      md.detail = True

      # Calculate entry point offset.
      top_addr = section.header.sh_addr
      entry_point = elf.header.e_entry
      offset = entry_point - top_addr
      if(offset < 0 or offset >= section.header.sh_size):
        print("Entry point is not in", section_name, "section.")
        exit()

      # Track whether we have found branches.
      branches = False

      # Disassemble the ELF file.
      with open(outfile_name, 'w') as of:
        # Print section and program header information.
        print("Disassembling: %s...\n" % filename, file=of)
        print("-"*50, file=of)
        print("Top Address of", section_name, "Section:", top_addr, file=of)
        print("\nProgram Entry Point Address:", entry_point, file=of)
        print("\nAddress Offset:", offset, file=of)
        print("\nSection header for", section_name, ":", section.header, file=of)
        print("\nProgram header:", elf.header, "\n", file=of)
        print("-"*50, file=of)
        
        # Disassemble at the entry point.
        for i in md.disasm(code[offset:], entry_point):
          print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str), file=of)
          if 1 in i.groups or 7 in i.groups:
            branches = True
          if (len(i.groups) > 0): print("\t\tInstruction group(s):", i.groups, "\n",file=of)

      # Indicate if the executable contains instructions from a branch/jump type instruction group.
      if branches:
        print(filename, "contains branch type instructions.")

if __name__ == "__main__":
  main()


'''
-------------------------------------------------
First, install the "pyinstaller" Python library if you want to compile this script into an executable to disassemble.

pip3 install pyinstaller
pyinstaller dist/entry_point/entry_point.py

Executable for entry_point.py is in the dist/entry_point/ directory.

-------------------------------------------------

readelf -h dist/entry_point/entry_point
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401a45
  Start of program headers:          64 (bytes into file)
  Start of section headers:          1877768 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         8
  Size of section headers:           64 (bytes)
  Number of section headers:         29
  Section header string table index: 28

readelf -s dist/entry_point/entry_point | grep _start
Symbol Table (filtered):
  33: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (3)
  40: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__

-------------------------------------------------

readelf -h `which make`
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0xace0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          221000 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         28
  Section header string table index: 27

readelf -s `which make` | grep _start
Symbol Table (filtered):
    60: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (2)
    70: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
   125: 0000000000238b38     4 OBJECT  GLOBAL DEFAULT   25 commands_started
   139: 000000000001c850   246 FUNC    GLOBAL DEFAULT   14 output_start
   205: 0000000000235000     0 NOTYPE  WEAK   DEFAULT   24 data_start
   207: 000000000000ace0    43 FUNC    GLOBAL DEFAULT   14 _start
   288: 0000000000235000     0 NOTYPE  GLOBAL DEFAULT   24 __data_start
   326: 0000000000235e10     0 NOTYPE  GLOBAL DEFAULT   25 __bss_start

-------------------------------------------------

readelf -h `which python3`
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x5b2fb0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          4524728 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         9
  Size of section headers:           64 (bytes)
  Number of section headers:         27
  Section header string table index: 26

readelf -s `which python3`
Symbol Table (filtered):
  55: 0000000000000000     0 NOTYPE  WEAK   DEFAULT  UND __gmon_start__
  85: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND __libc_start_main@GLIBC_2.2.5 (2)
 511: 00000000009b4ea0     0 NOTYPE  GLOBAL DEFAULT   23 __data_start
 588: 0000000000a50988     0 NOTYPE  GLOBAL DEFAULT   24 __bss_start
1044: 000000000063c960   268 OBJECT  GLOBAL DEFAULT   15 _Py_startswith__doc__
1251: 00000000005b2fb0    43 FUNC    GLOBAL DEFAULT   13 _start
1473: 00000000005b6ab0    17 FUNC    GLOBAL DEFAULT   13 _Py_bytes_startswith
1975: 00000000009b4ea0     0 NOTYPE  WEAK   DEFAULT   23 data_start
2139: 0000000000632010   171 FUNC    GLOBAL DEFAULT   13 PyThread_start_new_thread

-------------------------------------------------
'''