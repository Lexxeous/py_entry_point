def_exe := `which make`
three_exes := dist/entry_point/entry_point `which make` `which python3`

# Disassemble.
run_def:
	python3 entry_point.py $(def_exe)

# Disassemble list of three executables, including a compiled version of "entry_point.py".
run_3:
	python3 entry_point.py $(three_exes)

# Remove all output disassembly files.
clean:
	rm disassembly* *.spec

# Display the filtered symbol table for <def_exe>.
def_fsymbs:
	readelf -s $(def_exe) | grep _start

# Display the programs ELF header information for <def_exe>.
def_phead:
	readelf -h $(def_exe)