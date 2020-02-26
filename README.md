# <img src=".pics/Lexxeous/lexx_headshot_clear.png" width="100px"/> Lexxeous's Entry Point Disassembly: <img src=".pics/Linux/linux_logo.png" width="100"/>

### Summary:
This is a **Linux** based, **Python** powered program that takes a list of executables, disassembles them at their entry points, outputs header information about the programs and `.text` sections, and informs the user if the program contains branch type instructions. Unique disassembly information is outputted to separate output files for convenience. This program is a precursor basic block binary file analysis for assembly.

The **Python** script takes advantage of the following packages:

1. [Capstone](https://www.capstone-engine.org/)
2. [Pyelftools](https://github.com/eliben/pyelftools)
3. [Pyinstaller](https://www.pyinstaller.org/)

### Usage:
By default, the `Makefile` provides a few commands to disassemble a local `make` and `python3` distribution, as well as disassembling a compiled, executable version of `entry_point.py`.

Basic usage is as follows:

This is the manual way to disassemble any desired executable.
```bash
python3 entry_point.py <whitespace_separated_list_of_executable_paths>
```

This will disassemble a local `make` executable, if one exists.
```bash
make run_def
```

This will disassemble local `make` and `python3` executables, if they exist, as well as the local `entry_point` executable in the `dist/entry_point/` directory.
```bash
make run_3
```

> See the `Makefile` for a few more useful commands.