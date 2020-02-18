# integrity
Command line file integrity checker (in python)

This command is intended to be used along backup scripts to detect changes and bitrot issues into files. ``integrity`` command generates (or verifies) files with checksum information for each file found in the folder. If creating checksums option ``--recursive`` is specified, a checksum file is created within each folder found recursively. 

## Usage

```
usage: IntegrityChecker [-h] [-p] [-a] [-r] [-v] [path]

Create and check integrity checksums for files in folder

positional arguments:
  path

optional arguments:
  -h, --help          show this help message and exit
  -p, --absolutepath  Save absolute path when checksum was created
  -a, --all           Include all. Do NOT ignore folders stating with dot (.)
  -r, --recursive     Process subfolders recursively
  -v, --verbose       Verbose mode
```


