# integrity
Command line file integrity checker (written in python)

This command is intended to be used along backup scripts to detect changes and bitrot issues into files. ``IntegrityChecker`` command generates (or verifies) files with checksum information for each file found in the folder. If creating checksums option ``--recursive`` is specified, a checksum file is created within each folder found recursively. 

## Usage

```
usage: IntegrityChecker [-h] [-p] [-a] [-r] [-v] [path]

Create and check integrity checksums for files in folder

positional arguments:
  path

optional arguments:

  -h, --help          show this help message and exit
  -p, --absolutepath  Save absolute path when checksum is created
  -a, --all           Include all. Do NOT ignore folders stating with dot (.)
  -r, --recursive     Process subfolders recursively
  -j, --json          Check/Save checksumg file using JSON format instead of
                      YAML
  -c, --csv           Generate a CSV file (; delimited) detailing all the
                      files processed
  -f, --fastcsv       Generate a CSV file detailing all the files already
                      processed (use hash files)
  -i, --ignore        Ignore already stored checksums
  -t, --test          Test mode. Does NOT write updates to checksum files
  -v, --verbose       Verbose mode
  -d, --debug         Debug mode
```


