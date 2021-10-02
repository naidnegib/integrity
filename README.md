# IntegrityChecker
Command to check file integrity (written in python and also packed as Windows .exe)

This command is intended to be used along backup scripts to detect changes and bitrot issues into files. ``IntegrityChecker`` command generates (or verifies) files with checksum information for each file found in the folder. If creating checksums option ``--recursive`` is specified, a checksum file is created within each folder found recursively. 

## Usage

```
usage: IntegrityChecker [-h] [-p] [-a] [-r] [-j] [-c | -f] [-o OUTPUT] [-i]
                        [-t] [-v] [-d]
                        [path]

Create and check integrity checksums and hashes for files in folder

positional arguments:
  path

optional arguments:
  -h, --help            show this help message and exit
  -p, --absolutepath    Save absolute path
  -a, --all             Include all. Do NOT ignore files and folders stating
                        with dot (.)
  -r, --recursive       Process subfolders recursively
  -j, --json            Check/Save hash file using JSON format instead of YAML
  -c, --csv             Generate a CSV file (; delimited) detailing all the
                        files processed
  -f, --fastcsv         Generate a CSV file detailing all the files already
                        processed (use hash files)
  -o OUTPUT, --output OUTPUT
                        Output CSV contents to specified file
  -i, --ignore          Ignore already stored hashes (avoid changes detection)
  -t, --test            Test mode. Does NOT write updates to hash files
  -v, --verbose         Verbose mode
  -d, --debug           Debug mode
```

## CSV Export

The option to export results to CSV can be run in two modes:
* `--csv` : CSV creation by reading files and calculating hashes
* `--fastcsv` : CSV created just by reading already existing hash files (it doesn't check coherence with existing files or folders)

When a CSV file is created with the `--fastcsv` option, format parameters are relevant (`--json`).

The CSV file can be used for analytics such as:
* Looking for duplicated files
* Check offline changed files, files not accessed, ...
* Input for tools such as PowerBI
* Stream for running processes (CSV file is written incrementally), so you can know how many files have been processed in folder structures where hundreds of thousands or millions of files need to be processed. Samples:
  * Windows: `Get-Content ck++.csv | Measure-Object -Line`
  * Linux: `wc -l ck++.csv`
* Comparison between saved and actual hashes (`--fastcsv` and `--test` can provide complimentary information without updating existing hash files)


