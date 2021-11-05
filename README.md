# IntegrityChecker
Command to check file integrity (written in python and also packed as Windows .exe)

This command is intended to be used along backup scripts to detect changes and bitrot issues into files. ``IntegrityChecker`` command generates (or verifies) files with checksum information for each file found in the folder. If creating checksums option ``--recursive`` is specified, a checksum file (`.ck++.nfo`) is created within each folder found recursively. 

By default `.nfo` files are YAML text files, but they can be set to JSON format (`.ck++.json.nfo`) using the `--json` option. All the operations on files are based on selected format.

## Usage

```
usage: IntegrityChecker [-h] [-V] [-p] [-a] [-q] [-e] [-r] [-j] [-c | -f] [-o OUTPUT] [-i] [-t] [-s] [-v] [-d {1,2,3}] [path]

Create and check integrity checksums and hashes for files in folder

positional arguments:
  path

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         Print current version and exits
  -p, --absolutepath    Save absolute path
  -a, --all             Include all. Do NOT ignore files and folders stating with dot (.)
  -q, --quickadd        Quick add new files. Do not check or process already known files
  -e, --empty           Do not write hash files into empty folders (leaving them empty)
  -r, --recursive       Process subfolders recursively
  -j, --json            Check/Save hash file using JSON format instead of YAML
  -c, --csv             Generate a CSV file (; delimited) detailing all the files processed
  -f, --fastcsv         Generate a CSV file detailing all the files already processed (use hash files)
  -o OUTPUT, --output OUTPUT
                        Output CSV contents to specified file. Ignored if a CSV argument is not present.
  -i, --ignore          Ignore already stored hashes (avoid changes detection)
  -t, --test            Test mode. Does NOT write updates to hash files
  -s, --summary         Print a summary of processed files when finish
  -v, --verbose         Verbose mode
  -d {1,2,3}, --debuglevel {1,2,3}
                        Debug level: 1: Verbose (--verbose); 2: Detailed; 3: Debug
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
  * Windows: `date ; Get-Content ck++.csv | Measure-Object -Line`
  * Linux: `date ; wc -l ck++.csv`
* Comparison between saved and actual hashes (`--fastcsv` and `--test` can provide complimentary information without updating existing hash files)


## Examples

When processing folder structures with a high number of files it is recommended to use CSV options so you can later process all the information with aditional tools.

### Check version number:

Minor release versions should maintain `.nfo` files compatibility, so this check may become relevant:

`IntegrityChecker -V`

### Run recursively generating an specific CSV output:

`IntegrityChecker -rco file.csv Base-Folder-to-Explore/`

If you don't want to generate files in folders where there are not files to hash:

`IntegrityChecker -reco file.csv Base-Folder-to-Explore/`

### Generate a quick CSV if a previous hash was written:

`IntegrityChecker -rfo file.csv Base-Folder-to-Explore/`

It can be useful to automate changes detection between multiple runs.
Not only to existing files, but for detecting other changes such as:
* New files and folders created
* Files moved

# Building

`IntegrityChecker` Dependencies:
* `pyyaml`
* `colorama`

# Changelog

## v0.4
* File name for JSON files changed from `.ck++.nfoj` to `.ck++.json.nfo`
* `--debug` replaced by debug level `--debuglevel`
* Description (out of verbose mode), in color, for New, Changed and unchanged (Ok) files
* `--summay` partly implemented to start offering results
* `--quickadd` (not refined) to add new files into checksums ignoring the already existing ones
* Strings and constants moved to `constants.py`

## v0.3
* Version output (`--version`)
* Output CSV to specified file (`--output`)
* Option to avoid generating `.nfo` files on folders where nothing is being hashed (`--empty`)

## v0.2
* Export to CSV option (`--csv`)
* Generate a CSV without processing files, just by using existing `.nfo` files (`--fastcsv`)
* UTF-8 encoding by default
* Detected bugs (file management) solved

## v0.1
* Icon for the Windows .EXE executable
* Config file for using Auto-Py-to-Exe for .exe generation
* Recursive mode (`--recursive`)
* Debug mode (`--debug`)
* Store absolute path if required (`--absolutepath`)
* Include/ignore files starting with a dot (`--all`)
* Save results into `.nfo` files using JSON format (`--json`)
* Basic functionality to work and process parameters


# Backlog

List of features being considered to be implemented:

- [WIP] 'Continue'... to update only those files that are not already hashed
- Pre-scan: Generate initial statistics of files to process in order to offer an estimated progress bar or %
- Upgrade summary:
  - Folders
    - Processed folders
    - Empty folders
  - Processed files (processed hashes)
    - Omitted files (currently only folders are considered)
- Offer multiple hasing algorithms
- Set CSV field delimitator
- Comparisson commands (i.e. life comparisson or only-CSV-based) --> New command (Testing WIP using Pandas)
  - Mirror mode
  - CSV Analysis
    - Duplicated files
    - Changed files
    - Summary from CSV
    - Compare 2 CSVs to find different hashes on entries with same metadata
    - Ignore relative paths if everything is equal
- Check only one file (against local .nfo or general .csv) so it can be scripted


# Known Bugs

List of known bugs or limitations currently detected on the applications:

- Nothing here still... testing needed