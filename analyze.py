# analyze.py 
# A.K.A. IntegrityAnalyzer
import sys
import argparse
import os
from typing import Any
from datetime import datetime
from pathlib import Path
from io import StringIO
from colorama import Fore #, Back, Style
import pandas as pd
import numpy as np
import time

# Constants and strings
ANALYZE_DEFAULT_ENCODING = 'utf8'
ANALYZE_DESC = "IntegrityAnalyzer"
ANALYZE_TYPE = "ChecksumAnalysis"
ANALYZE_VERSION = "0.1"
INTEGRITY_HASH_FILENAME = ".ck++.nfo"
INTEGRITY_HASH_FILENAME_JSON = ".ck++.json.nfo"
INTEGRITY_HASH_FILENAME_CSV = "ck++.csv"

VALUE_DEFAULT_SEPARATOR = ';'
VALUE_VERBOSE_INFO = 1
VALUE_VERBOSE_DETAIL = 2
VALUE_VERBOSE_DEBUG = 3

TXT_V_ARGS = "Arguments detected: %s"
TXT_V_HOUR_FORMAT = "%H:%M:%S"


TXT_PROG = ANALYZE_DESC
TXT_DESCRIPTION = "Analyze integrity hashes from IntegrityChecker-generated CSV files"

#TXT_HELP_ABSOLUTE_PATH = "Save absolute path"
#TXT_HELP_CSV = "Generate a CSV file (; delimited) detailing all the files processed"
#TXT_HELP_CSV_FAST = "Generate a CSV file detailing all the files already processed (use hash files)"
TXT_HELP_DEBUG = "Debug level: 1: Verbose (--verbose); 2: Detailed; 3: Debug"
#TXT_HELP_EMPTY = "Do not write hash files into empty folders (leaving them empty)"
#TXT_HELP_JSON = "Check/Save hash file using JSON format instead of YAML"
#TXT_HELP_RECURSIVE = "Process subfolders recursively"
#TXT_HELP_IGNORE = "Ignore already stored hashes (avoid changes detection)"
#TXT_HELP_IGNORE_DOTS = "Include all. Do NOT ignore files and folders stating with dot (.)"
#TXT_HELP_OUTPUT = "Output CSV contents to specified file. Ignored if a CSV argument is not present."
#TXT_HELP_SUMMARY = "Print a summary of processed files when finish"
#TXT_HELP_TEST = "Test mode. Does NOT write updates to hash files"
TXT_HELP_VERBOSE = "Verbose mode"
TXT_HELP_FILES = "CSV files to compare"
TXT_HELP_VERSION = "Print current version and exits"

# CSV Entries: path, filename, size, changed, hash, oldhash, date, modification
TXT_O_CSV_HEADER = "PATH;FILENAME;SIZE;CHANGED;HASH;PREV_HASH;DATE;MODIFICATION"
TXT_O_CSV_LINE = "\"%s\";\"%s\";%s;\"%s\";\"%s\";\"%s\";\"%s\";\"%s\""
TXT_O_ELAPSED_TIME = "Elapsed time: %s"
TXT_O_VERSION = "%s Version %s"

## main ##
def main():
    # Start timer for measuring processing
    start_time = time.time()
    # Parse command-line parameters and adjust values
    parser = argparse.ArgumentParser(description=TXT_DESCRIPTION, prog=TXT_PROG)
    parser.add_argument('file', nargs=2, type=str, help=TXT_HELP_FILES)
    parser.add_argument('-V', '--version', action='store_true', help=TXT_HELP_VERSION)
    #parser.add_argument('-p', '--absolutepath', action='store_true', help=TXT_HELP_ABSOLUTE_PATH)
    parser.add_argument('-v', '--verbose', action='store_true', help=TXT_HELP_VERBOSE)
    parser.add_argument('-d', '--debuglevel', type=int, choices=[1, 2, 3], default=0, help=TXT_HELP_DEBUG)

    args = parser.parse_args()
    path = os.getcwd()

    if args.version:
        print(TXT_O_VERSION % (ANALYZE_DESC, ANALYZE_VERSION))
        return

    args.debuglevel = 1 if int(args.verbose) > args.debuglevel else args.debuglevel
    
    if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_ARGS % (args))

    # Run process
    #processFolder(path, args, csv_file)

    # try:
    df_file1 = pd.read_csv(args.file[0], sep=VALUE_DEFAULT_SEPARATOR)

    # Amount of duplicated hashes
    print(df_file1.duplicated(subset='HASH').sum())

    #Option 1: duplicated Ids dataframe
    hashes = df_file1["HASH"]
    df_file1_duplicated_hashes = df_file1[hashes.isin(hashes[hashes.duplicated()])]
    print(df_file1_duplicated_hashes)

    #Option 2: Duplicated values grouped by hash and file size (slower)
    df_file1_grouped_duplicates = pd.concat(g for _, g in df_file1.groupby(["HASH", "SIZE"]) if len(g) > 1)
    print(df_file1_grouped_duplicates)
    
    # Calculate processing time
    end_time = time.time()
    elapsed_time_str = time.strftime(TXT_V_HOUR_FORMAT, time.gmtime(end_time-start_time))
    if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_O_ELAPSED_TIME % elapsed_time_str)

    print (TXT_O_ELAPSED_TIME % elapsed_time_str)

if __name__ == '__main__':
    main()