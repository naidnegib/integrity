# integrity.py
# Create/check files parity recursively
import sys
import argparse
import os
import hashlib
import yaml
import json
from datetime import datetime
from pathlib import Path
from io import StringIO

time_zone = None


KEY_CREATION = "creation"
KEY_DESC = "generator" 
KEY_FILE_NAME = "file"
KEY_FILE_SIZE = "size"
KEY_FILE_CHANGED_DATE = "changed"
KEY_FILE_CREATION_DATE = "date"
KEY_FILE_CHECK_DATE = "checked"   # Date when this file was used to check all the files listed within
KEY_PATH = "path"
KEY_PREVIOUS_VALUE = "previous"
KEY_RESOURCES = "resources"
KEY_HASH = "sha256"
KEY_TYPE = "type"
KEY_VERSION = "version"

VALUE_HASH_NOT_READ = "ERROR!"

INTEGRITY_DESC = "IntegrityChecker"
INTEGRITY_TYPE = "ChecksumInventory"
INTEGRITY_VERSION = "0.2"
INTEGRITY_HASH_FILENAME = ".ck++.nfo"
INTEGRITY_HASH_FILENAME_JSON = ".ck++.nfoj"
INTEGRITY_HASH_FILENAME_CSV = "ck++.csv"

TXT_PROG = INTEGRITY_DESC
TXT_DESCRIPTION = "Create and check integrity checksums and hashes for files in folder"

TXT_HELP_ABSOLUTE_PATH = "Save absolute path"
TXT_HELP_CSV = "Generate a CSV file (; delimited) detailing all the files processed"
TXT_HELP_CSV_FAST = "Generate a CSV file detailing all the files already processed (use hash files)"
TXT_HELP_DEBUG = "Debug mode"
TXT_HELP_JSON = "Check/Save hash file using JSON format instead of YAML"
TXT_HELP_RECURSIVE = "Process subfolders recursively"
TXT_HELP_IGNORE = "Ignore already stored hashes (avoid changes detection)"
TXT_HELP_IGNORE_DOTS = "Include all. Do NOT ignore files and folders stating with dot (.)"
TXT_HELP_TEST = "Test mode. Does NOT write updates to hash files"
TXT_HELP_VERBOSE = "Verbose mode"

TXT_V_ARGS = "Arguments detected: %s"
TXT_V_EXISTING_HASH = "%s"
TXT_V_FILE_NOT_HASHED = "\t\t'%s' not hashed previously"
TXT_V_FILES_COUNT = "Detected %d items in folder"
TXT_V_FILES_CURRENT = "\tResource %d/%d"
TXT_V_FILES_DIRECTORY = "\t\tFolder: '%s'"
TXT_V_FILES_IGNORED_DOTFILE = "\t\tIgnoring file (--all not set): '%s'"
TXT_V_FILES_INPUT_CONTENTS = "------------------- CONVERTED FILE %s READ ----------------------\n%s -------------------- END OF OBJECT ---------------------\n"
TXT_V_FILES_INPUT_OK = "%s found and read!"
TXT_V_FILES_FILE = "\t\tProcessing file: '%s'"
TXT_V_FILES_OUTPUT_CONTENTS = "------------------- FILE %s TO DUMP ----------------------\n%s -------------------- END OF FILE ---------------------\n"
TXT_V_FILES_OUTPUT_OK = "%s saved properly"
TXT_V_FILES_READING_INPUT = "Warning: '%s' can't read previous information"
TXT_V_GENERATING_HASHES = "Generating hashes for directory: %s"
TXT_V_PROCESSING_EXISTING_HASHES = "Processing already existing hashes for directory: %s"

#TXT_O_CSV_LINE = "\"%s\"\t\"%s\"\t%s\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t\"%s\"\t" # path, filename, size, changed, hash, oldhash, date, modification
TXT_O_CSV_LINE = "\"%s\";\"%s\";%s;\"%s\";\"%s\";\"%s\";\"%s\";\"%s\"" # path, filename, size, changed, hash, oldhash, date, modification

TXT_O_FILES_CHANGED = "File '%s' changed! From: '%s' to: '%s'"

TXT_E_ACCESS = "Error: '%s' failed to be accessed"
TXT_E_FILES_WRITING_OUTPUT = "Error: Can't write to %s"
TXT_E_FILES_INFO_READ = "Error: While retrieving info for file '%s'. It may indicate a file system error!"


# Tool function to print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# Hash generation function
def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


# Search for previous values and return them as a dictionary
def loadPreviousHash(path, json_, verbose=False, debug=False):
    previous = {}
    filename = INTEGRITY_HASH_FILENAME_JSON if json_ else INTEGRITY_HASH_FILENAME
     
    try:
        input_file = str(os.path.join(path, filename))
        f = open (input_file, "r")
        input_str = f.read ()
        f.close()
        
        if verbose: print (TXT_V_FILES_INPUT_OK % (input_file))

        previous = json.loads(input_str) if json_ else yaml.safe_load(input_str)

        if debug: print(TXT_V_FILES_INPUT_CONTENTS % (input_file, previous))
    except:
        if debug: print (TXT_V_FILES_READING_INPUT % (path))

    return previous


# Save current hashes
def saveCurrentHash(path, json_, current, verbose=False, debug=False):
    ok = True
    filename = INTEGRITY_HASH_FILENAME_JSON if json_ else INTEGRITY_HASH_FILENAME
    output_str = json.dumps(current, indent=4, sort_keys=True, default=str) if json_ else yaml.dump(current, default_flow_style=False)    

    if debug: print (TXT_V_FILES_OUTPUT_CONTENTS % (filename, output_str))
        
    try:
        output_file = str(os.path.join(path, filename))
        f = open (output_file, "w")
        f.write (output_str)
        f.close()
        if verbose: print (TXT_V_FILES_OUTPUT_OK % (output_file))
    except:
        eprint (TXT_E_FILES_WRITING_OUTPUT % (path))
        ok = False
    return ok


# Process an specific path according to the specified args
def processFolder(path, args, csv_file):  
    output = {
    KEY_DESC: INTEGRITY_DESC,
    KEY_VERSION: INTEGRITY_VERSION,
    KEY_TYPE: INTEGRITY_TYPE,
    KEY_CREATION: datetime.now(tz=time_zone)
    }

    output[KEY_PATH] = path.absolute().as_posix() if args.absolutepath else os.path.splitdrive(path.absolute().as_posix())[1]

    if args.verbose: print (TXT_V_GENERATING_HASHES % (os.path.splitdrive(path.absolute().as_posix())[1]))

    try:
        files = os.listdir(path)
    except:
        eprint (TXT_E_ACCESS % (args.path))
        exit(-1)
    
    input = {} if args.ignore else loadPreviousHash(path, args.json, args.verbose, args.debug)
    previous_resources = input.get(KEY_RESOURCES)

    resources = {}
    subfolders = []
    file_count = len(files)

    if args.verbose: print (TXT_V_FILES_COUNT % (file_count))

    current = 0
    for filename in files:
        current = current + 1
        if args.verbose: print (TXT_V_FILES_CURRENT % (current, file_count))

        if str(filename).startswith(".") and not args.all: 
            if args.verbose: print (TXT_V_FILES_IGNORED_DOTFILE % (filename))
            continue
        
        file = path / filename
        file_changed = False
        old_hash = ""

        if not os.path.isdir(file):
            if args.verbose: print (TXT_V_FILES_FILE % (filename))

            file_size = 0
            file_creation = datetime.now(tz=time_zone)
            file_change = datetime.now(tz=time_zone)
            file_hash = VALUE_HASH_NOT_READ

            try:
            # I/O operations may raise exceptions due to file system defects!!!
                file_hash = sha256_checksum(file)
                file_size = os.path.getsize(file)
                file_creation = datetime.fromtimestamp(os.path.getctime(file), tz=time_zone)
                file_change = datetime.fromtimestamp(os.path.getmtime(file), tz=time_zone)
            except:
                eprint (TXT_E_FILES_INFO_READ % (file))

            resource = {
                KEY_FILE_NAME: filename,
                KEY_FILE_SIZE: file_size,
                KEY_FILE_CREATION_DATE: file_creation,
                KEY_FILE_CHANGED_DATE: file_change,
                KEY_HASH: file_hash}
            resources[filename]=resource

            # Check if the item is already hashed, then alert and save history!
            try:
                if previous_resources[filename][KEY_HASH] != resource[KEY_HASH]:
                    file_changed = True
                    old_hash = previous_resources[filename][KEY_HASH]
                    print (TXT_O_FILES_CHANGED % (file, previous_resources[filename][KEY_HASH], resource[KEY_HASH]))
                    if KEY_PREVIOUS_VALUE in previous_resources[filename]: previous_resources[filename].pop(KEY_PREVIOUS_VALUE)

                    resources[filename][KEY_PREVIOUS_VALUE]=previous_resources[filename]
            except:
                if args.verbose: print (TXT_V_FILE_NOT_HASHED % (filename))

            # Write a new CSV line, if requested
            if args.csv:  # path, filename, size, changed, hash, oldhash, date, modification
                print(TXT_O_CSV_LINE % (path, resource[KEY_FILE_NAME], resource[KEY_FILE_SIZE], file_changed, resource[KEY_HASH], old_hash, resource[KEY_FILE_CREATION_DATE], resource[KEY_FILE_CHANGED_DATE]), file=csv_file)
        else:
            if args.verbose: print (TXT_V_FILES_DIRECTORY % (filename))
            subfolders.append(file) # Queue for later processing, if recursive
    
    # Recap and save everything in this folder
    output[KEY_RESOURCES] = resources
    if not args.test: saveCurrentHash(path, args.json, output, args.verbose, args.debug)

    # Memory clean-up
    output = resources = input = previous_resources = {}

    # Process sub-folders
    if args.recursive:
        for folder in subfolders:
            processFolder (folder, args, csv_file)
    
    return


# Process an specific path just by recovering existing hashes
def processFolderHashes(path, args, csv_file):  

    if args.verbose: print (TXT_V_PROCESSING_EXISTING_HASHES % (os.path.splitdrive(path.absolute().as_posix())[1]))

    # Access the path
    try:
        files = os.listdir(path)
    except:
        eprint (TXT_E_ACCESS % (args.path))
        return
    
    # Load already existing hash file in the required format
    input = loadPreviousHash(path, args.json, args.verbose, args.debug)
    previous_resources = input.get(KEY_RESOURCES) if KEY_RESOURCES in input else {}

    # Inspect and process previous hash file
    for resource in previous_resources:
        # Write a new CSV line, if requested
        if args.debug: print(TXT_V_EXISTING_HASH % (resource))
        if args.csv:  # path, filename, size, changed, hash, oldhash, date, modification
            changed = KEY_PREVIOUS_VALUE in resource
            old_hash = resource[KEY_PREVIOUS_VALUE][KEY_HASH] if changed else ""
            print(TXT_O_CSV_LINE % (path, resource[KEY_FILE_NAME], resource[KEY_FILE_SIZE], changed, resource[KEY_HASH], old_hash, resource[KEY_FILE_CREATION_DATE], resource[KEY_FILE_CHANGED_DATE]), file=csv_file)
    
    # Look for current folders
    file_count = len(files)
    subfolders = []
    current = 0

    if args.verbose: print (TXT_V_FILES_COUNT % (file_count))
    
    for filename in files:
        current = current + 1
        if args.verbose: print (TXT_V_FILES_CURRENT % (current, file_count))
        
        file = path / filename

        if str(filename).startswith(".") and not args.all: 
            if args.verbose: print (TXT_V_FILES_IGNORED_DOTFILE % (filename))
            continue

        if os.path.isdir(file):
            if args.verbose: print (TXT_V_FILES_DIRECTORY % (filename))
            subfolders.append(file) # Queue for later processing, if recursive   

    # Memory clean-up
    input = previous_resources = {}

    # Process sub-folders
    if args.recursive:
        for folder in subfolders:
            processFolderHashes (folder, args, csv_file)
    
    return


def main():
    parser = argparse.ArgumentParser(description=TXT_DESCRIPTION, prog=TXT_PROG)
    group_csv = parser.add_mutually_exclusive_group()
    parser.add_argument('path', nargs='?', default=os.getcwd())
    parser.add_argument('-p', '--absolutepath', action='store_true', help=TXT_HELP_ABSOLUTE_PATH)
    parser.add_argument('-a', '--all', action='store_true', help=TXT_HELP_IGNORE_DOTS)
    parser.add_argument('-r', '--recursive', action='store_true', help=TXT_HELP_RECURSIVE)
    parser.add_argument('-j', '--json', action='store_true', help=TXT_HELP_JSON)
    group_csv.add_argument('-c', '--csv', action='store_true', help=TXT_HELP_CSV)
    group_csv.add_argument('-f', '--fastcsv', action='store_true', help=TXT_HELP_CSV_FAST)
    parser.add_argument('-i', '--ignore', action='store_true', help=TXT_HELP_IGNORE)
    parser.add_argument('-t', '--test', action='store_true', help=TXT_HELP_TEST)
    parser.add_argument('-v', '--verbose', action='store_true', help=TXT_HELP_VERBOSE)
    parser.add_argument('-d', '--debug', action='store_true', help=TXT_HELP_DEBUG)
    # TODO: Hacer que el verbose sea un nivel de 0 a X en vez de valores (verbose, debug, ...)
    # TODO: Poder especificar fichero de salida para el CSV
    # TODO: Opción para no generar ficheros de hash en carpetas vacías

    args = parser.parse_args()
    path = Path(args.path)

    args.csv = True if args.fastcsv else args.csv
    
    if args.debug: args.verbose = True
    if args.verbose: print (TXT_V_ARGS % (args))
    if args.csv:
        try:
            csv_file = open(INTEGRITY_HASH_FILENAME_CSV,"w")
        except:
            eprint (TXT_E_FILES_WRITING_OUTPUT % (INTEGRITY_HASH_FILENAME_CSV))
            csv_file = open(os.devnull,"w")
            args.csv = False
    if args.fastcsv:
        processFolderHashes (path, args, csv_file)  # Only process already existing files
    else:
        processFolder(path, args, csv_file)         # Process folders according to args
    if args.csv: csv_file.close()
    

if __name__ == '__main__':
    main()
