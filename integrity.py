# integrity.py
# A.K.A. IntegrityChecker
# Create/check files parity recursively
import sys
import argparse
import os
import hashlib
from typing import Any
import yaml
import json
from datetime import datetime
from pathlib import Path
from io import StringIO
from colorama import Fore #, Back, Style

time_zone = None


# Constants and strings
INTEGRITY_DEFAULT_ENCODING = 'utf8'
INTEGRITY_DESC = "IntegrityChecker"
INTEGRITY_TYPE = "ChecksumInventory"
INTEGRITY_VERSION = "0.4"
INTEGRITY_HASH_FILENAME = ".ck++.nfo"
INTEGRITY_HASH_FILENAME_JSON = ".ck++.json.nfo"
INTEGRITY_HASH_FILENAME_CSV = "ck++.csv"

KEY_CREATION = "creation"
KEY_DESC = "generator" 
KEY_FILE_NAME = "file"
KEY_FILE_SIZE = "size"
KEY_FILE_CHANGED_DATE = "changed"
KEY_FILE_CREATION_DATE = "date"
KEY_FILE_CHECK_DATE = "checked"   # Date when the hash file was used to check all the files listed within
KEY_PATH = "path"
KEY_PREVIOUS_VALUE = "previous"
KEY_RESOURCES = "resources"
KEY_HASH = "sha256"
KEY_TYPE = "type"
KEY_VERSION = "version"

VALUE_HASH_NOT_READ = "NULL"
VALUE_STRING_NOT_FOUND = ""
VALUE_INT_NOT_FOUND = 0

VALUE_VERBOSE_INFO = 1
VALUE_VERBOSE_DETAIL = 2
VALUE_VERBOSE_DEBUG = 3

TXT_PROG = INTEGRITY_DESC
TXT_DESCRIPTION = "Create and check integrity checksums and hashes for files in folder"

TXT_HELP_ABSOLUTE_PATH = "Save absolute path"
TXT_HELP_CSV = "Generate a CSV file (; delimited) detailing all the files processed"
TXT_HELP_CSV_FAST = "Generate a CSV file detailing all the files already processed (use hash files)"
TXT_HELP_DEBUG = "Debug level: 1: Verbose (--verbose); 2: Detailed; 3: Debug"
TXT_HELP_EMPTY = "Do not write hash files into empty folders (leaving them empty)"
TXT_HELP_JSON = "Check/Save hash file using JSON format instead of YAML"
TXT_HELP_RECURSIVE = "Process subfolders recursively"
TXT_HELP_IGNORE = "Ignore already stored hashes (avoid changes detection)"
TXT_HELP_IGNORE_DOTS = "Include all. Do NOT ignore files and folders stating with dot (.)"
TXT_HELP_OUTPUT = "Output CSV contents to specified file. Ignored if a CSV argument is not present."
TXT_HELP_SUMMARY = "Print a summary of processed files when finish"
TXT_HELP_TEST = "Test mode. Does NOT write updates to hash files"
TXT_HELP_VERBOSE = "Verbose mode"
TXT_HELP_VERSION = "Print current version and exits"

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

# CSV Entries: path, filename, size, changed, hash, oldhash, date, modification
TXT_O_CSV_HEADER = "PATH;FILENAME;SIZE;CHANGED;HASH;PREV_HASH;DATE;MODIFICATION"
TXT_O_CSV_LINE = "\"%s\";\"%s\";%s;\"%s\";\"%s\";\"%s\";\"%s\";\"%s\""

TXT_O_FILES_CHANGED = Fore.YELLOW + "[CHANGE] " + Fore.RESET + "File '%s' changed from: '%s' to: '%s'"
TXT_O_FILES_NEW =  Fore.BLUE + "[NEW] " + Fore.RESET + "File '%s' hashed: '%s'"
TXT_O_FILES_NOT_CHANGED = Fore.GREEN + "[OK] " + Fore.RESET + "File '%s' hashed: '%s'"
TXT_O_SUMMARY_FILES =           "=============================\n SUMMARY OF PROCESSED FILES\n============================="
TXT_O_SUMMARY_FILES_CHANGED =   "Files " + Fore.YELLOW + "[CHANGE]   " + Fore.RESET + "%12d"
TXT_O_SUMMARY_FILES_ERRORS =    "Files " + Fore.RED +    "[ERROR]    " + Fore.RESET + "%12d"
TXT_O_SUMMARY_FILES_IGNORED =   "Files " +               "[Ignored]  " +              "%12d"
TXT_O_SUMMARY_FILES_NEW =       "Files " + Fore.BLUE +   "[NEW]      " + Fore.RESET + "%12d"
TXT_O_SUMMARY_FILES_UNCHANGED = "Files " + Fore.GREEN +  "[OK]       " + Fore.RESET + "%12d"
TXT_O_VERSION = "%s Version %s"

TXT_E_ACCESS = Fore.RED + "[ERROR] " + Fore.RESET + "'%s' failed to be accessed"
TXT_E_FILES_WRITING_OUTPUT = Fore.RED + "[ERROR] " + Fore.RESET + "Can't write to %s"
TXT_E_FILES_INFO_READ = Fore.RED + "[ERROR] " + Fore.RESET + "While retrieving info for file '%s'. It may indicate a file system error!"


class Summary:
    unchanged = 0
    new = 0
    changed = 0
    ignored = 0
    errors = 0

summary_files = Summary()

# Tool function to print to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# Hash generation function
def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()                   
    try:
        with open(filename, 'rb') as f:
            for block in iter(lambda: f.read(block_size), b''):
                sha256.update(block)
    except:
        eprint (TXT_E_ACCESS % (filename))
        return VALUE_HASH_NOT_READ
    return sha256.hexdigest()


# Search for previous values and return them as a dictionary
def loadPreviousHash(path, args):
    previous = {}
    filename = INTEGRITY_HASH_FILENAME_JSON if args.json else INTEGRITY_HASH_FILENAME
     
    try:
        input_file = str(os.path.join(path, filename))
        f = open (input_file, "r", encoding=INTEGRITY_DEFAULT_ENCODING)
        input_str = f.read ()
        f.close()
        
        if args.debuglevel >= VALUE_VERBOSE_INFO:  print (TXT_V_FILES_INPUT_OK % (input_file))

        previous = json.loads(input_str) if args.json else yaml.safe_load(input_str)

        if args.debuglevel >= VALUE_VERBOSE_DEBUG: print(TXT_V_FILES_INPUT_CONTENTS % (input_file, previous))
    except:
        if args.debuglevel >= VALUE_VERBOSE_DEBUG: print (TXT_V_FILES_READING_INPUT % (path))

    return previous


# Save current hashes
def saveCurrentHash(path, args, current_hash_obj):
    ok = True
    filename = INTEGRITY_HASH_FILENAME_JSON if args.json else INTEGRITY_HASH_FILENAME
    output_str = json.dumps(current_hash_obj, indent=4, sort_keys=True, default=str) if args.json else yaml.dump(current_hash_obj, default_flow_style=False)    

    if args.debuglevel >= VALUE_VERBOSE_DEBUG: print (TXT_V_FILES_OUTPUT_CONTENTS % (filename, output_str))
        
    try:
        output_file = str(os.path.join(path, filename))
        f = open (output_file, "w", encoding=INTEGRITY_DEFAULT_ENCODING)
        f.write (output_str)
        f.close()
        if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_FILES_OUTPUT_OK % (output_file))
    except:
        eprint (TXT_E_FILES_WRITING_OUTPUT % (path))
        ok = False
    return ok


# Process an specific path according to the specified args
def processFolder(path, args, csv_file):
    # General initializations  
    output = {
    KEY_DESC: INTEGRITY_DESC,
    KEY_VERSION: INTEGRITY_VERSION,
    KEY_TYPE: INTEGRITY_TYPE,
    KEY_FILE_CHECK_DATE: datetime.now(tz=time_zone)
    }

    output[KEY_PATH] = path.absolute().as_posix() if args.absolutepath else os.path.splitdrive(path.absolute().as_posix())[1]

    if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_GENERATING_HASHES % (os.path.splitdrive(path.absolute().as_posix())[1]))

    # Access the path (if possible)
    try:
        files = os.listdir(path)
    except:
        eprint (TXT_E_ACCESS % (args.path))
        return
    
    # Load already existing hash file in the required format
    input = {} if args.ignore else loadPreviousHash(path, args)
    previous_resources = input[KEY_RESOURCES] if KEY_RESOURCES in input else {}

    output[KEY_CREATION] = input[KEY_CREATION] if KEY_CREATION in input else datetime.now(tz=time_zone)
    #previous_resources = input.get(KEY_RESOURCES, default={}) # If there's no resources return {}

    # Inspect and process previous hash file in case of --fastcsv option
    if args.fastcsv:
        for resource in previous_resources.values():
            # Write a new CSV line, if requested
            if args.debuglevel >= VALUE_VERBOSE_DEBUG: print(TXT_V_EXISTING_HASH % (resource))
            if args.csv:  # path, filename, size, changed, hash, oldhash, date, modification
                changed = KEY_PREVIOUS_VALUE in resource
                old_hash = resource[KEY_PREVIOUS_VALUE][KEY_HASH] if changed else ""
                print (TXT_O_CSV_LINE % 
                    (path, 
                    resource[KEY_FILE_NAME],
                    resource[KEY_FILE_SIZE],
                    changed, 
                    resource[KEY_HASH], 
                    old_hash, 
                    resource[KEY_FILE_CREATION_DATE], 
                    resource[KEY_FILE_CHANGED_DATE]), 
                    file=csv_file)

    # Process contents from the file system
    resources = {}
    subfolders = []
    file_count = len(files)

    if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_FILES_COUNT % (file_count))

    current = 0
    for filename in files:
        current = current + 1
        if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_FILES_CURRENT % (current, file_count))

        if str(filename).startswith(".") and not args.all: 
            if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_FILES_IGNORED_DOTFILE % (filename))
            summary_files.ignored += 1 # TODO: Detect if it's a file or folder
            continue
        
        file = path / filename
        file_changed = False
        old_hash = ""

        if not os.path.isdir(file):
            if not args.fastcsv: # Do not process files if not required
                if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_FILES_FILE % (filename))

                file_size = 0
                file_creation = datetime.now(tz=time_zone)
                file_change = datetime.now(tz=time_zone)
                file_hash = VALUE_HASH_NOT_READ
                file_already_hashed = False
                old_hash = ""

                try:
                # I/O operations may raise exceptions due to file system defects!!!
                    file_hash = sha256_checksum(file)
                    file_size = os.path.getsize(file)
                    file_creation = datetime.fromtimestamp(os.path.getctime(file), tz=time_zone)
                    file_change = datetime.fromtimestamp(os.path.getmtime(file), tz=time_zone)
                except:
                    eprint (TXT_E_FILES_INFO_READ % (file))
                    summary_files.errors += 1

                resource = {
                    KEY_FILE_NAME: filename,
                    KEY_FILE_SIZE: file_size,
                    KEY_FILE_CREATION_DATE: file_creation,
                    KEY_FILE_CHANGED_DATE: file_change,
                    KEY_HASH: file_hash}
                resources[filename]=resource

                # Check if the item is already hashed, then alert and save history!
                try:
                    file_already_hashed = True if filename in previous_resources else False
                    if previous_resources[filename][KEY_HASH] != resource[KEY_HASH]:
                        file_changed = True
                        old_hash = previous_resources[filename][KEY_HASH]
                        # print (TXT_O_FILES_CHANGED % (file, previous_resources[filename][KEY_HASH], resource[KEY_HASH]))
                        if KEY_PREVIOUS_VALUE in previous_resources[filename]: previous_resources[filename].pop(KEY_PREVIOUS_VALUE)

                        resources[filename][KEY_PREVIOUS_VALUE]=previous_resources[filename]
                except:
                    if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_FILE_NOT_HASHED % (filename))

                if file_changed:                                                # CHANGED File / Hash
                    print(TXT_O_FILES_CHANGED % (file, old_hash, file_hash))
                    summary_files.changed += 1
                elif file_already_hashed:                                       # SAME Hash
                    print(TXT_O_FILES_NOT_CHANGED % (file, file_hash))
                    summary_files.unchanged += 1
                else:                                                           # NEW File
                    print(TXT_O_FILES_NEW % (file, file_hash))
                    summary_files.new += 1

                # Write a new CSV line, if requested
                if args.csv:  # path, filename, size, changed, hash, oldhash, date, modification
                    print(TXT_O_CSV_LINE % (path, resource[KEY_FILE_NAME], resource[KEY_FILE_SIZE], file_changed, resource[KEY_HASH], old_hash, resource[KEY_FILE_CREATION_DATE], resource[KEY_FILE_CHANGED_DATE]), file=csv_file)
        else:
            if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_FILES_DIRECTORY % (filename))
            subfolders.append(file) # Queue for later processing, if recursive
    
    # Recap and save everything in this folder
    if not args.fastcsv:
        output[KEY_RESOURCES] = resources

        is_to_write = not args.test                             # If we are testing the file is not written
        is_empty_folder = len(resources) == 0 and args.empty    # Do not write empty folders with --empty
        is_to_write = is_to_write and not is_empty_folder

        if is_to_write:
            saveCurrentHash(path, args, output)

    # Memory clean-up
    output = resources = input = previous_resources = {}

    # Process sub-folders
    if args.recursive:
        for folder in subfolders:
            processFolder (folder, args, csv_file)
    
    return


## main ##
def main():
    # Parse command-line parameters and adjust values
    parser = argparse.ArgumentParser(description=TXT_DESCRIPTION, prog=TXT_PROG)
    group_csv = parser.add_mutually_exclusive_group()
    parser.add_argument('path', nargs='?', default=os.getcwd())
    parser.add_argument('-V', '--version', action='store_true', help=TXT_HELP_VERSION)
    parser.add_argument('-p', '--absolutepath', action='store_true', help=TXT_HELP_ABSOLUTE_PATH)
    parser.add_argument('-a', '--all', action='store_true', help=TXT_HELP_IGNORE_DOTS)
    parser.add_argument('-e', '--empty', action='store_true', help=TXT_HELP_EMPTY)
    parser.add_argument('-r', '--recursive', action='store_true', help=TXT_HELP_RECURSIVE)
    parser.add_argument('-j', '--json', action='store_true', help=TXT_HELP_JSON)
    group_csv.add_argument('-c', '--csv', action='store_true', help=TXT_HELP_CSV)
    group_csv.add_argument('-f', '--fastcsv', action='store_true', help=TXT_HELP_CSV_FAST)
    #parser.add_argument('-H', '--hash', type=str, choices=["md5", "sha256", "sha3_256", "shake_256", "blake2s"], default="sha256", help=TXT_HELP_HASH) # Hashing algorithm
    parser.add_argument('-o', '--output', type=str, default=INTEGRITY_HASH_FILENAME_CSV, help=TXT_HELP_OUTPUT)
    parser.add_argument('-i', '--ignore', action='store_true', help=TXT_HELP_IGNORE)
    parser.add_argument('-t', '--test', action='store_true', help=TXT_HELP_TEST)
    parser.add_argument('-s', '--summary', action='store_true', help=TXT_HELP_SUMMARY) # Print a summary after processing hashes
    #parser.add_argument('-g', '--gaps', action='store_true', help=TXT_HELP_GAPS) # Process non-hashed files only
    parser.add_argument('-v', '--verbose', action='store_true', help=TXT_HELP_VERBOSE)
    parser.add_argument('-d', '--debuglevel', type=int, choices=[1, 2, 3], default=0, help=TXT_HELP_DEBUG)

    args = parser.parse_args()
    path = Path(args.path)
    csv_file = Any

    if args.version:
        print(TXT_O_VERSION % (INTEGRITY_DESC, INTEGRITY_VERSION))
        return

    args.csv = True if args.fastcsv else args.csv
    args.debuglevel = 1 if int(args.verbose) > args.debuglevel else args.debuglevel
    
    if args.debuglevel >= VALUE_VERBOSE_INFO: print (TXT_V_ARGS % (args))
    if args.csv:
        try:
            csv_file = open(args.output,"w", encoding=INTEGRITY_DEFAULT_ENCODING)
            print(TXT_O_CSV_HEADER, file=csv_file)
        except:
            eprint (TXT_E_FILES_WRITING_OUTPUT % (args.output))
            csv_file = open(os.devnull,"w")
            args.csv = False

    # Run process
    processFolder(path, args, csv_file)

    # Clean-up and close-up
    if args.csv: csv_file.close()

    if args.summary:
        print (TXT_O_SUMMARY_FILES)
        print (TXT_O_SUMMARY_FILES_NEW % (summary_files.new))
        print (TXT_O_SUMMARY_FILES_UNCHANGED % (summary_files.unchanged))
        print (TXT_O_SUMMARY_FILES_CHANGED % (summary_files.changed))
        print (TXT_O_SUMMARY_FILES_IGNORED % (summary_files.ignored))
        print (TXT_O_SUMMARY_FILES_ERRORS % (summary_files.errors))


if __name__ == '__main__':
    main()


# TODO: Pre-scan: generate statistics of files to process in order to offer approximate evolution in %
# TODO: Mejorar la opción summary
#           - Directorios procesados:
#               - Directorios omitidos:
#               - Directorios sin nada que hashear:
#           - Ficheros procesados (hashes calculados):
#               - Ficheros omitidos: (actualmente no se distinguen de los directorios)
# TODO: Continuar... actualizar sólo ficheros que no tienen hash
# TODO: Múltiples algoritmos de hashing
# TODO: Indicar separador de campos en CSV
# TODO: Comandos de comparación (p.ej. en vivo o basado en CSVs), usando Pandas
#           - Mirror mode
#           - Analisis sobre un CSV
#               - Filtrar duplicados
#               - Mostrar cambiados
#               - Generar summary desde CSV
#               - Comparar CSV buscando ficheros con hash diferente y metadatos idénticos
#               - Ignorando rutas relativas si todo lo demás coincide
#               - ... 
#       https://docs.python.org/3/library/argparse.html#sub-commands