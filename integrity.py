# integrity.py
# Create/check files parity recursively
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
KEY_FILENAME = "file"
KEY_FILESIZE = "size"
KEY_FILECHANGEDATE = "changed"
KEY_FILECREATIONDATE = "date"
KEY_FILECHECKDATE = "checked"   # Date when this file was used to check all the files listed within
KEY_PATH = "path"
KEY_PREVIOUS_VALUE = "previous"
KEY_RESOURCES = "resources"
KEY_SHA256 = "sha256"
KEY_TYPE = "type"
KEY_VERSION = "version"

INTEGRITY_DESC = "IntegrityChecker"
INTEGRITY_TYPE = "ChecksumInventory"
INTEGRITY_VERSION = "0.1"
INTEGRITY_CHECKSUM_FILENAME = ".ck++.nfo"
INTEGRITY_CHECKSUM_FILENAME_JSON = ".ck++.nfoj"

TXT_PROG = INTEGRITY_DESC
TXT_DESCRIPTION = "Create and check integrity checksums for files in folder"

TXT_HELP_ABSOLUTEPATH = "Save absolute path when checksum was created"
TXT_HELP_DEBUG = "Debug mode"
TXT_HELP_JSON = "Check/Save checksumg file using JSON format instead of YAML"
TXT_HELP_RECURSIVE = "Process subfolders recursively"
TXT_HELP_IGNOREDOTS = "Include all. Do NOT ignore folders stating with dot (.)"
TXT_HELP_VERBOSE = "Verbose mode"

TXT_V_ARGS = "Arguments detected: %s"
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
TXT_V_GENERATING_CHECKSUMS = "Generating checksums for directory: %s"

TXT_O_FILES_CHANGED = "File '%s' changed! From: '%s' to: '%s'"

TXT_E_ACCESS = "Error: '%s' failed to be accessed"
TXT_E_FILES_READING_INPUT = "Error: '%s' can't read previous information"
TXT_E_FILES_WRITING_OUTPUT = "Error: Can't write to %s"


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def loadPreviousHash(path, json_, verbose=False, debug=False):
    previous = {}
    filename = INTEGRITY_CHECKSUM_FILENAME_JSON if json_ else INTEGRITY_CHECKSUM_FILENAME
     
    try:
        input_file = str(os.path.join(path, filename))
        f = open (input_file, "r")
        input_str = f.read ()
        f.close()
        
        if verbose: print (TXT_V_FILES_INPUT_OK % (input_file))

        previous = json.loads(input_str) if json_ else yaml.safe_load(input_str)

        if debug: print(TXT_V_FILES_INPUT_CONTENTS % (input_file, previous))
    except:
        print (TXT_E_FILES_READING_INPUT % (path))

    return previous

def saveCurrentHash(path, json_, current, verbose=False, debug=False):
    ok = True
    filename = INTEGRITY_CHECKSUM_FILENAME_JSON if json_ else INTEGRITY_CHECKSUM_FILENAME
    output_str = json.dumps(current, indent=4, sort_keys=True, default=str) if json_ else yaml.dump(current, default_flow_style=False)    

    if debug: print (TXT_V_FILES_OUTPUT_CONTENTS % (filename, output_str))
        
    try:
        output_file = str(os.path.join(path, filename))
        f = open (output_file, "w")
        f.write (output_str)
        f.close()
        if verbose: print (TXT_V_FILES_OUTPUT_OK % (output_file))
    except:
        print (TXT_E_FILES_WRITING_OUTPUT % (path))
        ok = False
    return ok

def main():
    output = {
    KEY_DESC: INTEGRITY_DESC,
    KEY_VERSION: INTEGRITY_VERSION,
    KEY_TYPE: INTEGRITY_TYPE,
    KEY_CREATION: datetime.now(tz=time_zone)
    }

    parser = argparse.ArgumentParser(description=TXT_DESCRIPTION, prog=TXT_PROG)
    parser.add_argument('path', nargs='?', default=os.getcwd())
    parser.add_argument('-p', '--absolutepath', action='store_true', help=TXT_HELP_ABSOLUTEPATH)
    parser.add_argument('-a', '--all', action='store_true', help=TXT_HELP_IGNOREDOTS)
    parser.add_argument('-r', '--recursive', action='store_true', help=TXT_HELP_RECURSIVE)
    parser.add_argument('-j', '--json', action='store_true', help=TXT_HELP_JSON)
    parser.add_argument('-v', '--verbose', action='store_true', help=TXT_HELP_VERBOSE)
    parser.add_argument('-d', '--debug', action='store_true', help=TXT_HELP_DEBUG)
    # TODO: Hacer que el verbose sea un nivel de 0 a X en vez de valores (verbose, debug, ...)
    # TODO: Poner opción --ignore para ignorar los datos anteriores y machacarlos

    args = parser.parse_args()
    path = Path(args.path)

    if args.debug: args.verbose = True
    output[KEY_PATH] = path.absolute().as_posix() if args.absolutepath else os.path.splitdrive(path.absolute().as_posix())[1]
    
    if args.verbose: print (TXT_V_ARGS % (args))
    if args.verbose: print (TXT_V_GENERATING_CHECKSUMS % (os.path.splitdrive(path.absolute().as_posix())[1]))

    try:
        files = os.listdir(path)
    except:
        print (TXT_E_ACCESS % (args.path))
        exit(-1)
    
    input = loadPreviousHash(path, args.json, args.verbose, args.debug)
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

        if not os.path.isdir(file):
            if args.verbose: print (TXT_V_FILES_FILE % (filename))

            resource = {
                KEY_FILENAME: filename,
                KEY_FILESIZE: os.path.getsize(file),
                KEY_FILECREATIONDATE: datetime.fromtimestamp(os.path.getctime(file), tz=time_zone),
                KEY_FILECHANGEDATE: datetime.fromtimestamp(os.path.getmtime(file), tz=time_zone),
                KEY_SHA256: sha256_checksum(file)}
            resources[filename]=resource

            # Check if the item is already hashed, then alert and save history!
            try:
                if previous_resources[filename][KEY_SHA256] != resource[KEY_SHA256]:
                    print (TXT_O_FILES_CHANGED % (filename, previous_resources[filename][KEY_SHA256], resource[KEY_SHA256]))
                    if KEY_PREVIOUS_VALUE in previous_resources[filename]: previous_resources[filename].pop(KEY_PREVIOUS_VALUE)

                    resources[filename][KEY_PREVIOUS_VALUE]=previous_resources[filename]
            except:
                if args.verbose: print (TXT_V_FILE_NOT_HASHED % (filename))

        else:
            if args.verbose: print (TXT_V_FILES_DIRECTORY % (filename))
            subfolders.append(file) # Queue for later processing, if recursive

    output[KEY_RESOURCES] = resources

    saveCurrentHash(path, args.json, output, args.verbose, args.debug)
    

if __name__ == '__main__':
    main()
