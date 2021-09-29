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
TXT_HELP_JSON = "Check/Save checksumg file using JSON format instead of YAML"
TXT_HELP_RECURSIVE = "Process subfolders recursively"
TXT_HELP_IGNOREDOTS = "Include all. Do NOT ignore folders stating with dot (.)"
TXT_HELP_VERBOSE = "Verbose mode"

TXT_V_ARGS = "Arguments detected: %s"
TXT_V_FILES_COUNT = "Detected %d items in folder"
TXT_V_FILES_CURRENT = "\tResource %d/%d"
TXT_V_FILES_DIRECTORY = "\t\tIgnoring folder: '%s'"
TXT_V_FILES_IGNORED_DOTFILE = "\t\tIgnoring file (--all not set): '%s'"
TXT_V_FILES_FILE = "\t\tProcessing file: '%s'"
TXT_V_GENERATING = "Generating checksums for directory: %s"
TXT_V_OUTPUT_CONTENTS = "------------------- FILE %s TO DUMP ----------------------\n%s -------------------- END OF FILE ---------------------\n"
TXT_V_OUTPUT_OK = "%s saved properly"

TXT_E_ACCESS = "Error: '%s' failed to be accessed"
TXT_E_WRITING_OUTPUT = "Error: Can't write to %s"


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def loadPreviousHash(path, isJson, verbose=False):
    previous = {}
    filename = INTEGRITY_CHECKSUM_FILENAME_JSON if isJson else INTEGRITY_CHECKSUM_FILENAME
    #try: 
    #    #file = 
    #except:
    #    # ...
    return previous

def saveCurrentHash(path, isJson, current, verbose=False):
    ok = True
    filename = INTEGRITY_CHECKSUM_FILENAME_JSON if isJson else INTEGRITY_CHECKSUM_FILENAME
    output_str = json.dumps(current, indent=4, sort_keys=True, default=str) if isJson else yaml.dump(current, default_flow_style=False)    

    if verbose: print (TXT_V_OUTPUT_CONTENTS % (filename, output_str))
        
    try:
        outputFile = str(os.path.join(path, filename))
        f = open (outputFile, "w")
        f.write (output_str)
        f.close()
        if verbose: print (TXT_V_OUTPUT_OK % (outputFile))
    except:
        print (TXT_E_WRITING_OUTPUT % (path))
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
    # TODO: Poner parámetro silent mode para que no salga nada por pantalla y haya un modo por defecto que sea el verbose-light

    args = parser.parse_args()
    path = Path(args.path)

    if args.absolutepath: output[KEY_PATH] = os.path.splitdrive(path.absolute().as_posix())[1]
    
    if args.verbose: print (TXT_V_ARGS % (args))
    if args.verbose: print (TXT_V_GENERATING % (os.path.splitdrive(path.absolute().as_posix())[1]))

    try:
        files = os.listdir(path)
    except:
        print (TXT_E_ACCESS % (args.path))
        exit(-1)
    


    #loadPreviousHash(path, args.json)


    resources = []
    filecount = len(files)

    if args.verbose: print (TXT_V_FILES_COUNT % (filecount))

    current = 0
    for filename in files:
        current = current + 1
        if args.verbose: print (TXT_V_FILES_CURRENT % (current, filecount))

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
            resources.append(resource)
        else:
            if args.verbose: print (TXT_V_FILES_DIRECTORY % (filename))

    output[KEY_RESOURCES] = resources

    saveCurrentHash(path, args.json, output, args.verbose)
    

if __name__ == '__main__':
    main()
