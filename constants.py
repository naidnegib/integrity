from colorama import Fore #, Back, Style

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
TXT_HELP_QUICK_ADD = "Quick add new files. Do not check or process already known files"
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
