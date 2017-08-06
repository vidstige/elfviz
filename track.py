"""Searches for the source library for all symbols"""
import argparse
from elftools.elf.elffile import ELFFile
#from elftools.elf.sections import SymbolTableSection


def get_type(symbol):
    return symbol.entry.st_info.type


def scan(f):
    elffile = ELFFile(f)
    symtab = elffile.get_section_by_name('.symtab')

    types = {}

    for s in symtab.iter_symbols():
        t = get_type(s)
        types[t] = types.get(t, 0) + 1
        #print("{}: {}".format(s.name, get_type(s)))

    print(types)


def main():
    parser = argparse.ArgumentParser(description="Scans elf binaries and tries to find the originating elf file for all symbols.")
    parser.add_argument('files', nargs='+', help="The elf files to scan")
    args = parser.parse_args()

    for filename in args.files:
        with open(filename, 'rb') as f:
            scan(f)

if __name__ == "__main__":
    main()
