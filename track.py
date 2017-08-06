"""Searches for the source library for all symbols"""
import argparse
import os
from elftools.elf.elffile import ELFFile

import pyar
#from elftools.elf.sections import SymbolTableSection


def slurp(libs, search_paths):
    origins = {}
    for lib in libs:
        print(lib)
        if os.path.isfile(lib):
            with open(lib, 'rb') as f:
                ar = pyar.load(f)
                for entry in ar.entries:
                    print('--- LOADING SYMBOLS FROM {} ---'.format(entry.name))
                    elffile = ELFFile(entry.get_stream(f))

                    #elffile = ELFFile(f)
                    symtab = elffile.get_section_by_name('.symtab')
                    for symbol in symtab.iter_symbols():
                        print(symbol.name)
                        origins[symbol.name] = lib

    return origins


def get_type(symbol):
    return symbol.entry.st_info.type


def scan(f, repo):
    elffile = ELFFile(f)
    symtab = elffile.get_section_by_name('.symtab')

    origins = {}
    #sum = 0
    for symbol in symtab.iter_symbols():
        #sum += symbol.entry.st_size
        origin = repo.get(symbol.name)
        origins[origin] = origins.get(origin, 0) + symbol.entry.st_size

    print(origins)


def main():
    parser = argparse.ArgumentParser(description="Scans elf binaries and tries to find the originating elf file for all symbols.")
    parser.add_argument('files', nargs='+', help="The elf files to scan")
    parser.add_argument('-L', nargs='*', dest='libs', help="Search this library for symbols", default=[])
    args = parser.parse_args()

    print(args.files)
    print(args.libs)
    repo = slurp(args.libs, [])
    for filename in args.files:
        with open(filename, 'rb') as f:
            scan(f, repo)

if __name__ == "__main__":
    main()
