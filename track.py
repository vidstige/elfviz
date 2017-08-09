"""Searches for the source library for all symbols"""
import argparse
import os
from elftools.elf.elffile import ELFFile, ELFError

import pyar
#from elftools.elf.sections import SymbolTableSection

def slurp(libs, search_paths):
    repo = {}
    for lib in libs:
        print("Loading from {}".format(lib))
        if os.path.isfile(lib):
            with open(lib, 'rb') as f:
                ar = pyar.load(f)
                for entry in ar.entries:
                    print('  {}'.format(entry.name))
                    try:
                        elffile = ELFFile(entry.get_stream(f))

                        #elffile = ELFFile(f)
                        symtab = elffile.get_section_by_name('.symtab')
                        for symbol in symtab.iter_symbols():                        
                            if symbol.name:
                                repo[symbol.name] = lib
                    except ELFError as e:
                        print(e)
                        import sys
                        print(e, file=sys.stderr)
    return repo

def get_type(symbol):
    return symbol.entry.st_info.type


def scan(f, repo):
    elffile = ELFFile(f)
    symtab = elffile.get_section_by_name('.symtab')

    size_by_origin = {}
    #sum = 0
    for symbol in symtab.iter_symbols():
        #sum += symbol.entry.st_size
        origin = repo.get(symbol.name)
        size_by_origin[origin] = size_by_origin.get(origin, 0) + symbol.entry.st_size

    import json
    with open('origins.txt', 'w') as outfile:
        for k in sorted(size_by_origin, key=size_by_origin.get, reverse=True):
            print("{origin}: {size}".format(origin=k, size=size_by_origin[k]), file=outfile)


def main():
    parser = argparse.ArgumentParser(description="Scans elf binaries and tries to find the originating elf file for all symbols.")
    parser.add_argument('files', nargs='+', help="The elf files to scan")
    parser.add_argument('-L', dest='libs', help="Search this library for symbols", default=[], action='append')
    args = parser.parse_args()

    print(args.files)
    print(args.libs)

    repo = slurp(args.libs, [])
    for filename in args.files:
        with open(filename, 'rb') as f:
            scan(f, repo)

if __name__ == "__main__":
    main()
