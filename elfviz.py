"""elfviz"""
from flask import Flask
from typing import List
import subprocess

import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

import cxxfilt

app = Flask(__name__)


def humanize(num, suffix='B'):
    for unit in ['','Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

@app.route('/')
def hello_world():
    return 'Hello, World!'


def process_file(filename):
    print('Processing file:', filename)
    with open(filename, 'rb') as f:
        section_info_highlevel(f)


def section_info_highlevel(stream):
    print('High level API...')
    elffile = ELFFile(stream)

    # Just use the public methods of ELFFile to get what we need
    # Note that section names are strings.
    for section in elffile.iter_sections():
        print("{:20} {}".format(section.name, humanize(len(section.data()))))

    symtab = elffile.get_section_by_name('.symtab')
    #symbols = demangle([symbol.name for symbol in symtab.iter_symbols()])
    #for s in symbols:
    #    print(s)
    for s in symtab.iter_symbols():
        try:
            cxxfilt.demangle(s.name)
        except cxxfilt.InvalidName as e:
            print("Invalid name {}".format(s.name), file=sys.stderr)
    
if __name__ == '__main__':
    #if sys.argv[1] == '--test':
    #    for filename in sys.argv[2:]:
    #        process_file(filename)
    process_file('../Reconstruction/komb/installdir_release/bin/vandra_scan')
