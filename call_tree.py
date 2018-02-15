import argparse
from elftools.elf.elffile import ELFFile, ELFError, RelocationSection

from collections import namedtuple
from elftools.elf.relocation import ENUM_RELOC_TYPE_i386, ENUM_RELOC_TYPE_x64, ENUM_RELOC_TYPE_MIPS, ELFRelocationError
from elftools.common.utils import elf_assert, struct_parse


def find_relocations_for_section(elffile, section):
    """ Given a section, find the relocation section for it in the ELF
        file. Return a RelocationSection object, or None if none was
        found.
    """
    reloc_section_names = (
            '.rel' + section.name,
            '.rela' + section.name)
    # Find the relocation section aimed at this one. Currently assume
    # that either .rel or .rela section exists for this section, but
    # not both.
    for relsection in elffile.iter_sections():
        if isinstance(relsection, RelocationSection) and relsection.name in reloc_section_names:
            return relsection
    return None


def compute_relocation(elffile, reloc, symtab):
    if reloc['r_info_sym'] >= symtab.num_symbols():
        raise ELFRelocationError(
            'Invalid symbol reference in relocation: index %s' % (
                reloc['r_info_sym']))
    sym_value = symtab.get_symbol(reloc['r_info_sym'])['st_value']

    reloc_type = reloc['r_info_type']
    recipe = None

    if elffile.get_machine_arch() == 'x86':
        if reloc.is_RELA():
            raise ELFRelocationError(
                'Unexpected RELA relocation for x86: %s' % reloc)
        recipe = _RELOCATION_RECIPES_X86.get(reloc_type, None)
    elif elffile.get_machine_arch() == 'x64':
        if not reloc.is_RELA():
            raise ELFRelocationError(
                'Unexpected REL relocation for x64: %s' % reloc)
        recipe = _RELOCATION_RECIPES_X64.get(reloc_type, None)
    elif elffile.get_machine_arch() == 'MIPS':
        if reloc.is_RELA():
            raise ELFRelocationError(
                'Unexpected RELA relocation for MIPS: %s' % reloc)
        recipe = _RELOCATION_RECIPES_MIPS.get(reloc_type, None)

    if recipe is None:
        raise ELFRelocationError(
                'Unsupported relocation type: %s' % reloc_type)

    # So now we have everything we need to actually perform the relocation.
    # Let's get to it:

    # 0. Find out which struct we're going to be using to read this value
    #    from the stream and write it back.
    if recipe.bytesize == 4:
        value_struct = elffile.structs.Elf_word('')
    elif recipe.bytesize == 8:
        value_struct = elffile.structs.Elf_word64('')
    else:
        raise ELFRelocationError('Invalid bytesize %s for relocation' %
                recipe.bytesize)

    # 1. Read the value from the stream (with correct size and endianness)
    original_value = struct_parse(
        value_struct,
        elffile.stream,
        stream_pos=reloc['r_offset'])
    # 2. Apply the relocation to the value, acting according to the recipe
    relocated_value = recipe.calc_func(
        value=original_value,
        sym_value=sym_value,
        offset=reloc['r_offset'],
        addend=reloc['r_addend'] if recipe.has_addend else 0)
    
    # 3. Return reolcation as a tuple
    # Make sure the relocated value fits back by wrapping it around. This
    # looks like a problem, but it seems to be the way this is done in
    # binutils too.
    relocated_value = relocated_value % (2 ** (recipe.bytesize * 8))
    return (reloc['r_offset'], relocated_value)

    # 3. Write the relocated value back into the stream
    #stream.seek(reloc['r_offset'])

    # Make sure the relocated value fits back by wrapping it around. This
    # looks like a problem, but it seems to be the way this is done in
    # binutils too.
    #relocated_value = relocated_value % (2 ** (recipe.bytesize * 8))
    #value_struct.build_stream(relocated_value, stream)

# Relocations are represented by "recipes". Each recipe specifies:
#  bytesize: The number of bytes to read (and write back) to the section.
#            This is the unit of data on which relocation is performed.
#  has_addend: Does this relocation have an extra addend?
#  calc_func: A function that performs the relocation on an extracted
#             value, and returns the updated value.
#
_RELOCATION_RECIPE_TYPE = namedtuple('_RELOCATION_RECIPE_TYPE',
    'bytesize has_addend calc_func')

def _reloc_calc_identity(value, sym_value, offset, addend=0):
    return value

def _reloc_calc_sym_plus_value(value, sym_value, offset, addend=0):
    return sym_value + value

def _reloc_calc_sym_plus_value_pcrel(value, sym_value, offset, addend=0):
    return sym_value + value - offset

def _reloc_calc_sym_plus_addend(value, sym_value, offset, addend=0):
    return sym_value + addend

def _reloc_calc_sym_plus_addend_pcrel(value, sym_value, offset, addend=0):
    return sym_value + addend - offset

# https://dmz-portal.mips.com/wiki/MIPS_relocation_types
_RELOCATION_RECIPES_MIPS = {
    ENUM_RELOC_TYPE_MIPS['R_MIPS_NONE']: _RELOCATION_RECIPE_TYPE(
        bytesize=4, has_addend=False, calc_func=_reloc_calc_identity),
    ENUM_RELOC_TYPE_MIPS['R_MIPS_32']: _RELOCATION_RECIPE_TYPE(
        bytesize=4, has_addend=False,
        calc_func=_reloc_calc_sym_plus_value),
}

_RELOCATION_RECIPES_X86 = {
    ENUM_RELOC_TYPE_i386['R_386_NONE']: _RELOCATION_RECIPE_TYPE(
        bytesize=4, has_addend=False, calc_func=_reloc_calc_identity),
    ENUM_RELOC_TYPE_i386['R_386_32']: _RELOCATION_RECIPE_TYPE(
        bytesize=4, has_addend=False,
        calc_func=_reloc_calc_sym_plus_value),
    ENUM_RELOC_TYPE_i386['R_386_PC32']: _RELOCATION_RECIPE_TYPE(
        bytesize=4, has_addend=False,
        calc_func=_reloc_calc_sym_plus_value_pcrel),
}

_RELOCATION_RECIPES_X64 = {
    ENUM_RELOC_TYPE_x64['R_X86_64_NONE']: _RELOCATION_RECIPE_TYPE(
        bytesize=8, has_addend=True, calc_func=_reloc_calc_identity),
    ENUM_RELOC_TYPE_x64['R_X86_64_64']: _RELOCATION_RECIPE_TYPE(
        bytesize=8, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    ENUM_RELOC_TYPE_x64['R_X86_64_PC32']: _RELOCATION_RECIPE_TYPE(
        bytesize=8, has_addend=True,
        calc_func=_reloc_calc_sym_plus_addend_pcrel),
    ENUM_RELOC_TYPE_x64['R_X86_64_32']: _RELOCATION_RECIPE_TYPE(
        bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
    ENUM_RELOC_TYPE_x64['R_X86_64_32S']: _RELOCATION_RECIPE_TYPE(
        bytesize=4, has_addend=True, calc_func=_reloc_calc_sym_plus_addend),
}

def iter_relocations(elffile, section):
    relocation_section = find_relocations_for_section(elffile, section)
    symtab = elffile.get_section(relocation_section['sh_link'])
    for reloc in relocation_section.iter_relocations():
        yield compute_relocation(elffile.stream, reloc, symtab)

def scan(f):
    elffile = ELFFile(f)
    #reladyn = elffile.get_section_by_name('.rela.dyn')
    #print('  %s section with %s relocations' % (
    #        '.rela.dyn', reladyn.num_relocations()))

    #for reloc in reladyn.iter_relocations():
    #    print('    Relocation (%s)' % 'RELA' if reloc.is_RELA() else 'REL')
    #    # Relocation entry attributes are available through item lookup
    #    print('      offset = %s' % reloc['r_offset'])
    #for section in elffile.iter_sections():
    #    print(section.name)

    for offset, value in iter_relocations(elffile, elffile.get_section_by_name('.text')):
        print('.text[{}] = {}'.format(offset, value))
        


def main():
    parser = argparse.ArgumentParser(description="List call tree for binary")
    parser.add_argument('files', nargs='+', help="The elf files to scan")
    args = parser.parse_args()

    for filename in args.files:
        with open(filename, 'rb') as f:
            scan(f)

if __name__ == "__main__":
    main()
