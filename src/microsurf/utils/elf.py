import bisect
import collections
import magic
from elftools.elf.elffile import ELFFile, SymbolTableSection

ELFSYBOLS = {}

# get function name of loc
def getfnname(file, loc):
    global ELFSYBOLS
    if file not in ELFSYBOLS:
        try:
            fileinfo = magic.from_file(file)
        except FileNotFoundError:
            return None
        if "ELF" not in fileinfo:
            return None
        if "not stripped" not in fileinfo:
            return None
        tmp = {}
        with open(file, "rb") as f:
            elf = ELFFile(f)
            symtab: SymbolTableSection = elf.get_section_by_name(".symtab")
            for i in range(symtab.num_symbols()):
                symbol = symtab.get_symbol(i)
                tmp[symbol["st_value"]] = symbol.name
        ELFSYBOLS[file] = collections.OrderedDict(
            sorted(tmp.items(), key=lambda t: t[0])
        )
    ind = bisect.bisect_left(list(ELFSYBOLS[file].keys()), loc)
    key = list(ELFSYBOLS[file].keys())[ind - 1]
    return ELFSYBOLS[file][key]



# taken from the pyelf examples page
def decode_file_line(dwarfinfo, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarfinfo.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                line = prevstate.line
                return CU.get_top_DIE().get_full_path(), line
            if entry.state.end_sequence:
                # For the state with `end_sequence`, `address` means the address
                # of the first byte after the target machine instruction
                # sequence and other information is meaningless. We clear
                # prevstate so that it's not used in the next iteration. Address
                # info is used in the above comparison to see if we need to use
                # the line information for the prevstate.
                prevstate = None
            else:
                prevstate = entry.state
    return None, None

def getCodeSnippet(file, loc):
    with open(file, "rb") as f:
        elf = ELFFile(f)
        path, ln = decode_file_line(elf.get_dwarf_info(), loc)
        try:
            with open(path, 'r') as f2:
                lines = f2.readlines()
            return lines[ln-3:ln+3]
        except Exception:
            return []