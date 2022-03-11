import bisect
import collections
import magic
from elftools.elf.elffile import ELFFile, SymbolTableSection


# get function name of loc
def getfnname(file, loc):
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
    symbols = collections.OrderedDict(sorted(tmp.items(), key=lambda t: t[0]))
    ind = bisect.bisect_left(list(symbols.keys()), loc)
    key = list(symbols.keys())[ind - 1]
    return symbols[key]
