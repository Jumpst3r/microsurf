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
