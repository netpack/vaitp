from pymatgen.io.cif import CifParser
parser = CifParser("vuln.cif")
structure = parser.parse_structures()