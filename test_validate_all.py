import sys, os
sys.path.insert(0, '.')
from main_orchestrator import _validate_vulnerability
from run_phase3 import _load_intended_vuln, ensure_dataset_populated

# Ensure dataset is populated from outros/
ensure_dataset_populated()

# All 82 test files (not just the 29 previously failing)
vuln_dir = 'vaitp_dataset/vulnerable'
patch_dir = 'vaitp_dataset/injectable'

if not os.path.isdir(vuln_dir) or not os.path.isdir(patch_dir):
    print(f"Dataset directories not found. Falling back to outros/")
    vuln_dir = 'vaitp_dataset/outros/vulnerable'
    patch_dir = 'vaitp_dataset/outros/injectable'

# Find all paired files
vuln_files = {f for f in os.listdir(vuln_dir) if f.endswith('.py')}
patch_files = {f for f in os.listdir(patch_dir) if f.endswith('.py')}
paired = sorted(vuln_files & patch_files)

valid_count = 0
invalid_count = 0
no_type_count = 0

for fn in paired:
    vuln_path = os.path.join(vuln_dir, fn)
    patch_path = os.path.join(patch_dir, fn)
    with open(vuln_path) as f:
        vuln_code = f.read()
    with open(patch_path) as f:
        patch_code = f.read()
    intended = _load_intended_vuln(fn)
    if not intended:
        no_type_count += 1
        continue
    is_valid, diag = _validate_vulnerability(vuln_code, patch_code, intended)
    status = 'VALID  ' if is_valid else 'INVALID'
    if is_valid:
        valid_count += 1
    else:
        invalid_count += 1
    print(f'{fn:<30} {status} {diag[:65]}')

print(f'\nSummary: {valid_count} valid, {invalid_count} invalid (need repair), {no_type_count} no vuln type')
print(f'Total: {len(paired)} paired files')
