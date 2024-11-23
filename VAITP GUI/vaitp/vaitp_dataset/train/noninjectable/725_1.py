def set_vcpu_affinity(vcpu_id, cpumap):
    # No validation of cpumap length, leading to potential buffer overflow
    # Directly passing cpumap to the xc_vcpu_setaffinity call
    result = libc.xc_vcpu_setaffinity(vcpu_id, cpumap)
    if result != 0:
        raise RuntimeError("Failed to set VCPU affinity")

# Example usage
vcpu_id = 0
cpumap = '1100000011000000'  # Crafted cpumap that exceeds expected size

set_vcpu_affinity(vcpu_id, cpumap)