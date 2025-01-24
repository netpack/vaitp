import re
from typing import List, Tuple

def _normalize_ip_address(ip_address: str) -> Tuple[int, int, int, int]:
    """
    Converts an IP address string to a tuple of 4 integers.

    Args:
        ip_address: The IP address string to convert

    Returns:
        A tuple of 4 integers, or an empty tuple if the IP address is invalid

    Raises:
        None
    """
    match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip_address)
    if not match:
        return ()

    parts = [int(part) for part in match.groups()]

    if any(part > 255 for part in parts):
        return ()

    return tuple(parts)


def _ip_address_in_range(ip_address: str, ip_range: str) -> bool:
    """
    Checks if an IP address is within an IP range

    Args:
        ip_address: The IP address to check
        ip_range: The IP range to check against, as a string of the form "192.168.1.0/24"

    Returns:
         True if the IP address is within the range, False otherwise.

    Raises:
        None
    """
    addr_parts = _normalize_ip_address(ip_address)
    if not addr_parts:
        return False

    range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$", ip_range)
    if not range_match:
        return False

    range_addr, prefix_length_str = range_match.groups()
    prefix_length = int(prefix_length_str)

    if prefix_length > 32:
        return False

    range_parts = _normalize_ip_address(range_addr)
    if not range_parts:
        return False

    addr_int = (addr_parts[0] << 24) + (addr_parts[1] << 16) + (addr_parts[2] << 8) + addr_parts[3]
    range_int = (range_parts[0] << 24) + (range_parts[1] << 16) + (range_parts[2] << 8) + range_parts[3]

    mask = ((1 << (32 - prefix_length)) - 1) ^ 0xFFFFFFFF

    return (addr_int & mask) == (range_int & mask)


def is_ip_allowed(
    ip_address: str, ip_range_blacklist: List[str], ip_range_whitelist: List[str]
) -> bool:
    """
    Checks if an IP address is allowed given a blacklist and whitelist of IP ranges

    Args:
        ip_address: The IP address to check.
        ip_range_blacklist: The blacklist of IP ranges
        ip_range_whitelist: The whitelist of IP ranges

    Returns:
        True if the IP address is allowed, False otherwise.
        IP addresses that are not explicitly allowed are denied.
    Raises:
        None
    """

    if not ip_address:
        return False

    if not ip_range_whitelist and not ip_range_blacklist:
      return True

    if ip_range_whitelist:
        for ip_range in ip_range_whitelist:
           if _ip_address_in_range(ip_address, ip_range):
                return True
    
    if ip_range_blacklist:
        for ip_range in ip_range_blacklist:
           if _ip_address_in_range(ip_address, ip_range):
              return False

    return not bool(ip_range_whitelist)
