# Vulnerable version of the d8s-dates package before CVE-2022-44052 was fixed
# This example demonstrates a potential backdoor via an untrusted third-party package

# Dangerous import statement
import democritus_timezones  # This package is potentially harmful

# Example function that uses the untrusted package
def get_time_zone_info():
    return democritus_timezones.get_current_time_zone()

# Example usage
if __name__ == "__main__":
    print("Current time zone info:", get_time_zone_info())