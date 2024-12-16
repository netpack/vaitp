def vulnerable_vfs_umount(mounted_path, unmount_path):
    # Vulnerable comparison based only on the length of the unmount path
    if len(unmount_path) <= len(mounted_path):
        # This can lead to a buffer overflow if unmount_path is longer than mounted_path
        if mounted_path.startswith(unmount_path):
            # Proceed with unmounting
            print("Unmounting:", mounted_path)
        else:
            print("Unmount path does not match the mounted path")
    else:
        # Potential heap buffer overflow risk
        print("Unmount path is too long, may cause overflow")

# Example usage that could trigger the vulnerability
vulnerable_vfs_umount("/mnt/my_device", "/mnt/my_device_extra_long_string")