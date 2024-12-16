def safe_vfs_umount(mounted_path, unmount_path):
    if len(unmount_path) > len(mounted_path):
        raise ValueError("Unmount path is too long")
    
    # Ensure the unmount path matches the mounted path
    if mounted_path[:len(unmount_path)] == unmount_path:
        # Proceed with unmounting
        print("Unmounting:", mounted_path)
    else:
        raise ValueError("Unmount path does not match the mounted path")
        
# Example usage
try:
    safe_vfs_umount("/mnt/my_device", "/mnt/my_device")
except ValueError as e:
    print(e)