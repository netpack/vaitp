import os
import subprocess
import tempfile
import shlex

def play_video(video_path):
    if not os.path.isfile(video_path):
        print("Error: Video file not found.")
        return
    
    try:
        # Ensure the video_path is an actual file and not a command by checking if it has an extension
        _, file_extension = os.path.splitext(video_path)
        if not file_extension:
            print("Error: Invalid video file path.")
            return

        # Build the command with proper escaping
        command = ["/usr/bin/vlc", "--play-and-exit", video_path]
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error playing video: {e}")
    except Exception as e:
         print(f"An unexpected error occurred: {e}")