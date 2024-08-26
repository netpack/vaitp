import tkinter as tk #TkVideoPlayer prior to 2.0.0
from tkvideoplayer import TkVideoPlayer

# Create a Tkinter window
root = tk.Tk()

# Create a TkVideo Player instance
player = TkVideoPlayer(root, width=640, height=480)

# Load a video file
player.load("example.mp4")

# Start playing the video
player.play()

# Keep the window open
root.mainloop()