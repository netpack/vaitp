# Import the tkvideoplayer package
from tkvideoplayer import TkinterVideo

# Import the tkinter package
import tkinter as tk

# Create a tkinter window
window = tk.Tk()

# Create a video player object
player = TkinterVideo(master=window, path="video.mp4")

# Play the video file
# This will consume a lot of memory and slow down the program
player.play()

# Start the tkinter main loop
window.mainloop()