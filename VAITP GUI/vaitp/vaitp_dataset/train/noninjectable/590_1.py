import bpy

# Example of a vulnerable script link that executes arbitrary code
def vulnerable_script_link():
    # This code could be modified by an attacker to execute arbitrary commands
    exec("print('Executing arbitrary code!')")

# Register the vulnerable script link
bpy.app.handlers.load_post.append(vulnerable_script_link)