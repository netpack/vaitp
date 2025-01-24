
import subprocess

def theInput(var1, var2):
    var_one = subprocess.list2cmdline([var1])
    var_two = subprocess.list2cmdline([var2])
    final_command_one = f'program /hard/coded/path/{var_one}'
    final_command_two = f'otherprogram /hard/coded/path2/{var_two}'
    try:
        subprocess.check_output(final_command_one, shell=False)
    except:
        print('error')
    try:
        subprocess.check_output(final_command_two, shell=False)
    except:
        print('error 2')
    return 'someOutput'