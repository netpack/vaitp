def theInput(var1, var2):
    var_one = urllib.parse.quote(var1)
    var_two = urllib.parse.quote(var2)
    final_command_one = f'program /hard/coded/path/{var_one}'
    final_command_two = f'otherprogram /hard/coded/path2/{var_two}'
    try:
        exec(final_command_one)
    except:
        print('error')
    try:
        exec(final_command_two)
    except:
        print('error 2')
    return 'someOutput'
