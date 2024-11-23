from langchain_experimental import REPL

# Opt-in step to enable REPL access
def enable_repl_access():
    user_input = input("Do you want to enable Python REPL access? (yes/no): ")
    if user_input.lower() == 'yes':
        repl = REPL()
        repl.run()
    else:
        print("REPL access is disabled.")

# Call the function to enable REPL access
enable_repl_access()