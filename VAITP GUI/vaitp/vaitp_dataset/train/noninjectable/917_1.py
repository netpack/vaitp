def execute_user_code(user_input):
    # Directly executing user input without proper sanitization
    eval(user_input)

# Example of vulnerable input that could be exploited
user_input = '{{/html}} {{async async="true" cached="false" context="doc.reference"}}{{groovy}}println("Hello " + "from groovy!"){{/groovy}}{{/async}}'

# This would execute the arbitrary Groovy code
execute_user_code(user_input)