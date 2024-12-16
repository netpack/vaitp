# Example representing vulnerable code for CVE-2008-0980 (simplified)
# This code is not the actual Spyce code, but demonstrates the vulnerability concept

def render_page_with_query_param(param_name):
    if param_name == "url":
      query_value = get_query_parameter("url")
    elif param_name == "x":
        query_value = get_query_parameter("x")
    elif param_name == "name":
        query_value = get_query_parameter("name")
    elif param_name == "Name":
        query_value = get_query_parameter("Name")
    elif param_name == "mytextarea":
        query_value = get_query_parameter("mytextarea")
    elif param_name == "mypass":
        query_value = get_query_parameter("mypass")
    elif param_name == "newline":
        query_value = get_query_parameter("newline")
    elif param_name == "text1":
        query_value = get_query_parameter("text1")
    elif param_name == "mytext":
        query_value = get_query_parameter("mytext")
    elif param_name == "mydate":
      query_value = get_query_parameter("mydate")
    else:
      query_value = ""

    # Vulnerability: Directly embedding the unsanitized query value in HTML
    html_output = f"<h1>The parameter value is: {query_value}</h1>"
    return html_output

def get_query_parameter(param_name):
    # This is a simplified representation of how the server might retrieve the query parameter
    # In a real application, query parameters would be parsed from the request URL.
    # For this demonstration, we'll use a hardcoded dictionary
    query_params = {
      "url": "test",
      "x": "test",
      "name": "test",
      "Name": "test",
      "mytextarea": "test",
      "mypass": "test",
      "newline": "test",
      "text1": "test",
      "mytext": "test",
      "mydate": "test"
    }
    return query_params.get(param_name, "") #return a default value if key doesn't exist


# Example usage (demonstrates the vulnerability)
# This would typically be called when a request is made to a specific endpoint
# Example 1:  Vulnerable to XSS using the "url" parameter
# result = render_page_with_query_param("url")

# Example 2: Vulnerable to XSS using the "x" parameter
# result = render_page_with_query_param("x")

# Example 3: Vulnerable to XSS using the "name" parameter
# result = render_page_with_query_param("name")

# Example 4: Vulnerable to XSS using the "Name" parameter
# result = render_page_with_query_param("Name")

# Example 5: Vulnerable to XSS using the "mytextarea" parameter
# result = render_page_with_query_param("mytextarea")

# Example 6: Vulnerable to XSS using the "mypass" parameter
# result = render_page_with_query_param("mypass")

# Example 7: Vulnerable to XSS using the "newline" parameter
# result = render_page_with_query_param("newline")

# Example 8: Vulnerable to XSS using the "text1" parameter
# result = render_page_with_query_param("text1")

# Example 9: Vulnerable to XSS using the "mytext" parameter
# result = render_page_with_query_param("mytext")

# Example 10: Vulnerable to XSS using the "mydate" parameter
# result = render_page_with_query_param("mydate")

# Example of how the vulnerable code would inject a script if the parameter contained it
# if you were to modify the hard coded dictionary to have a malicious javascript in one of the keys such as 
# query_params = {
#      "url": "<script>alert('XSS')</script>",
# ...
# }
# then uncommenting one of the render_page_with_query_param call would cause a javascript alert box to popup
