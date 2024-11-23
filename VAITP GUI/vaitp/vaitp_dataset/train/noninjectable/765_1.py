import os

def execute_macro(macro_path):
    # Directly execute the macro without any validation
    print(f"Executing macro from: {macro_path}")

def open_document_and_execute_macro(doc_path):
    # Simulate opening a document and executing a macro
    # An attacker could craft a document that specifies a malicious macro path
    macro_path = doc_path  # Assume the document contains the path to the macro
    execute_macro(macro_path)

# Example usage with a potentially malicious path
open_document_and_execute_macro('../some/unsafe/path/to/macro.py')  # This could lead to arbitrary code execution