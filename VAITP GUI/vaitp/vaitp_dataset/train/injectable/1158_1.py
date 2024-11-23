import streamlit as st
import os

# Disable static file sharing to mitigate path traversal vulnerability
st.set_option('server.enableStaticFileSharing', False)

# Example usage of Streamlit
st.title("Secure Streamlit App")
st.write("This app does not allow static file sharing to prevent vulnerabilities.")