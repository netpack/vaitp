import streamlit as st

# Enable static file sharing, which is vulnerable to path traversal
st.set_option('server.enableStaticFileSharing', True)

# Example usage of Streamlit
st.title("Vulnerable Streamlit App")
st.write("This app allows static file sharing, which can lead to vulnerabilities.")