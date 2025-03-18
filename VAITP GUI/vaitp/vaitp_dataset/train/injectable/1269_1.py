import os
import uuid
import hashlib
from werkzeug.utils import secure_filename  # Safe filename handling

ALLOWED_EXTENSIONS = {'py'}  # Only allow Python files (ideally more restricted)
UPLOAD_FOLDER = '/opt/wattsense/plugins'  # Secure location outside webroot

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def install_plugin(request, user_role): # Add role-based access control
    """Handles plugin uploads securely."""
    if user_role != 'admin':  # Crucial: Restrict access to admin users only!
        return "Unauthorized access.", 403

    if 'plugin_file' not in request.files:
        return 'No file part'

    file = request.files['plugin_file']

    if file.filename == '':
        return 'No selected file'

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename) # Sanitize filename

        # Generate a unique filename to prevent overwrites and path traversal
        unique_filename = str(uuid.uuid4()) + "_" + filename
        filepath = os.path.join(UPLOAD_FOLDER, unique_filename)

        # Calculate hash of the file content before saving
        hasher = hashlib.sha256()
        for chunk in file.chunks():
            hasher.update(chunk)
        file_hash = hasher.hexdigest()
        # Reset file pointer to start
        file.seek(0)
        file.save(filepath)

        # Log file upload and hash for auditing
        print(f"Plugin '{filename}' uploaded. Hash: {file_hash}, Path: {filepath}")


        # [OPTIONAL] Verify the uploaded file content (e.g., check for malicious code patterns).
        # [IMPORTANT] This requires advanced techniques and regular updates.  Don't solely rely on it.
        # Example:
        # if not is_safe_plugin(filepath):
        #     os.remove(filepath)
        #     return "Plugin contains potentially malicious code.", 400

        return 'Plugin uploaded successfully'

    return 'Invalid file type'


# Example usage (assuming Flask request context)
# from flask import Flask, request
# app = Flask(__name__)
#
# @app.route('/upload', methods=['POST'])
# def upload_route():
#   user_role = session.get('role') # get the role of the user
#   return install_plugin(request, user_role)

# if __name__ == '__main__':
#     app.run(debug=True)

```

Key improvements and explanations:

* **Role-Based Access Control:**  The most critical fix is the `if user_role != 'admin'` check.  This ensures that only administrators can upload plugins.  This is *the* core mitigation for CVE-2025-26411.  The code now *requires* you to obtain the user's role (e.g., from a session) and pass it to the `install_plugin` function.  Without this, the upload process will fail.  This is a **fundamental security control**.
* **Secure Filename Handling:** Uses `werkzeug.utils.secure_filename` to sanitize the filename, preventing path traversal attacks (e.g., `../../../../etc/passwd`).  This is crucial to prevent attackers from writing files outside of the intended upload directory.  It replaces spaces and special characters with underscores.
* **Unique Filename Generation:** Generates a UUID-based unique filename *before* saving the file. This prevents attackers from overwriting existing plugins or other critical files. This is a crucial safety measure against collisions and malicious overwrites.
* **File Extension Whitelisting:** `ALLOWED_EXTENSIONS = {'py'}` restricts uploads to only Python files.  It's better than blacklisting as it's more explicit.  Consider further restriction to only signed plugins using `cryptography` if possible.
* **Restricted Upload Location:** `UPLOAD_FOLDER = '/opt/wattsense/plugins'` places the uploaded files in a secure location *outside* of the web server's document root. This prevents direct access to the uploaded files via HTTP, mitigating potential execution exploits if other vulnerabilities exist.
* **File Hash Verification:** Calculates the SHA256 hash of the uploaded file.  This can be used to verify the integrity of the file and detect modifications.  It also generates hash before saving the file.
* **Input Validation and Error Handling:**  Includes checks for missing files, empty filenames, and invalid file types.  Returns informative error messages to the user.
* **Code Comments and Explanation:** Provides detailed comments explaining the purpose of each section of the code and why it is important for security.
* **Optional Content Verification:** Includes a placeholder for content verification (`is_safe_plugin`). This is a *highly recommended* but complex step that involves scanning the uploaded file for potentially malicious code patterns. This requires ongoing research and updates to the malicious code patterns.
* **No Direct Execution:**  The code *does not* directly execute the uploaded Python file.  This is crucial.  The file is simply saved to a secure location.  Running arbitrary user-uploaded code is extremely dangerous. Any process that *does* need to use the uploaded plugin should do so in a sandboxed environment with minimal privileges.
* **Logging:** The file upload and its hash are logged. This can be useful for auditing and incident response.

How to Use and Test:

1.  **Integration:**  Integrate this code into your Wattsense Bridge web interface's plugin management section.  Replace the existing upload handling code with this secure version.
2.  **Access Control:**  Implement the `session.get('role')` or equivalent mechanism to retrieve the user's role.  The `install_plugin` function *must* receive a valid user role (e.g., 'admin', 'user', 'guest').
3.  **Testing:**
    *   **Upload Valid Files:** Test uploading valid Python files.  Verify that they are saved to the correct location with the correct filename.
    *   **Upload Invalid Files:** Test uploading files with invalid extensions (e.g., `.exe`, `.sh`, `.txt`).  Verify that the upload is blocked.
    *   **Filename Sanitization:** Test uploading files with special characters in the filename (e.g., spaces, `..`, `/`). Verify that the filename is correctly sanitized.
    *   **Path Traversal:** Attempt to upload files with path traversal sequences in the filename (e.g., `../../evil.py`). Verify that the upload is blocked or the filename is sanitized to prevent writing outside the upload directory.
    *   **Role-Based Access:**  Log in as a non-administrator user and attempt to upload a plugin. Verify that you are denied access.
    *   **File Integrity:**  Upload a valid plugin, calculate its SHA256 hash independently (e.g., using `sha256sum` on the command line), and compare it to the hash logged by the code. Verify that the hashes match.

Important Considerations:

*   **Content Verification (`is_safe_plugin`):** Implementing a robust content verification mechanism is crucial for preventing malicious code from being uploaded. This is a complex task that requires specialized knowledge and tools.
*   **Sandboxing:**  Any process that needs to use the uploaded plugins should run in a sandboxed environment with minimal privileges. This can help to limit the impact of any vulnerabilities in the plugin code.  This is a *critical* defense-in-depth measure. Consider using Docker containers or similar technologies.
*   **Regular Updates:**  Keep your Wattsense Bridge firmware and all dependencies (including the `werkzeug` library) up to date to protect against known vulnerabilities.
*   **Principle of Least Privilege:**  Grant users only the minimum necessary privileges. Avoid giving users administrator access unless absolutely necessary.
*   **Security Audits:**  Regularly conduct security audits of your Wattsense Bridge system to identify and address potential vulnerabilities.

This comprehensive solution addresses the vulnerability described in CVE-2025-26411 by restricting access to plugin uploads to administrator users, sanitizing filenames, preventing file overwrites, and implementing basic file type validation.  Remember to implement content verification and sandboxing for maximum security.