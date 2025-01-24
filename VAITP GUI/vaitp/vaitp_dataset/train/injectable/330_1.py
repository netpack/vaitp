
from ni_measurementlink_service import MeasurementLinkService
from flask import abort, request, make_response

# Initialize the MeasurementLink service
service = MeasurementLinkService()
service.set_https(True)
service.set_certificate_file('certificate.pem')
service.set_key_file('key.pem')

# Start the service, listening on all interfaces
service.start(host='0.0.0.0', port=8080)

# Example endpoint that checks for local access and uses CSRF protection
@service.route('/sensitive-data', methods=['GET', 'POST'])
def sensitive_data():
    # Check if the request is coming from localhost
    if request.method == 'POST':
        token = request.form.get('csrf_token')
        if not token or not service.csrf.validate_csrf_token(token):
            abort(403)  # CSRF token is missing or invalid

    # Check if the request is coming from localhost
    if request.headers.get('Origin') != service.base_url:
        abort(403)  # Forbidden access for cross-site requests

    return make_response("This is sensitive data!", 200)