from ni_measurementlink_service import MeasurementLinkService
from flask import abort, request

# Initialize the MeasurementLink service
service = MeasurementLinkService()

# Start the service, restricting it to localhost
service.start(host='127.0.0.1', port=8080)

# Example endpoint that checks for local access
@service.route('/sensitive-data')
def sensitive_data():
    # Check if the request is coming from localhost
    if request.remote_addr != '127.0.0.1':
        abort(403)  # Forbidden access for non-local requests
    return "This is sensitive data!"