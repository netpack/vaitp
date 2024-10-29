from ni_measurementlink_service import MeasurementLinkService

# Initialize the MeasurementLink service
service = MeasurementLinkService()

# Start the service, exposing it to all network interfaces
service.start(host='0.0.0.0', port=8080)

# Example endpoint that should only be accessible locally
@service.route('/sensitive-data')
def sensitive_data():
    return "This is sensitive data!"