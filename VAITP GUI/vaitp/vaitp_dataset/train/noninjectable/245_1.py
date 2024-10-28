import boto3

# Create an IoT client
iot_client = boto3.client('iot', region_name='us-west-2')

# Connect to the AWS IoT Core without hostname verification
def connect_to_iot():
    response = iot_client.connect(
        endpoint='your-iot-endpoint.amazonaws.com',
        port=8883,
        # Note: This is a simplified example and does not include proper SSL context
    )
    return response

# Call the function to connect
connect_to_iot()