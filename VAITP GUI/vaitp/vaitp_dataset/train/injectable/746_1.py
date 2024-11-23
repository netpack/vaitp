import os
import yaml

def export_pipeline(pipeline, output_format='yaml'):
    # Retrieve S3 credentials securely from Kubernetes secrets
    s3_credentials = get_s3_credentials_from_secret()

    # Prepare the pipeline export without including sensitive information
    export_data = {
        'pipeline': pipeline,
        's3_credentials_id': s3_credentials['id']  # Use ID instead of plain credentials
    }

    if output_format == 'yaml':
        with open('pipeline_export.yaml', 'w') as file:
            yaml.dump(export_data, file)
    elif output_format == 'python_dsl':
        with open('pipeline_export.py', 'w') as file:
            file.write(f"pipeline = {pipeline}\n")
            file.write(f"s3_credentials_id = '{s3_credentials['id']}'\n")

def get_s3_credentials_from_secret():
    # Simulated function to retrieve S3 credentials from a Kubernetes secret
    # In a real implementation, this would interact with Kubernetes API to get the secret
    return {
        'id': 's3-credentials-secret-id'  # Only the secret ID is returned
    }