import os
import yaml

def export_pipeline(pipeline, output_format='yaml'):
    # Retrieve S3 credentials directly from the environment (vulnerable code)
    s3_access_key = os.getenv('S3_ACCESS_KEY')
    s3_secret_key = os.getenv('S3_SECRET_KEY')

    # Prepare the pipeline export including sensitive information
    export_data = {
        'pipeline': pipeline,
        's3_credentials': {
            'access_key': s3_access_key,
            'secret_key': s3_secret_key
        }
    }

    if output_format == 'yaml':
        with open('pipeline_export.yaml', 'w') as file:
            yaml.dump(export_data, file)
    elif output_format == 'python_dsl':
        with open('pipeline_export.py', 'w') as file:
            file.write(f"pipeline = {pipeline}\n")
            file.write(f"s3_credentials = {{'access_key': '{s3_access_key}', 'secret_key': '{s3_secret_key}'}}\n")