```
```python
import os
import uuid
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Dict

import boto3
from google.cloud import storage
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET")
S3_BUCKET = os.getenv("S3_BUCKET")
S3_DOMAIN = os.getenv("S3_DOMAIN")
S3_REGION = os.getenv("S3_REGION")
UPLOAD_METHOD = os.getenv("UPLOAD_METHOD")
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")
GCS_DOMAIN = os.getenv("GCS_DOMAIN")


s3 = None


def get_s3():
    global s3
    if not s3:
        boto3.setup_default_session(region_name=S3_REGION)
        s3 = boto3.client("s3", config=boto3.session.Config(signature_version="s3v4"))
    return s3


def get_uploads_dir():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "uploads")


def get_file_signature(file_path: str) -> str:
    return hmac.new(
        JWT_SECRET.encode("utf-8"), file_path.encode("utf-8"), hashlib.sha256
    ).hexdigest()


async def upload_file(file_path: str, signature: str, contents: bytes):
    # Make sure signature matches
    comp = get_file_signature(file_path)
    if not hmac.compare_digest(signature, comp):
        raise Exception("Invalid upload signature")

    # Watch out for poison null bytes
    if "\0" in file_path:
        raise Exception("Error: Filename must not contain null bytes")

    root_directory = get_uploads_dir()
    full_path = os.path.join(root_directory, file_path)

    # Prevent directory traversal
    if not full_path.startswith(root_directory):
        raise Exception(
            "Error: Path must not escape out of the 'uploads' directory."
        )

    dir_path = os.path.dirname(full_path)
    os.makedirs(dir_path, exist_ok=True)
    with open(full_path, "wb") as f:
        f.write(contents)


async def get_file_upload_url(ext: str, path_prefix: str):
    mimetypes: Dict[str, str] = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "svg": "text/svg",
    }

    if ext.lower() not in mimetypes:
        raise Exception(
            f"Invalid image file type. Only {', '.join(mimetypes.keys())} accepted."
        )

    filename = str(uuid.uuid4())
    file_path = f"{path_prefix}{filename}.{ext}"

    async def get_signed_google_url():
        storage_client = storage.Client()
        bucket = storage_client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(file_path)

        url = blob.generate_signed_url(
            version="v4",
            method="PUT",
            expiration=datetime.utcnow() + timedelta(minutes=15),
            content_type=mimetypes[ext.lower()],
        )

        return url

    if UPLOAD_METHOD == "s3":
        s3_params = {
            "Bucket": S3_BUCKET,
            "Key": file_path,
            "ContentType": mimetypes[ext.lower()],
            "ACL": "public-read",
        }

        upload_url = get_s3().generate_presigned_url(
            "put_object", Params=s3_params, ExpiresIn=15 * 60
        )

        return {
            "uploadURL": upload_url,
            "fileURL": S3_DOMAIN + ("/" if not S3_DOMAIN.endswith("/") else "") + file_path,
        }
    elif UPLOAD_METHOD == "google-cloud":
        upload_url = await get_signed_google_url()

        return {
            "uploadURL": upload_url,
            "fileURL": GCS_DOMAIN + ("/" if not GCS_DOMAIN.endswith("/") else "") + file_path,
        }
    else:
        file_url = f"/upload/{file_path}"
        upload_url = (
            f"/upload?path={file_path}&signature={get_file_signature(file_path)}"
        )
        return {
            "uploadURL": upload_url,
            "fileURL": file_url,
        }
