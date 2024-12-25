import uuid
import boto3
import hmac
import hashlib
import os
from google.cloud import storage
from datetime import datetime, timedelta


# Assuming secrets are loaded from environment variables or a similar mechanism
JWT_SECRET = os.environ.get("JWT_SECRET")
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_DOMAIN = os.environ.get("S3_DOMAIN")
S3_REGION = os.environ.get("S3_REGION")
UPLOAD_METHOD = os.environ.get("UPLOAD_METHOD")
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME")
GCS_DOMAIN = os.environ.get("GCS_DOMAIN")


s3 = None
def get_s3():
    global s3
    if not s3:
        s3 = boto3.client('s3', region_name=S3_REGION, config=boto3.session.Config(signature_version='v4'))
    return s3


def get_uploads_dir():
  return os.path.join(os.path.dirname(__file__), "..", "..", "uploads")


def get_file_signature(file_path):
    return hmac.new(JWT_SECRET.encode(), file_path.encode(), hashlib.sha256).hexdigest()


async def upload_file(file_path, signature, contents):
    # Make sure signature matches
    comp = get_file_signature(file_path)
    if not hmac.compare_digest(signature, comp):
        raise Exception("Invalid upload signature")

    full_path = os.path.join(get_uploads_dir(), file_path)
    dir_path = os.path.dirname(full_path)
    os.makedirs(dir_path, exist_ok=True)
    with open(full_path, "wb") as f:
        f.write(contents)

async def get_file_upload_url(ext, path_prefix):
    mimetypes = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "svg": "text/svg",
    }

    ext = ext.lower()
    if ext not in mimetypes:
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
            content_type=mimetypes[ext],
        )
        return url
    

    if UPLOAD_METHOD == "s3":
        s3_params = {
            "Bucket": S3_BUCKET,
            "Key": file_path,
            "ContentType": mimetypes[ext],
            "ACL": "public-read",
        }

        upload_url = get_s3().generate_presigned_url("put_object", Params=s3_params, ExpiresIn=15 * 60)
        
        file_url = S3_DOMAIN.rstrip("/") + "/" + file_path

        return {
            "uploadURL": upload_url,
            "fileURL": file_url,
        }
    elif UPLOAD_METHOD == "google-cloud":
        upload_url = await get_signed_google_url()

        file_url = GCS_DOMAIN.rstrip("/") + "/" + file_path

        return {
            "uploadURL": upload_url,
            "fileURL": file_url,
        }
    else:
        file_url = f"/upload/{file_path}"
        upload_url = f"/upload?path={file_path}&signature={get_file_signature(file_path)}"
        return {
            "uploadURL": upload_url,
            "fileURL": file_url,
        }
