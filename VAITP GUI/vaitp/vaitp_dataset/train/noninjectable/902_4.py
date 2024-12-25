import os
from dotenv import load_dotenv
import json
import re

load_dotenv(dotenv_path=".env.local", verbose=True)

ENVIRONMENT = os.getenv("NODE_ENV")
prod = ENVIRONMENT == "production"

IS_CLOUD = bool(os.getenv("IS_CLOUD"))


def get_upload_method():
    if IS_CLOUD:
        return "s3"

    method = os.getenv("UPLOAD_METHOD")
    if method and method in ["s3", "google-cloud"]:
        return method

    return "local"

UPLOAD_METHOD = get_upload_method()

MONGODB_URI = os.getenv("MONGODB_URI") or (
    "" if prod else "mongodb://root:password@localhost:27017/"
)
if not MONGODB_URI:
    raise ValueError("Missing MONGODB_URI environment variable")

APP_ORIGIN = os.getenv("APP_ORIGIN") or "http://localhost:3000"

cors_origin_regex = os.getenv("CORS_ORIGIN_REGEX")
CORS_ORIGIN_REGEX = re.compile(cors_origin_regex, re.I) if cors_origin_regex else None

GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID") or ""
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET") or ""

S3_BUCKET = os.getenv("S3_BUCKET") or ""
S3_REGION = os.getenv("S3_REGION") or "us-east-1"
S3_DOMAIN = os.getenv("S3_DOMAIN") or f"https://{S3_BUCKET}.s3.amazonaws.com/"
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY") or "dev"
if prod and ENCRYPTION_KEY == "dev":
    raise ValueError(
        "Cannot use ENCRYPTION_KEY=dev in production. Please set to a long random string."
    )

GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME") or ""
GCS_DOMAIN = (
    os.getenv("GCS_DOMAIN")
    or f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/"
)

JWT_SECRET = os.getenv("JWT_SECRET") or "dev"
if prod and not IS_CLOUD and JWT_SECRET == "dev":
    raise ValueError(
        "Cannot use JWT_SECRET=dev in production. Please set to a long random string."
    )

EMAIL_ENABLED = os.getenv("EMAIL_ENABLED") == "true"
EMAIL_HOST = os.getenv("EMAIL_HOST")
EMAIL_PORT = int(os.getenv("EMAIL_PORT") or 587)
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
EMAIL_FROM = os.getenv("EMAIL_FROM")
SITE_MANAGER_EMAIL = os.getenv("SITE_MANAGER_EMAIL")

STRIPE_SECRET = os.getenv("STRIPE_SECRET") or ""
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET") or ""
STRIPE_PRICE = os.getenv("STRIPE_PRICE") or ""

SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET") or ""

test_conn = os.getenv("POSTGRES_TEST_CONN")
POSTGRES_TEST_CONN = json.loads(test_conn) if test_conn else {}


AWS_CLOUDFRONT_DISTRIBUTION_ID = os.getenv("AWS_CLOUDFRONT_DISTRIBUTION_ID") or ""


EXPERIMENT_REFRESH_FREQUENCY = int(
    os.getenv("EXPERIMENT_REFRESH_FREQUENCY") or 6
)


DEFAULT_CONVERSION_WINDOW_HOURS = int(
    os.getenv("DEFAULT_CONVERSION_WINDOW_HOURS") or 72
)


METRIC_REFRESH_FREQUENCY = int(os.getenv("METRIC_REFRESH_FREQUENCY") or 24)

QUERY_CACHE_TTL_MINS = int(os.getenv("QUERY_CACHE_TTL_MINS") or 60)

IMPORT_LIMIT_DAYS = int(os.getenv("IMPORT_LIMIT_DAYS") or 365)

CRON_ENABLED = not bool(os.getenv("CRON_DISABLED"))