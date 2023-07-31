# Import required libraries
import base64
import io
import json
import os
import time
import zipfile

from datetime import timezone
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from functools import wraps
from google.cloud import storage, secretmanager
from io import BytesIO
from itsdangerous import URLSafeTimedSerializer
import requests


# Initialize Flask application
app = Flask(__name__)
app.config.update(
    dict(
        SERVER_NAME="sticky-paws.uc.r.appspot.com",
        PREFERRED_URL_SCHEME="https",
        SESSION_COOKIE_SECURE=True,
        REMEMBER_COOKIE_SECURE=True,
    )
)

# Initialize Flask plugins
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"],
    storage_uri="memory://",
    strategy="moving-window",
)
Talisman(app)

# Get Server API key from Google Cloud Secret Manager
client = secretmanager.SecretManagerServiceClient()
name = "projects/{project_id}/secrets/{secret_name}/versions/{version_id}".format(
    project_id="236548638255", secret_name="server-api-key", version_id="latest"
)
response = client.access_secret_version(name=name)
secret_value = response.payload.data.decode("UTF-8")
API_KEY = secret_value


# Get Mailgun API keys from Google Cloud Secret Manager
client = secretmanager.SecretManagerServiceClient()
name = "projects/{project_id}/secrets/{secret_name}/versions/{version_id}".format(
    project_id="236548638255", secret_name="mailgun-api-key", version_id="latest"
)
response = client.access_secret_version(name=name)
secret_value = response.payload.data.decode("UTF-8")
MAILGUN_API_KEY = secret_value


# Decorator function to check if the client is authorized to access the API
def require_api_key(view_function):
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        if request.headers.get("X-API-Key") != API_KEY:
            return "Unauthorized", 401
        return view_function(*args, **kwargs)

    return decorated_function


# Helper function to check if a file's size is within allowed limit
def allowed_size(file, max_size=32):
    # Check if file is a file-like object
    if not hasattr(file, "read") or not hasattr(file, "seek"):
        raise ValueError("The 'file' parameter must be a file-like object")

    # Store current file position
    current_position = file.tell()

    # Go to the end of the file
    file.seek(0, 2)  # 2 means 'relative to the end of file'

    # Get the size in bytes
    size_in_bytes = file.tell()

    # Restore original file position
    file.seek(current_position)

    # Convert size to megabytes (1 MB = 1024 * 1024 bytes)
    size_in_megabytes = size_in_bytes / 1048576.0

    # Check if the size is within the allowed limit
    return size_in_megabytes <= max_size


# Helper function to verify the uploaded file content
def verify_file(content_type, content_data):
    try:
        with zipfile.ZipFile(io.BytesIO(content_data), "r") as zip_ref:
            if content_type == "levels":
                required_files = {"level_information.ini"}
                thumbnail_files = {"thumbnail.png", "automatic_thumbnail.png"}
                object_placement_files = {
                    "object_placement_all.json",
                    "object_placement_all.txt",
                }
            elif content_type == "characters":
                required_files = {"character_config.ini"}
                thumbnail_files = set()
                object_placement_files = set()

            # Check if all required files are present in the uploaded zip file
            zip_files_no_folder = {file.split("/")[-1] for file in zip_ref.namelist()}

            if not required_files.issubset(zip_files_no_folder):
                return False

            # Check if at least one thumbnail file is present for the "levels" content type
            if content_type == "levels":
                if not thumbnail_files.intersection(zip_files_no_folder):
                    return False

                # Check if at least one object placement file is present
                if not object_placement_files.intersection(zip_files_no_folder):
                    return False

            # Add more file-specific validations here if needed

            return True
    except zipfile.BadZipFile:
        # If the uploaded file is not a valid zip file, return False
        return False


# Helper function to check if filename is valid
def allowed_filename(filename):
    # Strip the .zip extension from the filename
    if filename.endswith(".zip"):
        filename = filename[:-4]

    return filename.isalnum() and len(filename) == 9


# Initialize Google Cloud Storage client
storage_client = storage.Client()
bucket_name = "sticky-paws.appspot.com"
bucket = storage_client.get_bucket(bucket_name)


# Route to serve static files (HTML, CSS, JS, etc.)
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
@limiter.exempt
def serve_static(path):
    return send_from_directory("static", path)


# Route for uploading a new content file to Google Cloud Storage
@app.route("/upload", methods=["POST"])
@limiter.exempt
@require_api_key
def upload_level():
    if not allowed_filename(str(request.form["name"])):
        abort(400, "Invalid filename")

    content_data_base64 = request.form["data"]
    content_data = base64.b64decode(content_data_base64)
    content_type = request.form["content_type"]

    if content_type not in ["levels", "characters"]:
        return "Invalid content", 400

    max_allowed_size_in_megabytes = 32
    if not allowed_size(BytesIO(content_data), max_allowed_size_in_megabytes):
        return "Payload Too Large", 413

    content_filename = f"{content_type}" + "/" + request.form["name"]

    if not verify_file(content_type, content_data):
        return "Unsupported Media Type", 415

    blob = bucket.blob(content_filename)
    blob.upload_from_string(content_data, content_type="application/zip")
    blob.metadata["Uploaded-By"] = (
        request.access_route[0] if request.access_route else request.remote_addr
    )

    return f"{content_type[:-1].capitalize()} uploaded successfully", 200


# Route for retrieving a list of available levels from Google Cloud Storage
@app.route("/levels", methods=["GET"])
@limiter.exempt
def get_levels():
    blobs = bucket.list_blobs()

    levels = [
        {
            "name": blob.name,
            "time_created": blob.time_created.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        for blob in blobs
        if blob.name.startswith("levels/") and blob.name.endswith(".zip")
    ]

    sorted_levels = sorted(levels, key=lambda x: x["time_created"], reverse=True)

    return jsonify(sorted_levels), 200


# Route for retrieving a list of available characters from Google Cloud Storage
@app.route("/characters", methods=["GET"])
@limiter.exempt
def get_characters():
    blobs = bucket.list_blobs()

    characters = [
        {
            "name": blob.name,
            "time_created": blob.time_created.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        for blob in blobs
        if blob.name.startswith("characters/") and blob.name.endswith(".zip")
    ]

    sorted_characters = sorted(
        characters, key=lambda x: x["time_created"], reverse=True
    )

    return jsonify(sorted_characters), 200


# Route to retrieve metadata for a specific content file from Google Cloud Storage
@app.route("/metadata/<string:category>/<string:blob_name>", methods=["GET"])
@limiter.exempt
@require_api_key
def get_metadata(category, blob_name):
    if category not in ["levels", "characters"]:
        return "Invalid request.", 400

    if not allowed_filename(blob_name):
        abort(400, "Invalid file")

    blob_name = f"{category}/{blob_name}.zip"

    blob = bucket.get_blob(blob_name)
    zip_bytes = blob.download_as_bytes()

    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zip_file:
        root_folder = zip_file.namelist()[0].split("/")[0]
        name = root_folder

        thumbnail_data = None
        for file_name in ["thumbnail.png", "automatic_thumbnail.png"]:
            try:
                with zip_file.open(f"{root_folder}/{file_name}") as image_file:
                    thumbnail_data = base64.b64encode(image_file.read()).decode("utf-8")
                    break
            except KeyError:
                continue
        if thumbnail_data is None:
            raise Exception("Invalid file structure.")

    return json.dumps({"name": name, "thumbnail": thumbnail_data})


# Route to download a specific content file from Google Cloud Storage
@app.route("/download/<content_type>/<file_name>", methods=["GET"])
@limiter.exempt
@require_api_key
def download_content(content_type, file_name):
    if content_type not in ["levels", "characters"]:
        abort(400, "Invalid content")

    if not allowed_filename(file_name):
        abort(400, "Invalid file")

    content_filename = f"{content_type}/{file_name}.zip"
    blob = bucket.blob(content_filename)

    if not blob.exists():
        abort(404, "File not found")

    with io.BytesIO() as content_data:
        blob.download_to_file(content_data)
        content_data.seek(0)
        content_data_base64 = base64.b64encode(content_data.read()).decode("utf-8")

    return jsonify({"name": file_name, "data": content_data_base64}), 200


# Route for reporting a content file for review
@app.route("/report/<content_type>/<file_name>", methods=["POST"])
@limiter.exempt
@require_api_key
def report_content(content_type, file_name):
    if content_type not in ["levels", "characters"]:
        abort(400, "Invalid content")

    report_reason = request.form.get("report_reason", None)
    report_message = request.form.get("report_message", None)
    content_filename = f"{content_type}/{file_name}.zip"
    blob = bucket.blob(content_filename)
    metadata = blob.metadata
    keys = ["report_count", "report_reason"]

    if not blob.exists():
        abort(404, "File not found")

    for key in keys:
        if key == "report_count":
            value = int(metadata.get(key, 0)) + 1
            metadata[key] = str(value)
        elif key == "report_reason":
            message = f'{report_reason}: {report_message or "No message provided."}'
            reasons = metadata.get(key, "").split("|")
            reasons.append(message)
            metadata[key] = "|".join(reasons)

    blob.metadata = metadata
    blob.patch()

    if int(metadata[keys[0]]) >= 5:
        console_url = "https://console.cloud.google.com/storage/browser/{}/{}".format(
            bucket_name, file_name
        )
        requests.post(
            "https://api.mailgun.net/v3/sandbox198029222f0640d5a146332e0cbdb7a1.mailgun.org/messages",
            auth=("api", MAILGUN_API_KEY),
            data={
                "from": "Mailgun Sandbox <postmaster@sandbox198029222f0640d5a146332e0cbdb7a1.mailgun.org>",
                "to": "Jonnil <contact@jonnil.games>",
                "subject": "Sticky Paws - Content Report Alert",
                "template": "sticky paws - content report alert",
                "h:X-Mailgun-Variables": '{"file_name": "'
                + content_filename
                + '", "file_url": "'
                + console_url
                + '"}',
            },
        )


# Route that returns "418 I'm a teapot" to all requests as an easter egg
@app.route(
    "/teapot", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
)
@app.route(
    "/coffee", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
)
@limiter.exempt
def teapot():
    return "I'm a teapot", 418


# Route that returns "500 lp0 on fire" to all requests as an easter egg
@app.route(
    "/print", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
)
@limiter.exempt
def print():
    return "lp0 on fire", 500


# Start the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
