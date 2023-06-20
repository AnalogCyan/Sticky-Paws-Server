import base64
import io
import json
import os
import re
import zipfile
import zlib
from datetime import datetime, timezone
from io import BytesIO
from zipfile import ZipFile

from PIL import Image
from flask import Flask, request, jsonify, send_file, send_from_directory, abort
from flask_limiter import Limiter
from flask_talisman import Talisman
from google.cloud import storage, secretmanager
from passageidentity import Passage
from wtforms import Form, StringField, validators

import antigravity


# Initialize Flask app and rate limiter
app = Flask(__name__)
app.config["SERVER_NAME"] = "sticky-paws.uc.r.appspot.com"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_SECURE"] = True

limiter = Limiter(app, default_limits=["10 per minute"])
Talisman(app)

# Get API key from Google Cloud Secret Manager
client = secretmanager.SecretManagerServiceClient()
name = "projects/{project_id}/secrets/{secret_name}/versions/{version_id}".format(
    project_id="236548638255", secret_name="server-api-key", version_id="latest"
)
response = client.access_secret_version(name=name)
secret_value = response.payload.data.decode("UTF-8")
API_KEY = secret_value

# Configure Passage for authentication
PASSAGE_APP_ID = os.environ.get("PASSAGE_APP_ID")


class AuthenticationMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        request = Request(environ)
        psg = Passage(PASSAGE_APP_ID)
        try:
            user = psg.authenticateRequest(request)
        except:
            ret = Response("Authorization failed", mimetype="text/plain", status=401)
            return ret(environ, start_response)
        environ["user"] = user
        return self.app(environ, start_response)


@app.route("/auth", methods=["GET", "POST"])
def authenticatedRoute():
    passageID = environ["user"]
    authorized = authorizationCheck(passageID)
    if authorized:
        return "Authorized"


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


def allowed_filename(filename):
    return filename.isalnum() and len(filename) == 9


# Initialize Google Cloud Storage client
storage_client = storage.Client()
bucket_name = "sticky-paws.appspot.com"
bucket = storage_client.get_bucket(bucket_name)


# Serve static files (HTML, CSS, JS, etc.)
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
@limiter.exempt
def serve_static(path):
    return send_from_directory("static", path)


# Upload a new content file to Google Cloud Storage
@app.route("/upload", methods=["POST"])
@limiter.exempt
# @limiter.limit("5 per minute")
def upload_level():
    if request.headers.get("X-API-Key") != API_KEY:
        return "Unauthorized", 401

    if not allowed_filename(request.form["name"]):
        abort(400, "Invalid file")

    content_data_base64 = request.form["data"]
    content_data = base64.b64decode(content_data_base64)
    content_type = request.form["content_type"]

    if content_type not in ["levels", "characters"]:
        return "Invalid content", 400

    max_allowed_size_in_megabytes = 32
    if not allowed_size(BytesIO(content_data), max_allowed_size_in_megabytes):
        return "File is too large", 400

    content_filename = f"{content_type}" + "/" + request.form["name"]

    if not verify_file(content_type, content_data):
        return "Invalid file", 400

    blob = bucket.blob(content_filename)
    blob.upload_from_string(content_data, content_type="application/zip")

    return f"{content_type[:-1].capitalize()} uploaded successfully", 200


# Retrieve a list of available levels from Google Cloud Storage
@app.route("/levels", methods=["GET"])
@limiter.exempt
# @limiter.limit("10 per minute")
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


# Retrieve a list of available characters from Google Cloud Storage
@app.route("/characters", methods=["GET"])
@limiter.exempt
# @limiter.limit("10 per minute")
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


# Retrieve metadata for a specific content file from Google Cloud Storage
@app.route("/metadata/<string:category>/<string:blob_name>", methods=["GET"])
@limiter.exempt
def get_metadata(category, blob_name):
    if request.headers.get("X-API-Key") != API_KEY:
        return "Unauthorized", 401

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


# Download a specific content file from Google Cloud Storage
@app.route("/download/<content_type>/<file_name>", methods=["GET"])
@limiter.limit("10 per minute")
def download_content(content_type, file_name):
    if request.headers.get("X-API-Key") != API_KEY:
        return "Unauthorized", 401

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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
