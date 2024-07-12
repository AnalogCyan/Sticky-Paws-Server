# Import required libraries
import base64
import io
import json
import os
import zipfile
from io import BytesIO
from functools import wraps

from configparser import ConfigParser
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from google.cloud import storage, secretmanager
import requests

from io import StringIO
from PIL import Image, ImageDraw, ImageFont
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

# Import tenacity for retry logic
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)


# Define a custom exception for retryable errors
class KeyFetchError(Exception):
    pass


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

# Define variables for Nintendo
ISSUER = "https://e97b8a9d672e4ce4845ec6947cd66ef6-sb.baas.nintendo.com"
JWKS_URI = (
    "https://e97b8a9d672e4ce4845ec6947cd66ef6-sb.baas.nintendo.com/1.0.0/certificates"
)
APPLICATION_ID = "01004b9000490000"
ALGORITHM = "RS256"


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


# Helper function to ensure text is wrapped correctly
def smart_wrap(text, width):
    """Custom wrap function that avoids breaking short words where possible"""
    words = text.split()
    lines = []
    current_line = []

    for word in words:
        test_line = " ".join(current_line + [word])
        if len(test_line) <= width:
            current_line.append(word)
        else:
            lines.append(" ".join(current_line))
            current_line = [word]

    if current_line:
        lines.append(" ".join(current_line))

    return "\n".join(lines)


# Helper function to convert text to image
def text_to_image(text):
    # Size of the image
    image_width = 320
    image_height = 240

    # Create a new image with a dark gray background
    image = Image.new("RGB", (image_width, image_height), (50, 50, 50))
    draw = ImageDraw.Draw(image)

    # Define initial font and size
    initial_font_size = 20  # Start with a reasonable size for clarity
    font_path = "Arial.ttf"

    try:
        font = ImageFont.truetype(font_path, initial_font_size)
    except IOError:
        print("Defaulting to load_default() because Arial.ttf could not be loaded.")
        font = ImageFont.load_default()

    # Estimate maximum characters in a single line based on the letter 'W'
    max_char_in_line = image_width // (font.getbbox("W")[2] - font.getbbox("W")[0])
    wrapped_text = smart_wrap(text, max_char_in_line)
    lines = wrapped_text.split("\n")

    # Adjusting font size if the total text height exceeds the image height
    max_attempts = 5
    attempt = 0
    total_text_height = sum(font.getbbox(line)[3] for line in lines)

    while (
        total_text_height > image_height
        and initial_font_size > 10
        and attempt < max_attempts
    ):
        initial_font_size -= 1
        font = (
            ImageFont.truetype(font_path, initial_font_size)
            if font_path
            else ImageFont.load_default()
        )
        wrapped_text = smart_wrap(text, max_char_in_line)
        lines = wrapped_text.split("\n")
        total_text_height = sum(font.getbbox(line)[3] for line in lines)
        attempt += 1

    # Drawing text
    y = (image_height - total_text_height) // 2
    for line in lines:
        line_width = font.getbbox(line)[2]
        x = (image_width - line_width) // 2
        draw.text((x, y), line, font=font, fill="white")
        y += font.getbbox(line)[3]

    # Return the image
    return image


# Helper function to check if blob is unlisted
def check_unlisted(blob):
    level_unlisted = False
    zip_bytes = blob.download_as_bytes()
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zip_file:
        root_folder = zip_file.namelist()[0].split("/")[0]
        for file_name in ["level_information.ini"]:
            with zip_file.open(f"{root_folder}/data/{file_name}") as ini_file:
                ini_data = ini_file.read().decode("utf-8")
                config = ConfigParser()
                config.read_string(ini_data)
            if config.has_option("info", "visibility_index"):
                if (config.get("info", "visibility_index")) == '"1.000000"':
                    level_unlisted = True
                    break
    return level_unlisted


# Helper function to get JWKS from Nintendo with retry logic
@retry(
    stop=stop_after_attempt(5),  # Retry up to 5 times
    wait=wait_exponential(multiplier=1, min=2, max=10),  # Exponential backoff
    retry=retry_if_exception_type(KeyFetchError),  # Retry only on KeyFetchError
)
def get_jwks_with_retry(jwks_uri):
    try:
        response = requests.get(jwks_uri)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise KeyFetchError(f"Failed to fetch JWKS: {e}")


# Helper function to get public key from JWKS with retry logic
def public_key(jwks_uri, kid):
    try:
        jwks = get_jwks_with_retry(jwks_uri)
        keys = jwks["keys"]
        jwk = next((k for k in keys if k["kid"] == kid), None)
        if jwk:
            cert_str = jwk["x5c"][0]
            pem_cert = (
                f"-----BEGIN CERTIFICATE-----\n{cert_str}\n-----END CERTIFICATE-----"
            )
            cert_obj = load_pem_x509_certificate(pem_cert.encode())
            return cert_obj.public_key()
        else:
            raise KeyFetchError(f"Key with kid {kid} not found in JWKS")
    except KeyFetchError as e:
        print(f"Error fetching public key: {e}")
        return None


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
    if blob.metadata is None:
        blob.metadata = {}
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
        if blob.name.startswith("levels/")
        and blob.name.endswith(".zip")
        and not check_unlisted(blob)
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
@app.route("/metadata/<category>/<blob_name>", methods=["GET"])
@limiter.exempt
# @require_api_key
def get_metadata(category, blob_name):
    os_type = request.args.get("os_type", "os_unknown").lower()
    print(str(os_type))

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
        photographic = False
        thumbnail_data = None

        if category == "levels":
            for file_name in ["thumbnail.png", "automatic_thumbnail.png"]:
                try:
                    with zip_file.open(f"{root_folder}/{file_name}") as image_file:
                        thumbnail_data = base64.b64encode(image_file.read()).decode(
                            "utf-8"
                        )
                        break
                except KeyError:
                    continue
            if str(os_type) == "21":
                for file_name in ["level_information.ini"]:
                    with zip_file.open(f"{root_folder}/data/{file_name}") as ini_file:
                        ini_data = ini_file.read().decode("utf-8")
                        config = ConfigParser()
                        config.read_string(ini_data)

                    if config.has_option(
                        "Custom Backgrounds",
                        "thumbnail_uses_photographic_image",
                    ):
                        if (
                            config.get(
                                "Custom Backgrounds",
                                "thumbnail_uses_photographic_image",
                            )
                            == '"1.000000"'
                        ) and str(os_type) == "21":
                            photographic = True
                            break
            if photographic or thumbnail_data is None:
                img_byte_arr = BytesIO()
                text_to_image(name).save(img_byte_arr, format="PNG")
                thumbnail_data = base64.b64encode(img_byte_arr.getvalue()).decode(
                    "utf-8"
                )
        elif category == "characters":
            for file_name in [
                "thumbnail.png",
                "sprites/character_select_portrait.png",
                "sprites/stand.png",
                "sprites/skin0/character_select_portrait.png",
                "sprites/skin0/stand.png",
            ]:
                try:
                    with zip_file.open(f"{root_folder}/{file_name}") as image_file:
                        thumbnail_data = base64.b64encode(image_file.read()).decode(
                            "utf-8"
                        )
                        break
                except KeyError:
                    continue

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

    if blob.metadata is None:
        metadata = {}

    for key in keys:
        if key == "report_count":
            value = int(metadata.get(key, 0)) + 1
            metadata[key] = str(value)
        elif key == "report_reason":
            message = f'{report_reason}: {report_message if report_message else "No message provided."}'
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
            timeout=30,
        )

    return "Report submitted successfully.", 200


# Route for fetching how many levels and characters were uploaded today
@app.route("/today", methods=["GET"])
@limiter.exempt
def today():
    today = datetime.now(timezone.utc).date()

    # Function to count blobs uploaded today for a given prefix
    def count_blobs_uploaded_today(prefix, exclude_unlisted=False):
        blobs = bucket.list_blobs(prefix=prefix)
        count = 0
        for blob in blobs:
            if blob.time_created.date() == today:
                if exclude_unlisted and check_unlisted(blob):
                    continue
                count += 1
        return count

    # Get counts for each prefix
    levels_uploaded_today = count_blobs_uploaded_today("levels/", exclude_unlisted=True)
    characters_uploaded_today = count_blobs_uploaded_today("characters/")

    return jsonify(
        {
            "levels_uploaded_today": levels_uploaded_today,
            "characters_uploaded_today": characters_uploaded_today,
        }
    )


# Route for Nintendo Switch token validation
@app.route("/validate_token", methods=["GET"])
@limiter.exempt
def validate_token():
    id_token = request.args.get("id_token")
    if not id_token:
        return jsonify({"error": "Missing id_token"}), 400

    try:
        # Decode without verification to get headers
        unverified_header = jwt.get_unverified_header(id_token)

        # Validate the algorithm
        if unverified_header["alg"] != ALGORITHM:
            return jsonify({"error": "Invalid algorithm"}), 400

        # Validate the jku
        if unverified_header.get("jku") != JWKS_URI:
            return jsonify({"error": "Invalid jku"}), 400

        # Retrieve the public key
        key = public_key(JWKS_URI, unverified_header["kid"])
        if not key:
            return jsonify({"error": "Public key not found"}), 400

        # Decode and validate the JWT
        payload = jwt.decode(
            id_token,
            key,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={
                "verify_aud": False,  # Disable audience verification
                "verify_exp": False,  # Disable expiration verification
            },
        )

        # Validate 'iat' and 'exp'
        if payload["iat"] > payload["exp"]:
            return jsonify({"error": "Invalid 'iat' and 'exp' values"}), 400

        # Validate nintendo.ai value
        nintendo = payload["nintendo"]
        if nintendo["ai"].lower() != APPLICATION_ID.lower():
            return jsonify({"error": "Invalid Nintendo AI value"}), 400

        return payload, 200

    except jwt.ExpiredSignatureError as e:
        print(f"Token expired: {e}")
        return jsonify({"error": "Token has expired"}), 400
    except jwt.InvalidAudienceError as e:
        print(f"Invalid audience: {e}")
        return jsonify({"error": "Audience doesn't match"}), 400
    except jwt.InvalidIssuerError as e:
        print(f"Invalid issuer: {e}")
        return jsonify({"error": "Issuer doesn't match"}), 400
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {e}")
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({"error": "An unexpected error occurred"}), 500


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
def lp0():
    return "lp0 on fire", 500


# Start the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
