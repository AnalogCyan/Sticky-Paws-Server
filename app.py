import base64, io, json, os, zipfile, jwt
from io import BytesIO, StringIO
from functools import wraps
from configparser import ConfigParser
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from google.cloud import storage, secretmanager
import requests
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)


# Custom exception for key fetching errors
class KeyFetchError(Exception):
    pass


# Flask application initialization
app = Flask(__name__)
app.config.update(
    dict(
        SERVER_NAME="sticky-paws.uc.r.appspot.com",
        PREFERRED_URL_SCHEME="https",
        SESSION_COOKIE_SECURE=True,
        REMEMBER_COOKIE_SECURE=True,
    )
)

# Set up rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"],
    storage_uri="memory://",
    strategy="moving-window",
)

# Add security headers using Talisman
Talisman(app)

# Google Cloud Secret Manager to retrieve API key
secret_manager_client = secretmanager.SecretManagerServiceClient()
secret_name = "projects/{}/secrets/{}/versions/{}".format(
    "236548638255", "server-api-key", "latest"
)
secret_response = secret_manager_client.access_secret_version(name=secret_name)
API_KEY = secret_response.payload.data.decode("UTF-8")

# JWT settings
ALGORITHM = "RS256"
APPLICATION_IDS = ["01004b9000490000", "0100c8201aa36000"]


# Decorator to enforce API key requirement
def require_api_key(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if request.headers.get("X-API-Key") != API_KEY:
            return ("Unauthorized", 401)
        return func(*args, **kwargs)

    return decorated_function


# Check if file size is within allowed limit
def allowed_file_size(file_object, max_size_mb=32):
    if not hasattr(file_object, "read") or not hasattr(file_object, "seek"):
        raise ValueError("The 'file' parameter must be a file-like object")
    current_position = file_object.tell()
    file_object.seek(0, 2)
    file_size = file_object.tell()
    file_object.seek(current_position)
    return file_size / 1048576.0 <= max_size_mb


# Verify the content of uploaded files
def verify_file_content(file_type, file_data):
    try:
        with zipfile.ZipFile(io.BytesIO(file_data), "r") as zip_file:
            # Determine required files based on file type
            required_files = (
                {"level_information.ini"}
                if file_type == "levels"
                else {"character_config.ini"} if file_type == "characters" else set()
            )
            thumbnail_files = (
                {"thumbnail.png", "automatic_thumbnail.png"}
                if file_type == "levels"
                else set()
            )
            object_files = (
                {"object_placement_all.json", "object_placement_all.txt"}
                if file_type == "levels"
                else set()
            )
            zip_file_names = {os.path.basename(file) for file in zip_file.namelist()}
            # Check if all required files are present
            return required_files.issubset(zip_file_names) and (
                not file_type == "levels"
                or thumbnail_files.intersection(zip_file_names)
                and object_files.intersection(zip_file_names)
            )
    except zipfile.BadZipFile:
        return False


# Check if the filename is valid
def is_valid_filename(filename):
    return (
        filename[:-4].isalnum() and len(filename[:-4]) == 9
        if filename.endswith(".zip")
        else filename.isalnum() and len(filename) == 9
    )


# Smartly wrap text to fit within a given width
def smart_wrap_text(text, max_width):
    words = text.split()
    lines = []
    current_line = []
    for word in words:
        test_line = " ".join(current_line + [word])
        if len(test_line) <= max_width:
            current_line.append(word)
        else:
            lines.append(" ".join(current_line))
            current_line = [word]
    if current_line:
        lines.append(" ".join(current_line))
    return "\n".join(lines)


# Generate an image from the given text
def generate_text_image(text):
    image_width, image_height = 320, 240
    image = Image.new("RGB", (image_width, image_height), (50, 50, 50))
    draw = ImageDraw.Draw(image)
    font_size = 20
    font_path = "Arial.ttf"
    try:
        font = ImageFont.truetype(font_path, font_size)
    except:
        font = ImageFont.load_default()
    max_chars_per_line = image_width // (font.getbbox("W")[2] - font.getbbox("W")[0])
    wrapped_text = smart_wrap_text(text, max_chars_per_line)
    lines = wrapped_text.split("\n")
    max_attempts = 5
    attempt_count = 0
    text_height = sum(font.getbbox(line)[3] for line in lines)
    # Reduce font size if text exceeds image height
    while (
        text_height > image_height and font_size > 10 and attempt_count < max_attempts
    ):
        font_size -= 1
        font = (
            ImageFont.truetype(font_path, font_size)
            if font_path
            else ImageFont.load_default()
        )
        wrapped_text = smart_wrap_text(text, max_chars_per_line)
        lines = wrapped_text.split("\n")
        text_height = sum(font.getbbox(line)[3] for line in lines)
        attempt_count += 1
    y_position = (image_height - text_height) // 2
    for line in lines:
        line_width = font.getbbox(line)[2]
        x_position = (image_width - line_width) // 2
        draw.text((x_position, y_position), line, font=font, fill="white")
        y_position += font.getbbox(line)[3]
    return image


# Check if a level is unlisted based on metadata
def is_unlisted(blob):
    unlisted = False
    with zipfile.ZipFile(io.BytesIO(blob.download_as_bytes()), "r") as zip_file:
        root_folder = zip_file.namelist()[0].split("/")[0]
        with zip_file.open(f"{root_folder}/data/level_information.ini") as file:
            config = ConfigParser()
            config.read_string(file.read().decode("utf-8"))
            if (
                config.has_option("info", "visibility_index")
                and config.get("info", "visibility_index") == '"1.000000"'
            ):
                unlisted = True
    return unlisted


# Retry mechanism to fetch JWKS with exponential backoff
@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(KeyFetchError),
)
def get_jwks_with_retry(jwks_uri):
    try:
        response = requests.get(jwks_uri)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as error:
        raise KeyFetchError(f"Failed to fetch JWKS: {error}")


# Fetch the public key from JWKS endpoint
def fetch_public_key(jwks_uri, key_id):
    try:
        jwks = get_jwks_with_retry(jwks_uri)
        keys = jwks["keys"]
        jwt_key = next((key for key in keys if key["kid"] == key_id), None)
        if jwt_key:
            certificate = jwt_key["x5c"][0]
            pem_certificate = (
                f"-----BEGIN CERTIFICATE-----\n{certificate}\n-----END CERTIFICATE-----"
            )
            return load_pem_x509_certificate(pem_certificate.encode()).public_key()
        else:
            raise KeyFetchError(f"Key with kid {key_id} not found in JWKS")
    except KeyFetchError as error:
        print(f"Error fetching public key: {error}")
        return None


# Initialize Google Cloud Storage client and bucket
storage_client = storage.Client()
bucket_name = "sticky-paws.appspot.com"
bucket = storage_client.get_bucket(bucket_name)


# Serve static files from the 'static' directory
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
@limiter.exempt
def serve_static_files(path):
    return send_from_directory("static", path)


# Handle file upload requests
@app.route("/upload", methods=["POST"])
@limiter.exempt
@require_api_key
def upload_content():
    if not is_valid_filename(str(request.form["name"])):
        abort(400, "Invalid filename")
    content_data = base64.b64decode(request.form["data"])
    content_type = request.form["content_type"]
    if content_type not in ["levels", "characters"]:
        return "Invalid content", 400
    if not allowed_file_size(BytesIO(content_data), 32):
        return "Payload Too Large", 413
    content_filename = f"{content_type}/" + request.form["name"]
    if not verify_file_content(content_type, content_data):
        return "Unsupported Media Type", 415
    blob = bucket.blob(content_filename)
    blob.upload_from_string(content_data, content_type="application/zip")
    if blob.metadata is None:
        blob.metadata = {}
    blob.metadata["Uploaded-By"] = (
        request.access_route[0] if request.access_route else request.remote_addr
    )
    return f"{content_type[:-1].capitalize()} uploaded successfully", 200


# Retrieve the list of uploaded levels
@app.route("/levels", methods=["GET"])
@limiter.exempt
def get_levels():
    blobs = bucket.list_blobs()
    level_list = [
        {
            "name": blob.name,
            "time_created": blob.time_created.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        for blob in blobs
        if blob.name.startswith("levels/")
        and blob.name.endswith(".zip")
        and not is_unlisted(blob)
    ]
    return (
        jsonify(sorted(level_list, key=lambda x: x["time_created"], reverse=True)),
        200,
    )


# Retrieve the list of uploaded characters
@app.route("/characters", methods=["GET"])
@limiter.exempt
def get_characters():
    blobs = bucket.list_blobs()
    character_list = [
        {
            "name": blob.name,
            "time_created": blob.time_created.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        for blob in blobs
        if blob.name.startswith("characters/") and blob.name.endswith(".zip")
    ]
    return (
        jsonify(sorted(character_list, key=lambda x: x["time_created"], reverse=True)),
        200,
    )


# Retrieve metadata for a specific level or character
@app.route("/metadata/<category>/<blob_name>", methods=["GET"])
@limiter.exempt
def get_metadata(category, blob_name):
    os_type = request.args.get("os_type", "os_unknown").lower()
    if category not in ["levels", "characters"]:
        return "Invalid request.", 400
    if not is_valid_filename(blob_name):
        abort(400, "Invalid file")
    blob_full_name = f"{category}/{blob_name}.zip"
    blob = bucket.get_blob(blob_full_name)
    blob_data = blob.download_as_bytes()
    with zipfile.ZipFile(io.BytesIO(blob_data), "r") as zip_file:
        root_folder = zip_file.namelist()[0].split("/")[0]
        name = root_folder
        placeholder_thumbnail = False
        thumbnail_data = None
        # Handle metadata for levels
        if category == "levels":
            for filename in ["thumbnail.png", "automatic_thumbnail.png"]:
                try:
                    with zip_file.open(f"{root_folder}/{filename}") as file:
                        thumbnail_data = base64.b64encode(file.read()).decode("utf-8")
                        break
                except KeyError:
                    continue
            if str(os_type) == "21":
                for filename in ["level_information.ini"]:
                    with zip_file.open(f"{root_folder}/data/{filename}") as file:
                        config = ConfigParser()
                        config.read_string(file.read().decode("utf-8"))
                        if (
                            config.has_option(
                                "Custom Backgrounds",
                                "thumbnail_uses_photographic_image",
                            )
                            and config.get(
                                "Custom Backgrounds",
                                "thumbnail_uses_photographic_image",
                            )
                            == '"1.000000"'
                            and str(os_type) == "21"
                        ):
                            placeholder_thumbnail = True
                            break
            if placeholder_thumbnail or thumbnail_data is None:
                image_bytes = BytesIO()
                generate_text_image(name).save(image_bytes, format="PNG")
                thumbnail_data = base64.b64encode(image_bytes.getvalue()).decode(
                    "utf-8"
                )
        # Handle metadata for characters
        elif category == "characters":
            for filename in [
                "thumbnail.png",
                "sprites/character_select_portrait.png",
                "sprites/stand.png",
                "sprites/skin0/character_select_portrait.png",
                "sprites/skin0/stand.png",
            ]:
                try:
                    with zip_file.open(f"{root_folder}/{filename}") as file:
                        thumbnail_data = base64.b64encode(file.read()).decode("utf-8")
                        break
                except KeyError:
                    continue
    return json.dumps({"name": name, "thumbnail": thumbnail_data})


# Download specific content
@app.route("/download/<content_type>/<file_name>", methods=["GET"])
@limiter.exempt
@require_api_key
def download_content(content_type, file_name):
    if content_type not in ["levels", "characters"]:
        abort(400, "Invalid content")
    if not is_valid_filename(file_name):
        abort(400, "Invalid file")
    content_full_name = f"{content_type}/{file_name}.zip"
    blob = bucket.blob(content_full_name)
    if not blob.exists():
        abort(404, "File not found")
    with io.BytesIO() as content_data:
        blob.download_to_file(content_data)
        content_data.seek(0)
        encoded_content_data = base64.b64encode(content_data.read()).decode("utf-8")
    return jsonify({"name": file_name, "data": encoded_content_data}), 200


# Report specific content for moderation
@app.route("/report/<content_type>/<file_name>", methods=["POST"])
@limiter.exempt
@require_api_key
def report_content(content_type, file_name):
    if content_type not in ["levels", "characters"]:
        abort(400, "Invalid content")
    report_reason = request.form.get("report_reason", None)
    report_message = request.form.get("report_message", None)
    content_full_name = f"{content_type}/{file_name}.zip"
    blob = bucket.blob(content_full_name)
    metadata = blob.metadata
    metadata_keys = ["report_count", "report_reason"]
    if not blob.exists():
        abort(404, "File not found")
    if blob.metadata is None:
        metadata = {}
    for key in metadata_keys:
        if key == "report_count":
            report_count = int(metadata.get(key, 0)) + 1
            metadata[key] = str(report_count)
        elif key == "report_reason":
            message = f'{report_reason}: {report_message if report_message else "No message provided."}'
            reasons = metadata.get(key, "").split("|")
            reasons.append(message)
            metadata[key] = "|".join(reasons)
    blob.metadata = metadata
    blob.patch()
    return "Report submitted successfully.", 200


# Get today's uploads
@app.route("/today", methods=["GET"])
@limiter.exempt
def get_today_uploads():
    today_date = datetime.now(timezone.utc).date()

    # Count the number of uploads based on prefix and optionally exclude unlisted content
    def count_uploads(prefix, exclude_unlisted=False):
        blobs = bucket.list_blobs(prefix=prefix)
        count = 0
        for blob in blobs:
            if blob.time_created.date() == today_date:
                if exclude_unlisted and is_unlisted(blob):
                    continue
                count += 1
        return count

    return (
        jsonify(
            {
                "levels_uploaded_today": count_uploads("levels/", True),
                "characters_uploaded_today": count_uploads("characters/"),
            }
        ),
        200,
    )


# Validate Nintendo token
@app.route("/validate_token", methods=["GET"])
@limiter.exempt
def validate_nintendo_token():
    id_token = request.args.get("id_token")
    if not id_token:
        return jsonify({"error": "Missing id_token"}), 400

    try:
        # Get unverified header to access token metadata
        unverified_header = jwt.get_unverified_header(id_token)

        # Validate algorithm
        if unverified_header["alg"] != ALGORITHM:
            return jsonify({"error": "Invalid algorithm"}), 400

        # Get token claims without verification to access issuer
        unverified_claims = jwt.decode(id_token, options={"verify_signature": False})
        issuer = unverified_claims.get("iss")

        if not issuer:
            return jsonify({"error": "Missing issuer claim"}), 400

        # Construct JWKS URI from issuer
        jwks_uri = f"{issuer}/1.0.0/certificates"

        # Validate JKU matches issuer
        if unverified_header.get("jku") != jwks_uri:
            return jsonify({"error": "Invalid jku"}), 400

        # Fetch public key and verify token
        key = fetch_public_key(jwks_uri, unverified_header["kid"])
        if not key:
            return jsonify({"error": "Public key not found"}), 400

        # Verify token with appropriate issuer
        payload = jwt.decode(
            id_token,
            key,
            algorithms=[ALGORITHM],
            issuer=issuer,
            options={"verify_aud": False, "verify_exp": False},
        )

        # Validate timestamp order
        if payload["iat"] > payload["exp"]:
            return jsonify({"error": "Invalid 'iat' and 'exp' values"}), 400

        # Validate application ID
        nintendo_data = payload["nintendo"]
        if nintendo_data["ai"].lower() not in [
            app_id.lower() for app_id in APPLICATION_IDS
        ]:
            return jsonify({"error": "Invalid Nintendo AI value"}), 400

        return payload, 200

    except jwt.ExpiredSignatureError as error:
        print(f"Token expired: {error}")
        return jsonify({"error": "Token has expired"}), 400
    except jwt.InvalidAudienceError as error:
        print(f"Invalid audience: {error}")
        return jsonify({"error": "Audience doesn't match"}), 400
    except jwt.InvalidIssuerError as error:
        print(f"Invalid issuer: {error}")
        return jsonify({"error": "Issuer doesn't match"}), 400
    except jwt.InvalidTokenError as error:
        print(f"Invalid token: {error}")
        return jsonify({"error": str(error)}), 400
    except Exception as error:
        print(f"Unexpected error: {error}")
        return jsonify({"error": "An unexpected error occurred"}), 500


# Handle requests to '/teapot' and '/coffee' with a humorous response
@app.route(
    "/teapot", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
)
@app.route(
    "/coffee", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
)
@limiter.exempt
def handle_teapot():
    return "I'm a teapot", 418


# Handle requests to '/print' with a humorous error response
@app.route(
    "/print", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
)
@limiter.exempt
def handle_lp0():
    return "lp0 on fire", 500


# Run the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
