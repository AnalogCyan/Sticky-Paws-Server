from flask import Flask, request, jsonify, send_from_directory, abort
from flask_limiter import Limiter
from flask_talisman import Talisman
from google.cloud import storage, secretmanager
import os
import base64
import io

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
    project_id="236548638255",
    secret_name="server-api-key",
    version_id="1"
)
response = client.access_secret_version(name=name)
secret_value = response.payload.data.decode('UTF-8')

# Configure allowed file extensions
ALLOWED_EXTENSIONS = {'zip'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Initialize Google Cloud Storage client
storage_client = storage.Client()
bucket_name = "sticky-paws.appspot.com"
bucket = storage_client.get_bucket(bucket_name)


# Serve static files (HTML, CSS, JS, etc.)
@app.route('/', defaults={'path': 'index.html'})
@app.route('/<path:path>')
@limiter.exempt
def serve_static(path):
    return send_from_directory('static', path)


# Upload a new content file to Google Cloud Storage
@app.route('/upload', methods=['POST'])
@limiter.exempt
# @limiter.limit("5 per minute")
def upload_level():
    #! Temporary API key for testing. Do not use in production.
    #! TODO: Update API security
    api_key = "626ef06a-5092-4d09-b423-45480b1d4e4d"
    if request.headers.get("X-API-Key") != api_key:
        return "Unauthorized", 401

    content_data_base64 = request.form['data']
    content_data = base64.b64decode(content_data_base64)
    content_type = request.form['content_type']

    if content_type not in ["levels", "characters"]:
        return "Invalid content type", 400
    content_filename = f"{content_type}" + "/" + request.form['name']

    blob = bucket.blob(content_filename)
    blob.upload_from_string(content_data, content_type="application/zip")

    return f"{content_type[:-1].capitalize()} uploaded successfully", 200


# Retrieve a list of available levels from Google Cloud Storage
@app.route('/levels', methods=['GET'])
@limiter.limit("10 per minute")
def get_levels():
    blobs = bucket.list_blobs()

    levels = [{
        'name': blob.name,
        'time_created': blob.time_created
    } for blob in blobs if blob.name.startswith("levels/") and blob.name.endswith(".zip")]

    sorted_levels = sorted(
        levels, key=lambda x: x['time_created'], reverse=True)

    return jsonify(sorted_levels), 200


# Retrieve a list of available characters from Google Cloud Storage
@app.route('/characters', methods=['GET'])
@limiter.limit("10 per minute")
def get_characters():
    blobs = bucket.list_blobs()

    characters = [{
        'name': blob.name,
        'time_created': blob.time_created
    } for blob in blobs if blob.name.startswith("characters/") and blob.name.endswith(".zip")]

    sorted_characters = sorted(
        characters, key=lambda x: x['time_created'], reverse=True)

    return jsonify(sorted_characters), 200


# Download a specific content file from Google Cloud Storage
@app.route('/download/<content_type>/<file_name>', methods=['GET'])
@limiter.limit("10 per minute")
def download_content(content_type, file_name):
    if content_type not in ["levels", "characters"]:
        abort(400, "Invalid content type")

    if not allowed_file(file_name + '.zip'):
        abort(400, "Invalid file extension")

    content_filename = f"{content_type}/{file_name}.zip"
    blob = bucket.blob(content_filename)

    if not blob.exists():
        abort(404, "File not found")

    with io.BytesIO() as content_data:
        blob.download_to_file(content_data)
        content_data.seek(0)
        content_data_base64 = base64.b64encode(
            content_data.read()).decode('utf-8')

    return jsonify({"name": file_name, "data": content_data_base64}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
