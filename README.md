# Sticky Paws Server

This repository contains the server-side code for the game [Sticky Paws](https://github.com/Jonnil/Sticky-Paws-DX). The server is written in Python and provides API endpoints for uploading, listing, and downloading custom levels/characters.

## Functions

The following functions are defined on the Flask server:

- `require_api_key()`: Ensures that every request to the server is accompanied by a valid API key. Provides an additional layer of security.
- `allowed_size()`: Checks the size of uploaded files, ensuring they adhere to the defined size limit to maintain server efficiency.
- `verify_file()`: Verifies the integrity and format of uploaded files for proper game execution and to prevent any damage.
- `allowed_filename()`: Validates the filenames of uploaded files to maintain consistency and prevent potential file errors.
- `smart_wrap()`: Ensures that text is wrapped correctly to avoid breaking short words where possible.
- `text_to_image()`: Converts text to an image for missing thumbnails and photographic content on Nintendo Switch.

## API Endpoints

The following API endpoints are defined on the Flask server:

- `/`: Static route for testing and initial debugging purposes. Responds with a webpage displaying uploaded files.
- `/upload`: Upload a custom level/character created by a user. The request should contain base64-encoded data representing the character or level.
- `/levels`: List all the custom levels available for download. This endpoint returns a list of available custom levels sorted by date uploaded.
- `/characters`: List all the custom characters available for download. This endpoint returns a list of available custom characters sorted by date uploaded.
- `/metadata`: Retrieve metadata for a specified file, including name and thumbnail.
- `/download`: Download a specified custom level/character by sending a request with the content type (level or character) and ID as parameters.
- `/report`: Submit a report for a file that may violate our community guidelines.
- `/today`: Retrieve how many levels/characters were uploaded today (UTC, this may change).

## Disclaimer

Please be aware that this project represents a learning journey for both myself and [Jonnil](https://github.com/Jonnil). As such, aspects such as the code structure, commit history, and overall organization may not conform to industry standards or best practices at all times. We strived for progress and learning over perfection in this endeavor. We appreciate your understanding and, should you find something that could be improved, we welcome constructive criticism and suggestions. Please bear with us as we continue to grow and learn in our programming journey.

## License

This project is licensed under the [Apache 2.0](./LICENSE) License.
