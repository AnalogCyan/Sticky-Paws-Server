# Sticky Paws Server

This repository contains the server-side code for the game [Sticky Paws](https://github.com/Jonnil/Sticky-Paws-DX). The server is written in Python and provides API endpoints for uploading, listing, and downloading custom levels/characters.

## API Endpoints

- `/upload`: Upload a custom level/character created by a user. The request should contain base64-encoded data.
- `/levels`: List all the custom levels available for download. This endpoint returns a list of available custom levels sorted by date uploaded.
- `/characters`: List all the custom characters available for download. This endpoint returns a list of available custom characters sorted by date uploaded.
- `/download`: Download a specific custom level/character. The request should include the content type and ID as parameters.

## License

This project is licensed under the [Apache 2.0](./LICENSE) License.
