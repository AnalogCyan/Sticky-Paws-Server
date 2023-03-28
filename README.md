# Sticky Paws Server

This repository contains the server-side code for the game [Sticky Paws DX](https://github.com/Jonnil/Sticky-Paws-DX). The server is written in Python and provides API endpoints for uploading, listing, and downloading custom levels.

## API Endpoints

- `/upload`: Upload a custom level created by a user. The request should contain base64-encoded level data.
- `/levels`: List all the custom levels available for download. This endpoint returns available custom levels.
- `/download`: Download a specific custom level. The request should include the level ID as a parameter.

## License

This project is licensed under the [Apache 2.0](./LICENSE) License.
