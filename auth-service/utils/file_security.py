import os

ALLOWED_MIME_TYPES = [
    "image/png",
    "image/jpeg",
    "application/pdf",
    "text/plain"
]

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_mime(file):
    return file.content_type in ALLOWED_MIME_TYPES

