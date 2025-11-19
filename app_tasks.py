from datetime import datetime
from flask import request, jsonify
from werkzeug.utils import secure_filename
from db import get_db_file
import os
import re
import bleach
import hmac
import hashlib
import magic
import uuid
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB

def allowed_file(filename):
    """
    Check if a filename has an allowed extension.
    
    Args:
        filename: Name of the file to check
        
    Returns:
        True if extension is allowed, False otherwise
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_file_type(file_data):
    """
    Validate file type by checking actual content, not just extension.
    
    Args:
        file_data: Binary file data to validate
        
    Returns:
        Tuple of (is_valid, mime_type)
    """
    mime = magic.from_buffer(file_data, mime=True)
    allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/quicktime']
    return mime in allowed_mimes, mime

def upload_file(file):
    """
    Upload and validate a file to GridFS storage.
    
    Args:
        file: File object to upload
        
    Returns:
        GridFS file ID on success, error message tuple on failure
    """
    # Validate size
    file.seek(0, os.SEEK_END)
    if file.tell() > MAX_FILE_SIZE:
        logger.warning(f"File upload rejected: size exceeds {MAX_FILE_SIZE} bytes")
        return 'File too large', 413
    file.seek(0)

    file_data = file.read()

    if len(file_data) == 0:
        return "Empty File"

    filename = secure_filename(file.filename)

    # Validate file extension
    if not allowed_file(filename):
        logger.warning(f"File upload rejected: invalid extension for {filename}")
        return "File type not allowed"

    unique_filename = f"{uuid.uuid4()}_{filename}"
    
    file_validated, detected_mime = validate_file_type(file_data)

    # Validate actual file type
    if not file_validated:
        logger.warning(f"File upload rejected: invalid MIME type {detected_mime}")
        return 'Invalid file type', 400

    logger.info(f"File uploaded: {filename} ({detected_mime})")
    return get_db_file('write').put(
                                    file_data,
                                    filename=filename,
                                    content_type=detected_mime,
                                    upload_date=datetime.utcnow()
                                )

def validate_sanitize_bulk(data_list, index):
    """
    Validate and sanitize multiple inputs at once.
    
    Args:
        data_list: List of dictionaries with 'input' and 'pattern' keys
        index: Key name for the input value in each dictionary
        
    Returns:
        True if all inputs are valid, False otherwise
    """
    for data in data_list:
        if data[index] is not None:
            if not validate_sanitize(data[index], data['pattern']):
                return False

    return True

def validate_sanitize(value, pattern):
    """
    Validate and sanitize user input against a regex pattern.
    
    Args:
        value: Input value to validate
        pattern: Regex pattern for validation
        
    Returns:
        True if valid and sanitized, False otherwise
    """
    return True if re.fullmatch(pattern, value) and bleach.clean(value) == value else False

def is_direct_call():
    """
    Check if the request is a direct call (no referer) or a referred call.
    
    Returns:
        True if direct call, False otherwise
    """
    return True if request.headers.get('Referer') is None else False