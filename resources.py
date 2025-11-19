from flask import make_response
from bson.objectid import ObjectId
from db import get_db_file
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_routes():
    """
    Get routes for resource serving.
    
    Returns:
        List of route tuples
    """
    return [('/api/files/<file_id>', 'serve_file', serve_file, ['GET'])]

def serve_file(file_id):
    """
    Serve a file from GridFS by its ID.
    
    Args:
        file_id: ObjectId of the file to serve
        
    Returns:
        HTTP response with file content and appropriate headers
    """
    try:
        file = get_db_file('read').get(ObjectId(file_id))
        response = make_response(file.read())
        
        # Security headers for file serving
        response.headers['Content-Disposition'] = 'inline'
        response.headers['Content-Type'] = file.content_type
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        return response
    except Exception as e:
        logger.error(f"Error serving file {file_id}: {str(e)}")
        return "File not found", 404