from pymongo import MongoClient
from pymongo.write_concern import WriteConcern
from gridfs import GridFS
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Connect to MongoDB and return database
db = None

def init_db():
    """
    Initialize MongoDB connection and create necessary indexes.
    Should be called once at application startup.
    """
    global db
    mongodb_uri = os.environ.get('MONGODB_URI')
    if not mongodb_uri:
        raise ValueError("MONGODB_URI environment variable is required")
    
    db = MongoClient(mongodb_uri, tls=True)['socialbook']
    db['users'].create_index('username', unique=True)
    db['posts'].create_index('_id')
    logger.info("Database initialized successfully")

def get_db_users(operation):
    """
    Get users collection with appropriate write concern.
    
    Args:
        operation: 'read' for read operations, 'write' for write operations
        
    Returns:
        MongoDB users collection
    """
    return db['users'] if operation == "read" else db['users'].with_options(write_concern=WriteConcern(w=1, j=True))

def get_db_posts(operation):
    """
    Get posts collection with appropriate write concern.
    
    Args:
        operation: 'read' for read operations, 'write' for write operations
        
    Returns:
        MongoDB posts collection
    """
    return db['posts'] if operation == "read" else db['posts'].with_options(write_concern=WriteConcern(w=1, j=True))

def get_db_file(operation):
    """
    Get GridFS file storage with appropriate write concern.
    
    Args:
        operation: 'read' for read operations, 'write' for write operations
        
    Returns:
        GridFS instance
    """
    return GridFS(db) if operation == "read" else GridFS(db.with_options(write_concern=WriteConcern(w=1, j=True)))