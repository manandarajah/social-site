from bson.objectid import ObjectId
from flask import Blueprint, jsonify, redirect, request
from werkzeug.routing import IntegerConverter
from accounts import get_profile
from flask_login import login_required, current_user
from datetime import datetime, timezone
from security_config import regenerate_session
from regexes import POST_REGEX, TEXT_REGEX
from app_tasks import is_direct_call, upload_file, validate_sanitize
from db import get_db_file, get_db_posts
import base64

posts_bp = Blueprint('posts', __name__)
context = None

def config_app(app):
    global context
    context = app

def get_routes():
    return [
        ('/create-post', 'create_post', create_post, ['POST']),
        ('/update-post', 'update_post', update_post, ['POST']),
        ('/delete-post', 'delete_post', delete_post, ['POST']),
        ('/comment-post', 'comment_on_post', comment_on_post, ['POST']),
        ('/update-comment', 'update_comment', update_comment, ['POST']),
        ('/delete-comment', 'delete_comment', delete_comment, ['POST']),
        ('/api/posts', 'get_posts', get_posts, ['POST']),
        ('/api/posts/<string:username>', 'get_posts', get_posts, ['POST'])
    ]

@login_required
def create_post():

    if is_direct_call():
        return jsonify({'error': 'Direct calls are not allowed. Access denied!'}), 400

    data = request.form
    token = data.get('csrf_token')
    profile_picture = data.get('profile_picture','').strip()
    content = data.get('content', '').strip()
    attachment = request.files['attachment'] if request.files['attachment'] else None

    # Only require content (text) for a post; photo/video is optional
    if not content:
        return jsonify({'error': 'Post content is required'}), 400

    if not validate_sanitize(content, POST_REGEX):
        return jsonify({'error': 'Invalid data'}), 400

    content = base64.b64encode(content.encode('utf-8'))

    attachment_id = None

    try:
        # Handle file upload if attachment is present
        if attachment and attachment.filename:
            attachment_id = upload_file(attachment)

        post = {
            'username': current_user.id,
            'content': content,
            'attachment': attachment_id,
            'created_at': datetime.now(timezone.utc),
            'likes': [],
            'comments': []
        }

        inserted_post = get_db_posts('write').insert_one(post)
    except Exception as e:
        print(f"Error creating post: {e}")
        return jsonify({'error': 'Failed to create post'}), 500
        
    print("Posted successfully!")

    regenerate_session(context)
    return redirect('/')

@login_required
def update_post():

    if is_direct_call():
        return jsonify({'error': 'Direct calls are not allowed. Access denied!'}), 400

    data = request.form
    token = data.get('csrf_token')
    post_id = ObjectId(data.get('id'))
    content = data.get('content', '').strip()

    if not post_id:
        return jsonify({'error': 'Post ID is required'}), 400

    # post = get_db_posts('read').find_one({'_id': post_id})
    # if not post:
    #     return jsonify({'error': 'Post not found'}), 404

    # Only allow the owner to update their post
    # if post.get('username') != session['username']:
    #     return jsonify({'error': 'Forbidden'}), 403

    update_fields = {}
    if content and validate_sanitize(content, POST_REGEX):
        update_fields['content'] = base64.b64encode(content.encode('utf-8'))

    if not update_fields:
        return jsonify({'error': 'No update fields provided'}), 400

    result = get_db_posts('write').update_one({'_id': {"$eq": post_id}, 'username': {"$eq": current_user.id}}, {'$set': update_fields})

    if result.matched_count == 0:
        # Either post doesn't exist or user doesn't own it
        return jsonify({'error': 'Post not found or forbidden'}), 403

    regenerate_session(context)
    return redirect('/')

@login_required
def delete_post():
    if is_direct_call():
        return jsonify({'error': 'Direct calls are not allowed. Access denied!'}), 400

    data = request.form
    post_id = ObjectId(data.get('id'))
    attachment_id = ObjectId(data.get('attachment_id')) if data.get("attachment_id") != "None" else None
    token = data.get('csrf_token')
    if not post_id:
        return jsonify({'error': 'Post ID is required'}), 400

    try:
        post = get_db_posts('read').find_one({'_id': {"$eq": post_id}, 'username': {"$eq": current_user.id}})

        if not post:
            return jsonify({'error': 'Post not found or forbidden'}), 403

        result = get_db_file('write').delete(attachment_id)

        # Only allow the owner to delete their post
        result = get_db_posts('write').delete_one({'_id': {"$eq": post_id}, 'username': {"$eq": current_user.id}})

        if result.deleted_count == 0:
            return jsonify({'error': 'Post not found or forbidden'}), 403
    except Exception as e:
        return jsonify({'error': f'Error while deleting post: {str(e)}'}), 500

    regenerate_session(context)
    return redirect('/')

@login_required
def comment_on_post():
    """
    Endpoint to comment on a post.
    Expects form data: post_id, content, csrf_token
    """
    if is_direct_call():
        return jsonify({'error': 'Direct calls are not allowed. Access denied!'}), 400

    post_id_str = request.form.get('id')
    content = request.form.get('content')
    token = request.form.get('csrf_token')
    
    if not post_id_str or not content:
        return jsonify({'error': 'Post ID and content are required.'}), 400

    try:
        post_id = ObjectId(post_id_str)
    except Exception:
        return jsonify({'error': 'Invalid post ID.'}), 400

    # Assume there's a regex POST_REGEX, and validate_sanitize
    if not validate_sanitize(content, POST_REGEX):
        return jsonify({'error': 'Invalid comment content.'}), 400

    comment = {
        'username': current_user.id,
        'content': base64.b64encode(content.encode('utf-8')),
        'created_at': datetime.now(timezone.utc)
    }

    # Attach the comment to the post in db
    result = get_db_posts('write').update_one(
        {'_id': {"$eq": post_id}},
        {'$push': {'comments': comment}}
    )

    if result.matched_count == 0:
        return jsonify({'error': 'Post not found or forbidden'}), 403

    regenerate_session(context)
    return redirect('/')

@login_required
def update_comment():
    """
    Endpoint to update a comment's content.
    Expects form data: id (comment id), content, csrf_token
    """
    if is_direct_call():
        return jsonify({'error': 'Direct calls are not allowed. Access denied!'}), 400

    post_id_str = request.form.get('post_id')
    comment_id = request.form.get('comment_id')
    content = request.form.get('content')
    token = request.form.get('csrf_token')

    if not post_id_str or not comment_id or not content:
        return jsonify({'error': 'Post ID, Comment ID and content are required.'}), 400

    try:
        post_id = ObjectId(post_id_str)
    except Exception:
        return jsonify({'error': 'Invalid post ID.'}), 400

    # Assume POST_REGEX and validate_sanitize are available for content validation
    if not validate_sanitize(content, POST_REGEX):
        return jsonify({'error': 'Invalid comment content.'}), 400

    posts_db = get_db_posts('write')

    # Update the comment document in the array by user id
    try:
        # Only allow updating the user's own comment (match on username)
        result = posts_db.update_one(
            {
                '_id': {"$eq": post_id},
                'comments.'+comment_id+'.username': current_user.id
            },
            {
                '$set': {
                    'comments.'+comment_id+'.content': base64.b64encode(content.encode('utf-8'))
                }
            }
        )

        if result.matched_count == 0:
            return jsonify({'error': 'Comment not found or forbidden'}), 403

    except Exception as e:
        return jsonify({'error': f'Error updating comment: {str(e)}'}), 500

    regenerate_session(context)
    return redirect('/')

@login_required
def delete_comment():
    """
    Endpoint to delete a comment from a post.
    Expects form data: post_id, comment_index, csrf_token
    Only the comment's owner can delete their own comment.
    """
    if is_direct_call():
        return jsonify({'error': 'Direct calls are not allowed. Access denied!'}), 400

    post_id_str = request.form.get('post_id')
    comment_index_str = request.form.get('comment_index')
    token = request.form.get('csrf_token')

    if not post_id_str or comment_index_str is None:
        return jsonify({'error': 'Post ID and comment index are required.'}), 400

    try:
        post_id = ObjectId(post_id_str)
        comment_index = int(comment_index_str)
    except Exception:
        return jsonify({'error': 'Invalid post ID or comment index.'}), 400

    posts_db = get_db_posts('write')

    # Remove the comment from the comments array
    try:
        posts_db.update_one(
            {'_id': {'$eq': post_id}, f'comments.{comment_index}.username': {'$eq': current_user.id}},
            {'$unset': {f'comments.{comment_index}': 1}}
        )
        posts_db.update_one(
            {'_id': {'$eq': post_id}},
            {'$pull': {'comments': None}}
        )
    except Exception as e:
        return jsonify({'error': f'Error deleting comment: {str(e)}'}), 500

    regenerate_session(context)
    return redirect('/')

@login_required
def get_posts(username=None):

    if is_direct_call():
        return jsonify({'error': 'Direct calls are not allowed. Access denied!'}), 400

    posts_db = get_db_posts('read')
    posts = posts_db.find().sort('created_at', -1) if not username else posts_db.find({
        '$or': [
            {'username': {"$eq": username}}, 
            {'comments': {'$elemMatch': {'username': {'$eq': username}}}}
        ]}).sort('created_at', -1)
    posts = list(posts)
    comments = []
    
    for i, post in enumerate(posts):
        post['_id'] = str(post['_id'])
        post['created_at'] = post['created_at'].replace(tzinfo=timezone.utc).isoformat()
        post['attachment_id'] = str(post['attachment'])
        post['attachment'] = '/api/files/'+str(post['attachment']) if post['attachment'] is not None else post['attachment']
        comments.extend([(i, comment) for comment in post['comments']])

        profile = get_profile(post['username'])
        post['first_name'] = profile['first_name']
        post['last_name'] = profile['last_name']
        post['profile_picture'] = profile['profile_picture']
        post['content'] = post['content'].decode('utf-8')

    for i, (idx, comment) in enumerate(comments):
        profile = get_profile(comment['username'])
        comment['first_name'] = profile['first_name']
        comment['last_name'] = profile['last_name']
        comment['profile_picture'] = profile['profile_picture']
        comment['content'] = comment['content'].decode('utf-8')

        if i in posts[idx]['comments']:
            posts[idx]['comments'][i] = comment

    return jsonify({'posts': posts})