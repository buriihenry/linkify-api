from flask import Blueprint, request
import validators
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask.json import jsonify
from src.constants.http_status_code import HTTP_400_BAD_REQUEST, HTTP_409_CONFLICT, HTTP_201_CREATED, HTTP_200_OK
from src.database import Bookmark, db

bookmarks = Blueprint("bookmarks", __name__, url_prefix="/api/v1/bookmarks")

@bookmarks.route('/', methods=['POST', 'GET'])
@jwt_required()  # Make sure this is correctly placed
def handle_bookmarks():
    current_user = get_jwt_identity()
    
    if request.method == 'POST':
        body = request.get_json().get('body', '')
        url = request.get_json().get('url', '')  # Fix: changed from 'body' to 'url'
        
        if not validators.url(url):
            return jsonify({
                'error':'Enter a valid URL'
            }), HTTP_400_BAD_REQUEST
        
        if Bookmark.query.filter_by(url=url).first():
            return jsonify({
                'error':'URL already exists'
            }), HTTP_409_CONFLICT
        
        bookmark = Bookmark(url=url, body=body, user_id=current_user)
        db.session.add(bookmark)
        db.session.commit()
        
        return jsonify({
            'id':bookmark.id,
            'url': bookmark.url,
            'short_url':bookmark.short_url,
            'visit':bookmark.visits,
            'body': bookmark.body,
            'created_at': bookmark.created_at,
            'updated_at':bookmark.updated_at,
        }), HTTP_201_CREATED
    
    else:  # GET method
        bookmarks = Bookmark.query.filter_by(user_id=current_user)
        data = []
        
        for bookmark in bookmarks:
            data.append({
                'id':bookmark.id,
                'url': bookmark.url,
                'short_url':bookmark.short_url,
                'visit':bookmark.visits,
                'body': bookmark.body,
                'created_at': bookmark.created_at,
                'updated_at':bookmark.updated_at,
            })
        
        return jsonify({'data':data}), HTTP_200_OK