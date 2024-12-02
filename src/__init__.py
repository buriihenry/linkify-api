from flask.json import jsonify
from src.constants.http_status_code import HTTP_404_NOT_FOUND, HTTP_500_INTERNAL_SERVER_ERROR
from flask import Flask, config, redirect
import os
from src.auth import auth
from src.bookmarks import bookmarks
from src.database import db, Bookmark
from flask_jwt_extended import JWTManager
from flasgger import Swagger, swag_from
from src.config.swagger import template, swagger_config

def create_app(test_config=None):
    print("Creating Flask app")  # Debugging statement
    app = Flask(__name__, instance_relative_config=True)

    if test_config is None:
        app.config.from_mapping(
            SECRET_KEY=os.environ.get("SECRET_KEY"),
            SQLALCHEMY_DATABASE_URI=os.environ.get("SQLALCHEMY_DATABASE_URI"),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY'),
            SWAGGER={
                'title': "Bookmarks API",
                'uiversion': 3
            }
        )
    else:
        app.config.from_mapping(test_config)

    print("Initializing database")  # Debugging statement
    db.app = app
    db.init_app(app)

    print("Initializing JWTManager")  # Debugging statement
    JWTManager(app)

    print("Registering blueprints")  # Debugging statement
    app.register_blueprint(auth)
    app.register_blueprint(bookmarks)

    print("Configuring Swagger")  # Debugging statement
    Swagger(app, config=swagger_config, template=template)

    @app.get('/<short_url>')
    @swag_from('./docs/bookmarks/short_url.yaml')
    def redirect_to_url(short_url):
        print("Endpoint loaded with short_url.yaml")
        bookmark = Bookmark.query.filter_by(short_url=short_url).first_or_404()
        print(f"Bookmark: {bookmark}")  # Debugging statement

        if bookmark:
            bookmark.visits = bookmark.visits + 1
            db.session.commit()
            return redirect(bookmark.url)
        else:
            return jsonify({'error': 'Bookmark not found'}), HTTP_404_NOT_FOUND

    @app.errorhandler(HTTP_404_NOT_FOUND)
    def handle_404(e):
        print("Handling 404 error")  # Debugging statement
        return jsonify({'error': 'Not found'}), HTTP_404_NOT_FOUND

    @app.errorhandler(HTTP_500_INTERNAL_SERVER_ERROR)
    def handle_500(e):
        print("Handling 500 error")  # Debugging statement
        return jsonify({'error': 'Something went wrong, we are working on it'}), HTTP_500_INTERNAL_SERVER_ERROR

    print("Flask app created")  # Debugging statement
    return app
