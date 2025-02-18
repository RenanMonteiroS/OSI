from flask import Flask
from flask_cors import CORS
from flask_uploads import configure_uploads, IMAGES
from jinja2 import Environment, FileSystemLoader, select_autoescape
from logging.handlers import RotatingFileHandler
import logging
from .model.config import Config
from .model.responseException import ResponseException
from .extensions import images, initLimiter
from .routes.auth import auth_bp
from .routes.account import account_bp
from .routes.misc import misc_bp
import os

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    CORS(app, allow_headers=["Content-Type", "Authorization", "Accept-Language"], 
         methods=["GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"],
         origins="*")
    
    app.config["ROOT_PATH"] = os.path.dirname(os.path.abspath(__file__))

    app.config["TEMPLATE_ENV"] = Environment(
            loader=FileSystemLoader(os.path.join(app.config["ROOT_PATH"], "templates")),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    with app.app_context():
        initLimiter()

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    log_levels = {
        logging.DEBUG: './logs/debug.log',
        logging.INFO: './logs/info.log',
        logging.WARNING: './logs/warning.log',
        logging.ERROR: './logs/error.log',
        logging.CRITICAL: './logs/critical.log',
    }

    for level, filename in log_levels.items():
        handler = RotatingFileHandler(filename, maxBytes=200*1024*1024, backupCount=5)
        handler.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    app.config["LOGGER"] = logger

    # Configure file uploads
    app.config['UPLOADED_IMAGES_DEST'] = os.path.join('app', 'templates', 'static', 'images')
    app.config['UPLOADED_IMAGES_ALLOW'] = IMAGES
    configure_uploads(app, images)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(misc_bp)

    @app.errorhandler(ResponseException)
    def responseExceptionError(e):
        app.logger.exception(e)
        return e.getErrorData(), e.statusCode

    @app.errorhandler(Exception)
    def genericError(e):
        app.logger.exception(e)
        return {"msg": str(e), "status": "error"}, 500

    return app