from flask import Blueprint, request, current_app
import os
from ..util.checkPermissions import isAdmin
from ..model.responseException import ResponseException

misc_bp = Blueprint('misc', __name__)


@misc_bp.route("/uploadLogo", methods=["PUT", "OPTIONS"])
@isAdmin
def uploadLogo():
    if 'file' not in request.files:
        return ResponseException("Any file was found. Please upload it", 400)
    
    file = request.files["file"]

    if file.filename == '':
        return ResponseException("File is empty", 400)

    filepath = os.path.join(current_app.config['UPLOADED_IMAGES_DEST'], 'logo.png')
    file.save(filepath)

    return {"msg": f"Logo uploaded at path {filepath}", "status": "success"}, 201