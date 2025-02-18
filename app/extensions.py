from flask import current_app
from flask_limiter import Limiter
from flask_uploads import UploadSet, IMAGES
from flask_limiter.util import get_remote_address

#limiter = Limiter(
#    get_remote_address,
#    app=server,
#    default_limits=["500 per hour"],
#    storage_uri=current_app.config["LIMITER_STORAGE_URL"],
#    strategy=current_app.config["LIMITER_STRATEGY"]
#)

limiter = Limiter(key_func=get_remote_address, 
                  default_limits=["500 per hour"])

def initLimiter():
    limiter.init_app(current_app)
    limiter._storage_uri = current_app.config["LIMITER_STORAGE_URL"]
    limiter._strategy = current_app.config["LIMITER_STRATEGY"]

images = UploadSet('images', IMAGES)