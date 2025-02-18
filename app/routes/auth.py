from flask import Blueprint, request, current_app
from ..model.user import User
from ..util.checkPermissions import isAuth
#from util.auth_utils import isAuth, isAdmin, isOwnOrAdmin
#from util.email_utils import send_activation_email
from ..model.responseException import ResponseException
import bcrypt, pyotp, jwt, datetime

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/login", methods=["POST"])
def postLogin():
    from base64 import b32encode

    email = request.json["email"]
    password = request.json["password"]
    mfaKey = request.json["mfaKey"]
        
    for user in User.objects(email=email):
        if not pyotp.TOTP(b32encode(str.encode(user.mfaSecret))).now() == mfaKey:
            raise ResponseException(f"Wrong TOTP value", 401)

        if not bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            raise ResponseException("Wrong Password", 401)

        if not user.status == 'active':
            raise ResponseException(f"User id:{user.id} is not active", 401)
           
        tokenExpiration = datetime.timedelta(minutes=30) + datetime.datetime.now() 

        payload = {
           "userEmail": user.email,
            "userId": str(user.id),
            "tokenExpiration": str(tokenExpiration)
        }
            
        if current_app.config['JWT_ALGORITHM'] == 'HS256':
            JWT_SECRET = current_app.config['JWT_SECRET']
            jwtToken = jwt.encode(payload=payload, key=JWT_SECRET, algorithm=current_app.config['JWT_ALGORITHM'])
        elif current_app.config['JWT_ALGORITHM'] == 'RS256':
            with open(current_app.config['JWT_PRIVATE_KEY_PATH'], 'r') as f:
                PRIVATE_KEY = f.read()
            
            jwtToken = jwt.encode(payload=payload, key=PRIVATE_KEY, algorithm=current_app.config['JWT_ALGORITHM'])
        else:
            raise ResponseException("Invalid JWT encryption method", 400)
            
        current_app.logger.info(f"User {str(user.id)} logged in.")
                     
        return {"msg": f"Login of user {str(user.id)} done", "status": "success", "JWT": f"{jwtToken}"}, 200 

@auth_bp.route("/isValid", methods=["GET"])
def isValid():
    decodedJwt = isAuth(request)
    if not decodedJwt: 
        raise ResponseException("Cannot decode JWT", 400)
        
    return {"msg": f"JWT is valid", "status": "success"}, 200