from functools import wraps
from ..model.responseException import ResponseException
from ..model.user import User
from flask import current_app, request, make_response
from jwt.exceptions import DecodeError
import jwt, configparser, datetime

config = configparser.ConfigParser()
config.read('config.conf')


def isAuth(request):
    """Checks if the user is authenticated. Expects a Request object and returns a decoded JWT."""
    try:
        authorizationJwt = request.headers.get('Authorization')
        if not authorizationJwt:
            raise ResponseException('Not authenticated', 401)
        if not 'Bearer' in authorizationJwt:
            raise ResponseException('Not authenticated', 401)
        
        authorizationJwt = authorizationJwt.split(' ')[1]

        if current_app.config['JWT_ALGORITHM'] == 'HS256':
            JWT_SECRET = current_app.config['JWT_SECRET']
            decodedJwt = (jwt.decode(authorizationJwt, JWT_SECRET, algorithms=current_app.config['JWT_ALGORITHM']))
        elif current_app.config['JWT_ALGORITHM'] == 'RS256':
            with open(current_app.config['JWT_PUBLIC_KEY_PATH'], 'r') as f:
                PUBLIC_KEY = f.read()
            decodedJwt = (jwt.decode(authorizationJwt, PUBLIC_KEY, algorithms=current_app.config['JWT_ALGORITHM']))
        else:
            raise ResponseException("Invalid JWT encryption method", 400)

        if not User.objects(id=decodedJwt["userId"]) or not User.objects(email=decodedJwt["userEmail"]):
            raise ResponseException("This JWT has not a user associated with. Please try again with a valid user", 400)
   
        if datetime.datetime.now() > datetime.datetime.strptime(decodedJwt["tokenExpiration"], '%Y-%m-%d %H:%M:%S.%f'):
            raise ResponseException("JWT expired. Please login again", 401)
        
        return decodedJwt
        
    except DecodeError as e:
        raise ResponseException(f"Error decoding JWT: {e}", 401)

    except Exception as e:
        raise ResponseException(str(e), 500)


def isOwnOrAdmin(func):
    """Decorator which checks if the user is an administrator or itself. Implements isAuth function"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            decodedJwt = isAuth(request)
            
            reqUserId = decodedJwt["userId"]
            reqUser = None

            for user in User.objects(id=reqUserId):
                reqUser = user

            if str(kwargs["userId"]) != reqUserId and reqUser.role != 'admin':
                return make_response({"msg": "You are not allowed to do this operation", "status": "Unauthorized"}, 401)
            kwargs["reqUser"] = decodedJwt
            return func(*args, **kwargs)
        except ResponseException as e:
            return make_response(e.getErrorData(), e.statusCode)

        except Exception as e:
            return make_response({"msg": e}, 500)
        
    return wrapper

def isAdmin(func):
    """Decorator which checks if the user is an administrator. Implements isAuth function"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            decodedJwt = isAuth(request)
            
            reqUserId = decodedJwt["userId"]
            reqUser = None

            for user in User.objects(id=reqUserId):
                reqUser = user

            if reqUser.role != 'admin':
                raise ResponseException("You are not allowed to do this operation", 401)
                
            return func(*args, **kwargs)
        
        except ResponseException as e:
            return make_response(e.getErrorData(), e.statusCode)
        except Exception as e:
            return make_response({"msg": e}, 500)

    return wrapper
