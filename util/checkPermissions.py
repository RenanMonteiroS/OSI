from model.responseException import ResponseException
from model.user import User
import jwt, configparser, datetime

config = configparser.ConfigParser()
config.read('config.conf')
JWT_SECRET = config['JWT']['JWT_SECRET']

def isAuth(request, userId):
    authorizationJwt = request.headers.get('Authorization')
    if not authorizationJwt:
        raise ResponseException('Not authenticated', 401)
    if not 'Bearer' in authorizationJwt:
        raise ResponseException('Not authenticated', 401)
    if not User.objects(id=userId):
        raise ResponseException("Invalid user id", 400)
        
    authorizationJwt = authorizationJwt.split(' ')[1]
    decodedJwt = (jwt.decode(authorizationJwt, JWT_SECRET, algorithms="HS256"))

    if datetime.datetime.now() > datetime.datetime.strptime(decodedJwt["tokenExpiration"], '%Y-%m-%d %H:%M:%S.%f'):
        raise ResponseException("JWT expired. Please login again", 401)
        
    return decodedJwt

def isOwnOrAdmin(reqUserId, userId):
    reqUser = None
    for user in User.objects(id=reqUserId):
            reqUser = user

    if str(userId) != reqUserId and reqUser.role != 'admin':
        raise ResponseException("You are not allowed to do this operation", 400)
    else:
         return reqUser
        