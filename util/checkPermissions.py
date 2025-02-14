from model.responseException import ResponseException
from model.user import User
import jwt, configparser, datetime

config = configparser.ConfigParser()
config.read('config.conf')
JWT_SECRET = config['JWT']['JWT_SECRET']

def isAuth(request):

    authorizationJwt = request.headers.get('Authorization')
    if not authorizationJwt:
        raise ResponseException('Not authenticated', 401)
    if not 'Bearer' in authorizationJwt:
        raise ResponseException('Not authenticated', 401)
        
    
    authorizationJwt = authorizationJwt.split(' ')[1]

    if not config['JWT']['JWT_ALGORITHM']:
        JWT_ALGORITHM = 'HS256'
        decodedJwt = (jwt.decode(authorizationJwt, JWT_SECRET, algorithms=JWT_ALGORITHM))
    else:
        JWT_ALGORITHM = config['JWT']['JWT_ALGORITHM']
            
        with open(config['JWT']['JWT_PUBLIC_KEY_PATH'], 'r') as f:
            public_key = f.read()

        JWT_ALGORITHM = config['JWT']['JWT_ALGORITHM']
        decodedJwt = (jwt.decode(authorizationJwt, public_key, algorithms=JWT_ALGORITHM))


    if not User.objects(id=decodedJwt["userId"]) or not User.objects(email=decodedJwt["userEmail"]):
         raise ResponseException("This JWT has not a user associated with. Please try again with a valid user", 400)

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
        