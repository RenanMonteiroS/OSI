import logging
from flask import Flask, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from model.user import User
from model.responseException import ResponseException
from mongoengine import connect
from secrets import token_urlsafe
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from cryptography.hazmat.primitives import serialization
from base64 import b32encode
from jinja2 import Environment, FileSystemLoader, select_autoescape
from uuid import uuid4
from os import remove
from util.checkPermissions import isAuth, isOwnOrAdmin
import bcrypt, smtplib, jwt, pyotp, random, string, qrcode, configparser, datetime, re

app = Flask(__name__)
CORS(app, allow_headers=["Content-Type", "Authorization", "Accept-Language"], 
     methods=["GET", "POST", "PATCH", "DELETE"],
     origins="*",
    )
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["20 per hour"],
)

config = configparser.ConfigParser()
config.read('config.conf')

logger = logging.getLogger(__name__)

MONGODB_URI = config['DATABASE']['MONGODB_URI']
JWT_SECRET = config['JWT']['JWT_SECRET']

@app.errorhandler(ResponseException)
def ResponseExceptionError(e):
    logger.exception(e)
    return e.getErrorData(), e.statusCode

@app.errorhandler(Exception)
def genericError(e):
    logger.exception(e)
    msg = {}
    for x in e.__dict__:
        msg[x] = str(e.__dict__[x])
    msg["status"] = "error"
    return msg, 500

@app.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def postRegister():
    
        if not "name" in request.json or not "email" in request.json or not "password" in request.json:
            raise ResponseException("'name'/'email'/'password' expected", 400)

        name = request.json["name"]
        email = request.json["email"]
        password = request.json["password"]

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ResponseException("E-mail is not valid", 400)

        if len(password) <= 5:
            raise ResponseException("Password too short", 400)

        if User.objects(email=email):
            raise ResponseException(msg=f"User with e-mail: {email} already exists", statusCode=400)

        
        salt =  bcrypt.gensalt(rounds=14)
        hashedPassword =  bcrypt.hashpw(str.encode(password), salt)
        hashedPassword = hashedPassword.decode()
            
        
        mfaSecret = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(16))
        totp = pyotp.TOTP(b32encode(str.encode(mfaSecret)))
        
        qrcodeFullPathName = f'./templates/static/images/qrcode-{uuid4()}.png'
        img = qrcode.make(totp.provisioning_uri(name=email, issuer_name=f'{config['COMPANY_INFO']['COMPANY_NAME']} OSI'))
        img.save(qrcodeFullPathName)
        
        createdUser = User(name=name, email=email, password=hashedPassword, activationToken=token_urlsafe(), mfaSecret=mfaSecret).save()
        logger.info(f"User {createdUser.id} created.")

        env = Environment(
            loader=FileSystemLoader('./templates/'),
            autoescape=select_autoescape(['html', 'xml'])
        )
        template = env.get_template('emailTemplate.html')
        html = template.render(userName=createdUser.name, activationLink=f"http://{request.host}/activate?token={createdUser.activationToken}", 
                            companyName=config['COMPANY_INFO']['COMPANY_NAME'], companyWebsite=config['COMPANY_INFO']['COMPANY_WEBSITE'])

        message = MIMEMultipart("alternative")
        message['Subject'] = "Conclua a ativação da sua conta da OSI"
        part = MIMEText(html, 'html')
        message.attach(part)
        
        fp = open('./templates/static/images/logo.png', 'rb')
        image1 = MIMEImage(fp.read())
        fp.close()
        image1.add_header('Content-ID', '<logo>')
        message.attach(image1)
        fp = open(qrcodeFullPathName, 'rb')
        image2 = MIMEImage(fp.read())
        fp.close()
        image2.add_header('Content-ID', '<qrCode>')
        message.attach(image2)
        fp = open('./templates/static/images/emailActivationIllustration.png', 'rb')
        image3 = MIMEImage(fp.read())
        fp.close()
        image3.add_header('Content-ID', '<emailActivationIllustration>')
        message.attach(image3)
        server = smtplib.SMTP(config['SMTP']['SMTP_SERVER'], int(config['SMTP']['SMTP_PORT']))
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(config['SMTP']['SMTP_USER'], config['SMTP']['SMTP_PASSWORD'])
        server.sendmail(config['SMTP']['SMTP_EMAILSENDER'], createdUser.email, message.as_string())
        server.quit()

        logger.info(f"Activation e-mail sended.")

        remove(qrcodeFullPathName)

        return {"msg": f"User created: {createdUser.id}", "status": "success"}, 201
        

@app.route("/activate", methods=["GET"])
def getActivate():
    token = request.args.get('token')
    if not User.objects(activationToken=token):
        raise ResponseException(f"Invalid token", 400)
    
    for user in User.objects(activationToken=token):
        user.update(status = 'active', activationToken = None)
        logger.info(f"User {str(user.id)} activated.")
    
    return {"msg": f"User {user.id} updated (inactive - active)", "status": "success"}, 200
    
@app.route("/login", methods=["POST"])
def postLogin():
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
            
        if not config['JWT']['JWT_ALGORITHM']:
            JWT_ALGORITHM = 'HS256'
            jwtToken = jwt.encode(payload=payload, key=JWT_SECRET, algorithm=JWT_ALGORITHM)
        else:
            JWT_ALGORITHM = config['JWT']['JWT_ALGORITHM']
            
            with open(config['JWT']['JWT_PRIVATE_KEY_PATH'], 'r') as f:
                private_key = f.read()

            jwtToken = jwt.encode(payload=payload, key=private_key, algorithm=JWT_ALGORITHM)
            
        logger.info(f"User {str(user.id)} logged in.")
                     
        return {"msg": f"Login of user {str(user.id)} done", "status": "success", "JWT": f"{jwtToken}"}, 200 

@app.route("/account/<string:userId>", methods=["PATCH"])
def patchUpdateAccount(userId):
    decodedJwt=isAuth(request)

    if not User.objects(id=userId):
        raise ResponseException("Invalid user id", 400)

    reqUser = isOwnOrAdmin(decodedJwt["userId"], userId)
        
    user = User.objects(id=userId).first()

    for dataKey in request.json:
        if dataKey == 'email':
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', request.json[dataKey]):
                raise ResponseException("E-mail is not valid", 400)
            if User.objects(email=request.json[dataKey]):
                    raise ResponseException("An user with this e-mail already exists", 400)
        elif dataKey == 'password' and len(request.json["password"]) <= 5:
            raise ResponseException("Password too short", 400)
        elif dataKey == 'status' and reqUser.role != 'admin':
            raise ResponseException("You are not allowed to change the status", 401)
        elif dataKey == 'role' and reqUser.role != 'admin':
            raise ResponseException("You are not allowed to change the status", 401)
        elif dataKey == 'activationToken' or dataKey == 'mfaSecret':
            raise ResponseException("You are not allowed to change the status", 401)
        else:
            setattr(user, dataKey, request.json[dataKey])
        
        user.save()
        logger.info(f"User {userId} updated by user {decodedJwt["userId"]}")

        return {"msg": f"User {userId} updated", "status": "success"}, 200

        
@app.route("/account/<string:userId>", methods=["DELETE"])
def deleteDeleteAccount(userId):
    decodedJwt=isAuth(request)
        
    isOwnOrAdmin(decodedJwt["userId"], userId)

    if not User.objects(id=userId):
        raise ResponseException("Invalid user id", 400)

    user = User.objects(id=userId).first()
        
    user.delete()
    logger.info(f"User {userId} deleted by user {decodedJwt["userId"]}")

    return {"msg": f"User {userId} deleted", "status": "success"}, 200

        
@app.route("/isValid", methods=["GET"])
def isValid():
    decodedJwt = isAuth(request)
    if not decodedJwt: 
        raise ResponseException("Cannot decode JWT", 400)
        
    return {"msg": f"JWT is valid", "status": "success"}, 200

if __name__ == "__main__":
    try:
        logger.setLevel(logging.DEBUG)
        log_levels = {
            logging.DEBUG: './logs/debug.log',
            logging.INFO: './logs/info.log',
            logging.WARNING: './logs/warning.log',
            logging.ERROR: './logs/error.log',
            logging.CRITICAL: './logs/critical.log',
        }

        for level, filename in log_levels.items():
            handler = logging.FileHandler(filename)
            handler.setLevel(level)  # Set the handler to only handle this level
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        connect(host=MONGODB_URI, maxPoolSize=50)
        logger.info(f"Database connected")
        app.run(port=8080, debug=True)
    except Exception as e:
        logger.critical(f"Error trying to connect to database: {e}")
        print(e)
