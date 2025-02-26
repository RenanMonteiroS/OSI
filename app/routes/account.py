from flask import Blueprint, request, current_app
from ..model.user import User
from ..extensions import limiter
from ..util.checkPermissions import isAdmin, isOwnOrAdmin
from ..util.sendEmail import sendActivationEmail
from ..model.responseException import ResponseException
import bcrypt, re, os

account_bp = Blueprint('account', __name__)

@account_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def postRegister():
        from random import SystemRandom
        from string import ascii_uppercase, digits
        from base64 import b32encode
        from pyotp import TOTP
        from qrcode import make
        from uuid import uuid4
        from os import remove
        from email.mime.text import MIMEText
        from email.mime.image import MIMEImage
        from email.mime.multipart import MIMEMultipart
        from smtplib import SMTP
        from secrets import token_urlsafe

        if not "name" in request.json or not "email" in request.json or not "password" in request.json:
            raise ResponseException("'name'/'email'/'password' expected", 400)

        name = request.json["name"]
        email = request.json["email"]
        password = request.json["password"]

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ResponseException("E-mail is not valid", 400)

        if len(password) <= 5:
            raise ResponseException("Password too short", 400)
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+$', password):
            raise ResponseException("Password does not correspond to the  set of required characters (special, uppercase, lowercase and number)", 400)

        if User.objects(email=email):
            raise ResponseException(msg=f"User with e-mail: {email} already exists", statusCode=400)

        
        salt =  bcrypt.gensalt(rounds=14)
        hashedPassword =  bcrypt.hashpw(str.encode(password), salt)
        hashedPassword = hashedPassword.decode()
            
        
        mfaSecret = ''.join(SystemRandom().choice(ascii_uppercase + digits) for _ in range(16))
        totp = TOTP(b32encode(str.encode(mfaSecret)))
        
        qrcodeFullPathName = os.path.join(current_app.config["ROOT_PATH"], "templates", "static", "images", f"qrcode-{uuid4()}.png")
        img = make(totp.provisioning_uri(name=email, issuer_name=f'{current_app.config['COMPANY_NAME']} OSI'))
        img.save(qrcodeFullPathName)
        
        createdUser = User(name=name, email=email, password=hashedPassword, activationToken=token_urlsafe(), mfaSecret=mfaSecret).save()
        current_app.logger.info(f"User {createdUser.id} created.")

        
        template = current_app.config["TEMPLATE_ENV"].get_template('emailTemplate.html')
        html = template.render(userName=createdUser.name, activationLink=f"http://{request.host}/activate?token={createdUser.activationToken}", 
                            companyName=current_app.config['COMPANY_NAME'], companyWebsite=current_app.config['COMPANY_WEBSITE'])

        message = MIMEMultipart("alternative")
        message['Subject'] = "Conclua a ativação da sua conta da OSI"
        part = MIMEText(html, 'html')
        message.attach(part)

        fp = open(os.path.join(current_app.config["ROOT_PATH"], "templates", "static", "images", "logo.png"), "rb")
        image1 = MIMEImage(fp.read())
        fp.close()
        image1.add_header('Content-ID', '<logo>')
        message.attach(image1)
        fp = open(qrcodeFullPathName, 'rb')
        image2 = MIMEImage(fp.read())
        fp.close()
        image2.add_header('Content-ID', '<qrCode>')
        message.attach(image2)
        fp = open(os.path.join(current_app.config["ROOT_PATH"], "templates", "static", "images", "emailActivationIllustration.png"), "rb")
        image3 = MIMEImage(fp.read())
        fp.close()
        image3.add_header('Content-ID', '<emailActivationIllustration>')
        message.attach(image3)
        server = SMTP(current_app.config['SMTP_SERVER'], int(current_app.config['SMTP_PORT']))
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(current_app.config['SMTP_USER'], current_app.config['SMTP_PASSWORD'])
        server.sendmail(current_app.config['SMTP_EMAILSENDER'], createdUser.email, message.as_string())
        server.quit()

        current_app.logger.info(f"Activation e-mail sended.")

        remove(qrcodeFullPathName)

        return {"msg": f"User created: {createdUser.id}", "status": "success"}, 201

@account_bp.route("/activate", methods=["GET"])
def getActivate():
    token = request.args.get('token')
    if not User.objects(activationToken=token):
        raise ResponseException(f"Invalid token", 400)
    
    for user in User.objects(activationToken=token):
        user.update(status = 'active', activationToken = None)
        current_app.logger.info(f"User {str(user.id)} activated.")
    
    return {"msg": f"User {user.id} updated (inactive - active)", "status": "success"}, 200

@account_bp.route("/account/create", methods=["POST"])
@isAdmin
def postCreateAccount():
        from random import SystemRandom
        from string import ascii_uppercase, digits
        from base64 import b32encode
        from pyotp import TOTP
        from qrcode import make
        from uuid import uuid4
        from os import remove

        from secrets import token_urlsafe

        if not "name" in request.json or not "email" in request.json or not "password" in request.json:
            raise ResponseException("'name'/'email'/'password' expected", 400)

        name = request.json["name"]
        email = request.json["email"]
        password = request.json["password"]

        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            raise ResponseException("E-mail is not valid", 400)

        if len(password) <= 5:
            raise ResponseException("Password too short", 400)
        if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+$', password):
            raise ResponseException("Password does not correspond to the  set of required characters (special, uppercase, lowercase and number)", 400)

        if User.objects(email=email):
            raise ResponseException(msg=f"User with e-mail: {email} already exists", statusCode=400)

        
        salt =  bcrypt.gensalt(rounds=14)
        hashedPassword =  bcrypt.hashpw(str.encode(password), salt)
        hashedPassword = hashedPassword.decode()
            
        
        mfaSecret = ''.join(SystemRandom().choice(ascii_uppercase + digits) for _ in range(16))
        totp = TOTP(b32encode(str.encode(mfaSecret)))
        
        qrcodeFullPathName = os.path.join(current_app.config["ROOT_PATH"], "templates", "static", "images", f"qrcode-{uuid4()}.png")
        img = make(totp.provisioning_uri(name=email, issuer_name=f'{current_app.config['COMPANY_NAME']} OSI'))
        img.save(qrcodeFullPathName)
        
        createdUser = User(name=name, email=email, password=hashedPassword, activationToken=token_urlsafe(), mfaSecret=mfaSecret).save()
        current_app.logger.info(f"User {createdUser.id} created.")

        sendActivationEmail(createdUser, qrcodeFullPathName)        

        remove(qrcodeFullPathName)

        return {"msg": f"User created: {createdUser.id}", "status": "success"}, 201

@account_bp.route("/account/<string:userId>", methods=["PATCH"])
@isOwnOrAdmin
def patchUpdateAccount(userId, reqUser):
    user = User.objects(id=userId).first()
    reqUser = User.objects(id=reqUser["userId"]).first()

    if not user:
        raise ResponseException("This user does not exist.", 400)

    for dataKey in request.json:
        if dataKey == 'email' and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', request.json[dataKey]):
            raise ResponseException("E-mail is not valid", 400)
        if dataKey == 'email' and User.objects(email=request.json[dataKey]):
                raise ResponseException("An user with this e-mail already exists", 400)
        elif dataKey == 'password':
            if len(request.json["password"]) <= 5:
                raise ResponseException("Password too short", 400)
            if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+$', request.json["password"]):
                raise ResponseException("Password does not correspond to the  set of required characters (special, uppercase, lowercase and number)", 400)
            else:
                salt =  bcrypt.gensalt(rounds=14)
                hashedPassword =  bcrypt.hashpw(str.encode(request.json[dataKey]), salt)
                hashedPassword = hashedPassword.decode()
                setattr(user, dataKey, hashedPassword)
        elif dataKey == 'status' and reqUser["role"] != 'admin':
            raise ResponseException("You are not allowed to change the status", 401)
        elif dataKey == 'status' and reqUser["role"] == 'admin':
            setattr(user, dataKey, request.json[dataKey])
            setattr(user, "activationToken", None)
        elif dataKey == 'role' and reqUser["role"] != 'admin':
            raise ResponseException("You are not allowed to change the status", 401)
        elif dataKey == 'activationToken' or dataKey == 'mfaSecret':
            raise ResponseException("You are not allowed to change the status", 401)
        else:
            setattr(user, dataKey, request.json[dataKey])

    user.save()

    current_app.logger.info(f"User {userId} updated by user {reqUser.id}")

    return {"msg": f"User {userId} updated", "status": "success"}, 200

@account_bp.route("/account/<string:userId>", methods=["DELETE"])
@isOwnOrAdmin
def deleteDeleteAccount(userId, reqUser):
    if not User.objects(id=userId):
        raise ResponseException("Invalid user id", 400)

    user = User.objects(id=userId).first()
        
    user.delete()
    current_app.logger.info(f"User {userId} deleted by user {reqUser["userId"]}")

    return {"msg": f"User {userId} deleted", "status": "success"}, 200