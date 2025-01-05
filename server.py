from flask import Flask, request
from flask_cors import CORS
from model.user import User
from model.responseException import ResponseException
from mongoengine import connect
from secrets import token_urlsafe
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from base64 import b32encode
from jinja2 import Environment, FileSystemLoader, select_autoescape
from uuid import uuid4
from os import remove
import bcrypt, smtplib, jwt, pyotp, random, string, qrcode, configparser, datetime

app = Flask(__name__)
CORS(app, allow_headers=["Content-Type", "Authorization", "Accept-Language"], 
     methods=["GET", "POST", "PATCH"],
     origins="*",
    )


config = configparser.ConfigParser()
config.read('config.conf')

MONGODB_URI = config['DATABASE']['MONGODB_URI']
JWT_SECRET = config['JWT']['JWT_SECRET']

@app.route("/register", methods=["POST"])
def postRegister():
    try:
        name = request.json["name"]
        email = request.json["email"]
        password = request.json["password"]

        if not "name" in request.json or not "email" in request.json or not "password" in request.json:
            raise ResponseException("'name'/'email'/'password' expected", 400)

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

        remove(qrcodeFullPathName)

        return {"msg": f"User created: {createdUser.id}", "status": "success"}, 201
    except ResponseException as e:
        return e.getErrorData(), e.statusCode
    except Exception as e:
        msg = {}
        for x in e.__dict__:
            msg[x] = str(e.__dict__[x])
        msg["status"] = "error"
        return msg, 500

@app.route("/activate", methods=["GET"])
def getActivate():
    try:
        token = request.args.get('token')
        if not User.objects(activationToken=token):
            raise ResponseException(f"Invalid token", 400)
    
        for user in User.objects(activationToken=token):
            user.update(status = 'active', activationToken = None)
            return {"msg": f"User {user.id} updated (inactive - active)", "status": "success"}, 200
    except ResponseException as e:
        return e.getErrorData(), e.statusCode
    except Exception as e:
        msg = {}
        for x in e.__dict__:
            msg[x] = str(e.__dict__[x])
        msg["status"] = "error"
        return msg, 500
    
@app.route("/login", methods=["POST"])
def postLogin():
    try:
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
            
            jwtToken = jwt.encode(payload=payload, key=JWT_SECRET)
                     
        return {"msg": f"Login of user {str(user.id)} done", "status": "success", "JWT": f"{jwtToken}"}, 200
    
    except ResponseException as e:
        return e.getErrorData(), e.statusCode
    except Exception as e:
        msg = {}
        for x in e.__dict__:
            msg[x] = str(e.__dict__[x])
        msg["status"] = "error"
        return msg, 500

@app.route("/update/<string:userId>", methods=["PATCH"])
def patchUpdate(userId):
    try:
        authorizationJwt = request.headers.get('Authorization')
        if not authorizationJwt:
            raise ResponseException('Not authenticated', 401)
        if not 'Bearer' in authorizationJwt:
            raise ResponseException('Not authenticated', 401)
        if not User.objects(id=userId):
            raise ResponseException("Invalid user id", 400)
            
        authorizationJwt = authorizationJwt.split(' ')[1]
        decodedJwt = (jwt.decode(authorizationJwt, JWT_SECRET, algorithms="HS256"))
        print (datetime.datetime.strptime(decodedJwt["tokenExpiration"], '%Y-%m-%d %H:%M:%S.%f'))
        if datetime.datetime.now() > datetime.datetime.strptime(decodedJwt["tokenExpiration"], '%Y-%m-%d %H:%M:%S.%f'):
            raise ResponseException("JWT expired. Please login again", 401)

        reqUser = None
        for user in User.objects(id=decodedJwt["userId"]):
            reqUser = user

        if str(userId) != decodedJwt["userId"] and reqUser.role != 'admin':
            raise ResponseException("You are not allowed to do this operation", 400)
        
        oldUser = None
        for user in User.objects(id=userId):
            oldUser = user

        for dataKey in request.json:
            if dataKey == 'name' or 'email':
                setattr(oldUser, dataKey, request.json[dataKey])
        
        oldUser.save()

        return {"msg": f"User {userId} updated", "status": "success"}, 200

    except ResponseException as e:
        return e.getErrorData(), e.statusCode
    except Exception as e:
        msg = {}
        for x in e.__dict__:
            msg[x] = str(e.__dict__[x])
            msg["status"] = "error"
            return msg, 500

if __name__ == "__main__":
    try:
        connect(host=MONGODB_URI)
        app.run(port=8080, debug=True)
    except Exception as e:
        print(e)
