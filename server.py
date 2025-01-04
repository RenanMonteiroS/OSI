from flask import Flask, request, Response
from flask_cors import CORS
from model.user import User
from mongoengine import connect
from secrets import token_urlsafe
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from base64 import b32encode
from jinja2 import Environment, FileSystemLoader, select_autoescape
from uuid import uuid4
from os import remove
import bcrypt, smtplib, jwt, pyotp, random, string, qrcode, configparser

app = Flask(__name__)
CORS(app, allow_headers=["Content-Type", "Authorization", "Accept-Language"], 
     methods=["GET", "POST"],
     origins="*",
    )


config = configparser.ConfigParser()
config.read('config.conf')

MONGODB_URI = config['DATABASE']['MONGODB_URI']
JWT_SECRET = config['JWT']['JWT_SECRET']

@app.route("/register", methods=["POST"])
def postRegister():
    name = request.json["name"]
    email = request.json["email"]
    password = request.json["password"]

    if User.objects(email=email):
        return Response(f"User with e-mail: {email} already exists", status=400)

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

    return Response(f"User created: {createdUser.id}", status=201)

@app.route("/activate", methods=["GET"])
def getActivate():
    token = request.args.get('token')
    if not User.objects(activationToken=token):
        return Response(f"Invalid token", status=400)
    
    for user in User.objects(activationToken=token):
        user.update(status = 'active', activationToken = None)
        return Response(f"User {user.id} updated (inactive - active)", status=200)
    
@app.route("/login", methods=["POST"])
def postLogin():
    email = request.json["email"]
    password = request.json["password"]
    mfaKey = request.json["mfaKey"]

    for user in User.objects(email=email):
        if not pyotp.TOTP(b32encode(str.encode(user.mfaSecret))).now() == mfaKey:
            return Response(f"Wrong TOTP value", status=401)

        if not bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            return Response("Wrong Password", status=401)

        if not user.status == 'active':
            return Response(f"User id:{user.id} is not active", status=401)
        
        payload = {
            "email": user.email,
            "userId": str(user.id)
        }

        jwtToken = jwt.encode(payload=payload, key=JWT_SECRET)
        
    return Response(jwtToken, status=200)

    
if __name__ == "__main__":
    try:
        connect(host=MONGODB_URI)
        app.run(port=8080, debug=True)
    except Exception as e:
        print(e)
