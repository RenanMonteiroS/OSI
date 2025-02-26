from flask import Blueprint, request, current_app, render_template, redirect
import os
from mongoengine import connect
from ..util.checkPermissions import isAdmin
from ..model.responseException import ResponseException
from ..model.config import Config
import configparser

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

@misc_bp.route("/dbping", methods=["POST"])
def dbPing():    
    try:
        from pymongo import MongoClient
        if not request.json["dbUri"]:
            raise ResponseException("Database URL is not defined", 400)
        dbUri = request.json["dbUri"]
        client = MongoClient(host=dbUri)
        
        ping = client.admin.command('ping')

        if ping['ok'] == 1:
            return {"msg": "Database connected.", "status": "ok"}, 200
        else:
            raise ResponseException("Database connection failed." , 400)

    except ResponseException as e:
        raise ResponseException(e.msg, e.statusCode)
    except Exception as e:
        return {"msg": "Internal Server Error", "status": "error"}, 500

@misc_bp.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == 'GET':
        if current_app.config['SETUP_DONE'] == 1:
            return render_template('setup.html', setupDone=1)
        else:
            return render_template('setup.html', setupDone=0)
    if request.method == "POST":
        from ..util.hashedPassword import generateHashedPassword
        from ..util.totp import generateTotpQrCode
        from ..util.restartSystem import restartSystemThread
        from uuid import uuid4
        from os import remove
        from ..model.user import User
        from ..util.sendEmail import sendActivationEmail
        import re

        from secrets import token_urlsafe

        try:
            if not request.json['dbUri'] or not request.json['jwtAlgorithm'] or not request.json['smtpServer'] or not request.json['smtpPort'] or not request.json['smtpUser'] or not request.json['smtpPassword'] or not request.json['smtpEmailSender'] or not request.json['adminEmail'] or not request.json['adminPassword']:
                return {"msg": "Some field was not filled correctly", "status": "error"}, 500
            
            with open(os.path.join(current_app.config["ROOT_PATH"], '..', 'config.conf'), "w") as f:                
                f.write(f"[DATABASE]\nMONGODB_URI={request.json['dbUri']}\n[JWT]\nJWT_ALGORITHM={request.json['jwtAlgorithm']}\nJWT_SECRET={request.json['jwtSecret']}\nJWT_PUBLIC_KEY_PATH={request.json['jwtPublicKeyPath']}\nJWT_PRIVATE_KEY_PATH={request.json['jwtPrivateKeyPath']}\n[SMTP]\nSMTP_SERVER={request.json['smtpServer']}\nSMTP_PORT={request.json['smtpPort']}\nSMTP_USER={request.json['smtpUser']}\nSMTP_PASSWORD={request.json['smtpPassword']}\nSMTP_EMAILSENDER={request.json['smtpEmailSender']}\n[COMPANY_INFO]\nCOMPANY_WEBSITE={request.json['companyWebsite']}\nCOMPANY_NAME={request.json['companyName']}\n[LIMITER]\nLIMITER_STORAGE_URL={request.json['limiterDbUri']}\nLIMITER_STRATEGY={request.json['limiterStrategy']}")
            
            config = configparser.ConfigParser()
            configFile = os.path.join(current_app.config["ROOT_PATH"], '..', 'config.conf')
            config.read('config.conf')
            config.read(configFile)
            serverConfig = Config(config['DATABASE']['MONGODB_URI'], 
                            config['JWT']['JWT_ALGORITHM'], config['JWT']['JWT_SECRET'], config['JWT']['JWT_PUBLIC_KEY_PATH'], config['JWT']['JWT_PRIVATE_KEY_PATH'], 
                            config['LIMITER']['LIMITER_STORAGE_URL'], config['LIMITER']['LIMITER_STRATEGY'], 
                            config['COMPANY_INFO']['COMPANY_NAME'], config['COMPANY_INFO']['COMPANY_WEBSITE'], 
                            config['SMTP']['SMTP_SERVER'], config['SMTP']['SMTP_PORT'], config['SMTP']['SMTP_USER'], config['SMTP']['SMTP_PASSWORD'], config['SMTP']['SMTP_EMAILSENDER'])
            
            current_app.config.from_object(serverConfig)
            connect(host=request.json['dbUri'], alias='default')
            
            with open(os.path.join(current_app.config["ROOT_PATH"], 'templates', 'static', 'images', 'logo.png'), 'wb') as f:
                import base64
                f.write(base64.b64decode(request.json["companyLogo"]))

            name = request.json["adminName"]
            email = request.json["adminEmail"]
            password = request.json["adminPassword"]

            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                raise ResponseException("E-mail is not valid", 400)

            if len(password) <= 5:
                raise ResponseException("Password too short", 400)
            if not re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_]).+$', password):
                raise ResponseException("Password does not correspond to the  set of required characters (special, uppercase, lowercase and number)", 400)

            if User.objects(email=email):
                raise ResponseException(msg=f"User with e-mail: {email} already exists", statusCode=400)
            
            hashedPassword = generateHashedPassword(password)
            
            qrcodeFullPathName = os.path.join(current_app.config["ROOT_PATH"], "templates", "static", "images", f"qrcode-{uuid4()}.png")
            mfaSecret = generateTotpQrCode(email, qrcodeFullPathName)

            createdUser = User(name=name, email=email, password=hashedPassword, role='admin', activationToken=token_urlsafe(), mfaSecret=mfaSecret).save()
            current_app.logger.info(f"User {createdUser.id} created.")
            sendActivationEmail(createdUser, qrcodeFullPathName)        

            remove(qrcodeFullPathName)
            
            current_app.config["SETUP_DONE"] = 1

            restartSystemThread.start()

            return {"msg": "Done", "status": "ok"}, 200
        except ResponseException as e:
            raise ResponseException(e.msg, e.statusCode)
        except Exception as e:
            print(f"Error: {e}")
            os.remove(os.path.join(current_app.config["ROOT_PATH"], '..', 'config.conf'))
            return {"msg": "Fail", "status": "error"}, 500

@misc_bp.route("/", methods=["GET"])
def main():
    return redirect("/setup")