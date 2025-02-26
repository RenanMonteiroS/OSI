from flask import current_app, request
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from smtplib import SMTP
import os

def sendActivationEmail(createdUser, qrcodeFullPathName):
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
    return 