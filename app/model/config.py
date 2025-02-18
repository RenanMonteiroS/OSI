import configparser

config = configparser.ConfigParser()
config.read('config.conf')

class Config:
    MONGODB_URI = config['DATABASE']['MONGODB_URI']
    JWT_ALGORITHM = config['JWT']['JWT_ALGORITHM']
    JWT_SECRET = config['JWT']['JWT_SECRET']
    JWT_PUBLIC_KEY_PATH = config['JWT']['JWT_PUBLIC_KEY_PATH']
    JWT_PRIVATE_KEY_PATH = config['JWT']['JWT_PRIVATE_KEY_PATH']
    LIMITER_STORAGE_URL = config['LIMITER']['LIMITER_STORAGE_URL']
    LIMITER_STRATEGY = config['LIMITER']['LIMITER_STRATEGY'] or "fixed-window"
    JWT_ALGORITHM = config['JWT']['JWT_ALGORITHM'] or 'HS256'
    COMPANY_NAME = config['COMPANY_INFO']['COMPANY_NAME']
    COMPANY_WEBSITE = config['COMPANY_INFO']['COMPANY_WEBSITE']
    SMTP_SERVER = config['SMTP']['SMTP_SERVER']
    SMTP_PORT = int(config['SMTP']['SMTP_PORT'])
    SMTP_USER = config['SMTP']['SMTP_USER']
    SMTP_PASSWORD = config['SMTP']['SMTP_PASSWORD']
    SMTP_EMAILSENDER = config['SMTP']['SMTP_EMAILSENDER']