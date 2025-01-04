from mongoengine import Document, StringField

STATUS = ('active', 'inactive')

class User(Document):
    name = StringField(required=True)
    email = StringField(required=True)
    password = StringField(required=True)
    activationToken = StringField()
    mfaSecret = StringField(required=True)
    status = StringField(required=True, choices=STATUS)
        