from mongoengine import Document, StringField, DateTimeField
from datetime import datetime

STATUS = ('active', 'inactive')
ROLES = ('admin', 'common')

class User(Document):
    name = StringField(required=True)
    email = StringField(required=True)
    password = StringField(required=True)
    activationToken = StringField()
    mfaSecret = StringField(required=True)
    status = StringField(required=True, choices=STATUS, default='inactive')
    role= StringField(required=True, choices=ROLES, default='common')
    created_at = DateTimeField(required=True, default=datetime.now())
    modified_at = DateTimeField(required=True, default=datetime.now())

    def save(self, *args, **kwargs):
        if not self.created_at:
            self.created_at = datetime.now()
        self.updated_at = datetime.now()
        return super(User, self).save(*args, **kwargs)

        