# OSI

OSI is a SSO, used for manipulating users and authentication. 
It's a microservice, which returns a JWT.

All user information are stored in a MongoDB Atlas database.

Supports TOTP (Google Authentication) authentication.

### Built with
* <img src="https://s3.dualstack.us-east-2.amazonaws.com/pythondotorg-assets/media/community/logos/python-logo-only.png" width="5%">
* <img src="https://flask.palletsprojects.com/en/stable/_images/flask-horizontal.png" width="15%">

## Installation

### Prerequisites 
* python3
  ```bash
  # RedHat-based distros
  sudo dnf install python3
  # Debian-based distros
  sudo apt-get install python3
  ```

* pip
  ```bash
  python3 -m ensurepip --default-pip
  ```

* Dependencies
  ```bash
  pip install flask flask_cors mongoengine secrets Jinja2 uuid bcrypt smtplib pyjwt pyotp qrcode
  ```

Use the git cli for downloading the project.

```bash
git clone https://github.com/RenanMonteiroS/OSI.git
```

### Configuration
Below is a step by step for configure correctly the app with your company's information:

1. Create a config.conf file with the code below:
   ```
   [DATABASE]
    MONGODB_URI=mongodb+srv://user:password@your-cluster/database

   [JWT]
    JWT_SECRET=super-secret-jwt

   [SMTP]
    SMTP_SERVER=smtp.your-smtp-provider.com
    SMTP_PORT=587
    SMTP_USER=your-smtp-user-email@example.com.br
    SMTP_PASSWORD=your-smtp-password
    SMTP_EMAILSENDER=your-smtp-email@example.com.br

   [COMPANY_INFO]
    COMPANY_WEBSITE=https://your-company-website.com.br
    COMPANY_NAME=your-company-name
   ```

2. Alter the variables in `config.conf` file. 
   `[DATABASE]`, `[JWT]` and `[SMTP]` are required
   If your database URI contains special characters (like @, in password), it needs to be converted to [percent encode](https://developer.mozilla.org/en-US/docs/Glossary/Percent-encoding).
   However, Python strings does not works well with percentage characters, so it needs to have one more percentage character. 
   Example.: If your password is abc@123, it needs to be changed to abc%%40123 in the connection string.

3. Add your company logo in the `templates > static > images` folder, with the name `logo.png`. (Not required)

## Endpoints

### /register

**[POST] Method**
Creates a inactive user, with the e-mail, name and encrypted password received.
Also, it generates:
* An activation token (in database), which will be used in [/activate](#activate)
* A QR code with the TOTP used for authentication
* An e-mail, sended for the user's e-mail, with the activation link and the QR Code

**Expects:**
* email: User's e-mail (must be unique)
* name: User's name
* password: User's password

### /activate

**[GET] Method**
Activates previously created user.
[/login](#login) endpoint expects an 'active' user.

**Expects (query param):**
* ?token: User's activationToken

### /login

**[POST] Method**
Generates and returns a JWT token, with `userId`, `userEmail` and a `tokenExpiration` as payload.
The token have an expiration time of 30 minutes.
The generated JWT uses the secret configured in `config.conf` file, in the [JWT] section. 

**Expects:**
* email: User's e-mail (must be unique)
* password: User's password
* mfaKey: Users's TOTP key, generated by Google Authenticator

## Roadmap

- [x] Code Improvement - CORS
- [x] Feature - Add company's personalization
- [x] Feature - Use validator for POST/PATCH/PUT requests
- [ ] Feature - Upload to company's logo
- [x] Code Improvement - Better error handling
- [x] Code Improvement - `created_at` and `modified_at` column in User class/document 
- [x] Code Improvement - JWT with expiration time payload attribute and validation
- [ ] Feature - JWT RS256 based support 
- [ ] Feature - Create DockerFile
- [X] Feature - Create file with required packages to `pip install -r requirements.txt`
- [X] Feature - Delete and Update user (admin/owner)
- [ ] Feature - Password and TOTP redefinition
- [ ] Feature - Setup page
    - [ ] Create default admin user in setup
- [ ] Feature - User Prima ORM to support other database engines (MySQL, Postgres and SQL Server)
- [ ] Feature - Create a frontend to manipulate OSI backend (Vue.js)
- [ ] Code Improvement - Handle better special characters in MONGODB_URI
- [ ] Multi-language Support
    - [ ] pt-br

See the [open issues](https://github.com/RenanMonteiroS/OSI/issues) for a full list of proposed features (and known issues).

## Contributing

Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request