import bcrypt

def generateHashedPassword(password):
    salt =  bcrypt.gensalt(rounds=14)
    hashedPassword =  bcrypt.hashpw(str.encode(password), salt)
    hashedPassword = hashedPassword.decode()
    return hashedPassword