class responseException(Exception):
    def __init__(self, msg, statusCode):
        self.msg = msg
        self.statusCode = statusCode
        self.status = "error"
    def getErrorData(self):
        return {"msg": self.msg, "status": self.status}