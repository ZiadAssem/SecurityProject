import hashlib

class MD5Hash:
    def __init__(self):
        self.md5 = hashlib.md5()

    def update(self, data):
        self.md5.update(data)

    def hexdigest(self):
        return self.md5.hexdigest()
    

class SHA256Hash:
    def __init__(self):
        self.sha256 = hashlib.sha256()

    def update(self, data):
        self.sha256.update(data)
        
    def hexdigest(self):
        return self.sha256.hexdigest()



