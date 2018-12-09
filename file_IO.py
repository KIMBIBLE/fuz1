def getSeedfile(filename):
   f = open(filename, "rb")
   r = f.read()
   f.close()
   return r

def putFile(filename, content):
   f = open(filename, "wb")
   f.write(content)
   f.close()
   
   
