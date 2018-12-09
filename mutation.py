import os
import subprocess
import shutil
import time
import random

def mutation4(article): # insert random byte and delete original byte
   random.seed(os.urandom(30))
   length = ord(os.urandom(1))
   rand = random.randint(0,len(article)) # location
   randombytes = os.urandom(length)
   result = article[:rand]
   result += randombytes
   result += article[(rand+length):]
   return result
