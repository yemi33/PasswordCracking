#!/usr/bin/env python3
import hashlib
import binascii
import concurrent.futures

class PasswordCracker:
  def __init__(self, wordFile, passwordFile, mode = "single"):
    self.words = [line.strip().lower() for line in open(wordFile)]
    self.passwordHashes = [line.strip().split(":")[1] for line in open(passwordFile)]
    self.wordFile = wordFile
    self.passwordFile = passwordFile
    if mode == "single":
      self.hashesDictionary = self.calculateSingleWordHashes()
    elif mode == "double":
      self.hashesDictionary = self.calculateDoubleWordHashes()
    self.numHashesComputed = len(self.hashesDictionary)

  def calculateSingleWordHashes(self):
    hashes = dict()
    for password in self.words:
      encodedPassword = password.encode('utf-8') 
      md5 = hashlib.md5(encodedPassword)
      passwordHash = md5.digest()
      passwordHashAsHex = binascii.hexlify(passwordHash)
      passwordHashAsHexString = passwordHashAsHex.decode('utf-8') 
      hashes[passwordHashAsHexString] = password
    
    return hashes

  def calculateDoubleWordHashesHelper(self, password1, hashes):
    for password2 in self.words:
        password = password1 + password2
        encodedPassword = password.encode('utf-8')
        md5 = hashlib.md5(encodedPassword)
        passwordHash = md5.digest() 
        passwordHashAsHex = binascii.hexlify(passwordHash) 
        passwordHashAsHexString = passwordHashAsHex.decode('utf-8')
        if passwordHashAsHexString in self.passwordHashes:
          hashes[passwordHashAsHexString] = password

  def calculateDoubleWordHashes(self):
    hashes = dict()
    with concurrent.futures.ThreadPoolExecutor() as executor:
      print("here")
      futures = []
      for password1 in self.words:
        futures.append(executor.submit(calculateDoubleWordHashesHelper, self=self, password1=password1, hashes=hashes))
      for future in concurrent.futures.as_completed(futures):
        print("completed")
  
    return hashes

  def crackPassword(self):
    numCracked = 0
    input = open(self.passwordFile).read().split("\n")
    output = open("passwords1_cracked.txt", "a")
    for line in input:
      splitString = line.split(":")
      username = splitString[0]
      passwordHash = splitString[1] 
      password = ""
      if passwordHash in self.hashesDictionary:
        password = self.hashesDictionary[passwordHash]
        output.write(f"{username}:{password}\n")
        numCracked += 1
    
    return numCracked
  
class SaltedPasswordCracker:
  def __init__(self, wordFile, passwordFile, mode = "single"):
    self.words = [line.strip().lower() for line in open(wordFile)]
    self.wordFile = wordFile
    self.passwordFile = passwordFile
    self.mode = mode
    self.numHashesComputed = 0

  def matchHashSingle(self, salt, hash):
    #single word passwords
    for password in self.words:
      origPassword = password
      password = salt + password
      encodedPassword = password.encode('utf-8') 
      md5 = hashlib.md5(encodedPassword)
      passwordHash = md5.digest()
      passwordHashAsHex = binascii.hexlify(passwordHash)
      passwordHashAsHexString = passwordHashAsHex.decode('utf-8') 
      if hash == passwordHashAsHexString:
        return origPassword
      self.numHashesComputed += 1

    return None

  def matchHashDoubleHelper(self, salt, hash, password1):
    for password2 in self.words:
        origPassword = password1 + password2
        password = salt + password1 + password2
        encodedPassword = password.encode('utf-8')
        md5 = hashlib.md5(encodedPassword)
        passwordHash = md5.digest() 
        passwordHashAsHex = binascii.hexlify(passwordHash) 
        passwordHashAsHexString = passwordHashAsHex.decode('utf-8')
        if hash == passwordHashAsHexString:
          return origPassword
        self.numHashesComputed += 1

    return None

  def matchHashDouble(self, salt, hash):
    #two words passwords
    with concurrent.futures.ThreadPoolExecutor() as executor:
      futures = []
      for password1 in self.words:
        futures.append(executor.submit(matchHashDoubleHelper,salt=salt, hash=hash, password1=password1))
      for future in concurrent.futures.as_completed(futures):
        # if any of the threads find the matching pw, return that
        if future.result() != None:
          return future.result()
      return None

  def crackPassword(self):
    input = open(self.passwordFile).read().split("\n")
    output = open("passwords2_cracked.txt", "a")
    numCracked = 0
    for line in input:
      splitString = line.split(":")
      username = splitString[0]
      salt = splitString[1].split("$")[0]
      saltedPasswordHash = splitString[1].split("$")[1]
      password = ""
      # if the mode is "single", then use the matchHashSingle Method
      if self.mode == "single":
        if self.matchHashSingle(salt, saltedPasswordHash) != None:
          password = self.matchHashSingle(salt, saltedPasswordHash)
          output.write(f"{username}:{password}\n")
          numCracked += 1
      # if the mode is "double", then use the matchHashDouble method
      else:
        if self.matchHashDouble(salt, saltedPasswordHash) != None:
          password = self.matchHashDouble(salt, saltedPasswordHash)
          output.write(f"{username}:{password}\n")
          numCracked += 1
    
    return numCracked
    
if __name__ == "__main__":
  '''
  To be time efficient, separating single word pws from double word pws (the latter is the bottleneck.)
  '''

  '''
  PART 1: Un-Salted PWs
  '''
  # # just checking single word passwords
  # passwordCracker = PasswordCracker("words.txt", "passwords1.txt")
  # result = passwordCracker.crackPassword()
  # print(result) # 1162
  # print(passwordCracker.numHashesComputed) # 267751

  '''
  Time Results for Part 1, only calculating single word PWs:
  real    0m1.110s
  user    0m0.765s
  sys 0m0.062s

  267751 hashes were calculated in 0.765s
  which means
  350001 hashes / second 

  now we need to calculate
  7.16 * 10^10 hashes for all double words pws
  which will take
  204829.69 seconds
  = 3413 mins
  = 56.9 hrs
  ~ 2.4 days

  wtf
  '''

  # just checking double word passwords
  passwordCracker = PasswordCracker("words.txt", "passwords1.txt", mode = "double")
  result = passwordCracker.crackPassword()
  print(result) 
  print(passwordCracker.numHashesComputed)

  '''
  PART 2: Salted PWs
  '''

  # saltedPasswordCracker = SaltedPasswordCracker("words.txt", "passwords2.txt")
  # result2 = saltedPasswordCracker.crackPassword()
  # print(result2)
  # print(saltedPasswordCracker.numHashesComputed)
