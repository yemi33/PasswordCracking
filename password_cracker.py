#!/usr/bin/env python3
import hashlib
import binascii

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

  def calculateDoubleWordHashes(self):
    hashes = dict()
    for password1 in self.words:
      for password2 in self.words:
        password = password1 + password2
        encodedPassword = password.encode('utf-8')
        md5 = hashlib.md5(encodedPassword)
        passwordHash = md5.digest() 
        passwordHashAsHex = binascii.hexlify(passwordHash) 
        passwordHashAsHexString = passwordHashAsHex.decode('utf-8')
        if passwordHashAsHexString in self.passwordHashes:
          hashes[passwordHashAsHexString] = password

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

  def matchHashDouble(self, salt, hash):
    #two words passwords
    for password1 in self.words:
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

  def crackPassword(self):
    input = open(self.passwordFile).read().split("\n")
    output = open("passwords2_cracked.txt", "a")
    numCracked = 0
    for line in input:
      splitString = line.split(":")
      username = splitString[0]
      try:
        secondSplitString = splitString[1].split("$")
        salt = secondSplitString[0]
        saltedPasswordHash = secondSplitString[1]
      except:
        continue
      password = ""
      # if the mode is "single", then use the matchHashSingle Method
      if self.mode == "single":
        password = self.matchHashSingle(salt, saltedPasswordHash)
        if password != None:
          output.write(f"{username}:{password}\n")
          numCracked += 1
      # if the mode is "double", then use the matchHashDouble method
      else:
        password = self.matchHashDouble(salt, saltedPasswordHash)
        if password != None:
          output.write(f"{username}:{password}\n")
          numCracked += 1
    
    return numCracked
    
if __name__ == "__main__":
  '''
  To be time efficient, separating single word pws from double word pws (the latter is the bottleneck. (O(n^2) where n is the length of words.txt))
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
  sys     0m0.062s

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

  # # just checking double word passwords
  # passwordCracker = PasswordCracker("words.txt", "passwords1.txt", mode = "double")
  # result = passwordCracker.crackPassword()
  # print(result) 
  # print(passwordCracker.numHashesComputed)

  '''
  PART 2: Salted PWs
  '''

  # just checking single word passwords
  saltedPasswordCracker = SaltedPasswordCracker("words.txt", "passwords2.txt")
  result2 = saltedPasswordCracker.crackPassword()
  print(result2) # 1133
  print(saltedPasswordCracker.numHashesComputed) # 466049067

  '''
  Time Results for Part 2, only calculating single word PWs:
  real    19m18.601s
  user    18m47.653s
  sys     0m15.026

  466049067 hashes were calculated in 18m47s = 1127s
  which means
  413530 hashes / second 

  now to calculate all double word pws
  7.16 * 10^10 hashes (worst case for each line in passwords2.txt)
  there are 2326 lines in passwords2.txt
  which makes the worst case number of hashes we need to calculate
  1.66 * 10^14 hashes
  which will take
  ~ 402731604 seconds
  ~ 6712193 mins
  ~ 111869 hrs
  ~ 4661 days
  ~ 12.8 years

  yeepee
  '''