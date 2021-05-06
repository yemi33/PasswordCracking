#!/usr/bin/env python3
import hashlib
import binascii

class PasswordCracker:
  def __init__(self, word_file, password_file):
    self.words = [line.strip().lower() for line in open(word_file)]
    self.passwordHashes = [line.strip().split(":")[1] for line in open(password_file)]
    #self.words = self.words[:100]
    self.hashes_dictionary = self.calculateSingleWordHashes()
    self.hashes_dictionary_double = dict()

  def calculateSingleWordHashes(self):
    hashes = dict()
    #single word passwords
    for password in self.words:
      encodedPassword = password.encode('utf-8') 
      md5 = hashlib.md5(encodedPassword)
      passwordHash = md5.digest()
      passwordHashAsHex = binascii.hexlify(passwordHash)
      passwordHashAsHexString = passwordHashAsHex.decode('utf-8') 
      hashes[passwordHashAsHexString] = password

  def calculateDoubleWordHashes(self):
    hashes = dict()
    #two words passwords
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

  def crackPassword(self,file):
    numCracked = 0
    input = open(file).read().split("\n")
    output = open("passwords1_cracked.txt", "a")
    for line in input:
      splitString = line.split(":")
      username = splitString[0]
      passwordHash = splitString[1] 
      password = ""
      if passwordHash in self.hashes_dictionary:
        password = self.hashes_dictionary[passwordHash]
        output.write(f"{username}:{password}\n")
        numCracked += 1
      elif self.hashes_dictionary_double != "" and passwordHash in self.hashes_dictionary_double:
        password = self.hashes_dictionary_double[passwordHash]
        output.write(f"{username}:{password}\n")
        numCracked += 1
      else:
        self.hashes_dictionary_double = self.calculateDoubleWordHashes()
    
    return numCracked
  
class SaltedPasswordCracker:
  def __init__(self, word_file, password_file):
    self.words = [line.strip().lower() for line in open(word_file)]

  def matchHash(self, salt, hash):
    '''
    Create a dictionary 
    key: hash
    value: pw

    for each combination of words in the file,
    calculate the hash, and save the hash as the key and the combination as the value
    '''
    #single word passwords
    for password in self.words:
      password = salt + password
      encodedPassword = password.encode('utf-8') 
      md5 = hashlib.md5(encodedPassword)
      passwordHash = md5.digest()
      passwordHashAsHex = binascii.hexlify(passwordHash)
      passwordHashAsHexString = passwordHashAsHex.decode('utf-8') 
      if hash == passwordHashAsHexString:
        return password
    
    #two words passwords
    for password1 in self.words:
      for password2 in self.words:
        password = salt + password1 + password2
        encodedPassword = password.encode('utf-8')
        md5 = hashlib.md5(encodedPassword)
        passwordHash = md5.digest() 
        passwordHashAsHex = binascii.hexlify(passwordHash) 
        passwordHashAsHexString = passwordHashAsHex.decode('utf-8')
        if hash == passwordHashAsHexString:
          return password

    return None

  def crackPassword(self,file):
    input = open(file).read().split("\n")
    output = open("passwords2_cracked.txt", "a")
    numCracked = 0
    for line in input:
      splitString = line.split(":")
      username = splitString[0]
      salt = splitString[1].split("$")[0]
      saltedPasswordHash = splitString[1].split("$")[1]
      password = ""
      if self.matchHash(salt, saltedPasswordHash) != None:
        password = self.matchHash(salt, saltedPasswordHash)
        output.write(f"{username}:{password}\n")
        numCracked += 1
    
    return numCracked
    
if __name__ == "__main__":
  # passwordCracker = PasswordCracker("words.txt", "passwords1.txt")
  # result = passwordCracker.crackPassword("passwords1.txt")
  # print(f"Number of pws cracked for regular passwords: {result}")
  saltedPasswordCracker = SaltedPasswordCracker("words.txt", "passwords2.txt")
  result2 = saltedPasswordCracker.crackPassword("passwords2.txt")
  print(f"Number of pws cracked for salted passwords: {result2}")