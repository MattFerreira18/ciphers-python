import re

def isEncryptionAllowed(name):
    return name in ['aes', 'asymmetric']

def hasNumbers(string):
  return re.match('[0-9]', string)

# TODO fix this regex
def hasSymbols(string):
  return re.match("[!@#$%^&*()_+\-=\[\]{};':\"\|,.<>/?]", string)

def isAESKeyLengthValid(key):
  return len(key) == 16

def hasOnlyLetters(string):
  if (hasNumbers(string)):
    return False

  if (hasSymbols(string)):
    return False

  return True
