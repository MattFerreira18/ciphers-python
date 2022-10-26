import re

def hasNumbers(string):
  return re.match('[0-9]', string)

# TODO fix this regex
def hasSymbols(string):
  return re.match("[!@#$%^&*()_+\-=\[\]{};':\"\|,.<>/?]", string)

def hasOnlyLetters(string):
  if (hasNumbers(string)):
    return False

  if (hasSymbols(string)):
    return False

  return True
