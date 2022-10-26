import random
from ciphers.constants import SEPARATOR, ALPHABET

def genRandomTextKey():
  text = ''

  for i in range(0, 16):
    text += ALPHABET[random.randint(0, len(ALPHABET) - 1)]

  return text

def preparePlaintext(plaintext):
   return plaintext.upper().replace(' ', SEPARATOR)

def removeSeparatorFromPlaintext(plaintext):
  return plaintext.replace(SEPARATOR, ' ')
