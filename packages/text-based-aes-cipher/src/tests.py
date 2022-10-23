from main import encryptECB, decryptECB, preparePlaintext, removeSeparatorFromPlaintext
from constants import ALPHABET
import random

def genRandomTextKey():
  text = ''

  for i in range(0, 16):
    text += ALPHABET[random.randint(0, len(ALPHABET) - 1)]

  return text


def firstTest():
  text = "HELLO WORLD THIS IS A TEST OF MY TEXT AES CIPHER"
  key  = "ASVRFWGSSCXBLSKW"
  ciphertext = encryptECB(preparePlaintext(text), key)
  plaintext = decryptECB(ciphertext, key)

  print('TEST N1:', text == removeSeparatorFromPlaintext(plaintext))

def secondTest():
  text = "HELLOXWORLDXTHISXISXAXTESTXOFXMYXTEXTXAESXCIPHER"
  key = "BAAAAAAAAAAAAAAA"
  ciphertext = encryptECB(text, key)
  plaintext = decryptECB(ciphertext, key)

  print('TEST N2:', text == removeSeparatorFromPlaintext(plaintext))

def thirdTest():
  text = "HELLOXWORLDXTHISXISXAXTESTXOFXMYXTEXTXAESXCIPHER"
  key = genRandomTextKey()
  ciphertext = encryptECB(preparePlaintext(text), key)
  plaintext = decryptECB(ciphertext, key)

  print('TEST N3:', text == removeSeparatorFromPlaintext(plaintext))

def main():
    print('UNIT TESTS RESULT:')
    firstTest()
    secondTest()
    thirdTest()

main()
