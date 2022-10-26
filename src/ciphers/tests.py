from ciphers.aes import encryptECB, decryptECB
from ciphers.utils import genRandomTextKey

def firstTest():
  text = "HELLO WORLD THIS IS A TEST OF MY TEXT AES CIPHER"
  key  = "ASVRFWGSSCXBLSKW"
  ciphertext = encryptECB(text, key)
  plaintext = decryptECB(ciphertext, key)

  print('TEST N1:', text == plaintext and text != ciphertext)

def secondTest():
  text = "HELLOXWORLDXTHISXISXAXTESTXOFXMYXTEXTXAESXCIPHER"
  key = "BAAAAAAAAAAAAAAA"
  ciphertext = encryptECB(text, key)
  plaintext = decryptECB(ciphertext, key)

  print('TEST N2:', text == plaintext and text != ciphertext)

def thirdTest():
  text = "HELLOXWORLDXTHISXISXAXTESTXOFXMYXTEXTXAESXCIPHER"
  # text = 'SDFSFSDFDSFSD'
  key = genRandomTextKey()
  ciphertext = encryptECB(text, key)
  plaintext = decryptECB(ciphertext, key)
  print(text == plaintext)
  # print('TEST N3:', text == plaintext and text != ciphertext)

def main():
    print('UNIT TESTS RESULT:')
    firstTest()
    secondTest()
    thirdTest()

main()
