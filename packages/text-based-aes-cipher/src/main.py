from constants import ALPHABET, HILL_CIPHER_MATRIX, HILL_CIPHER_MATRIX_INVERSE, SBOX, SBOX_INVERSE, SEPARATOR
import random
'''
 Algorithm based in C# implementation of n1k0m0:
 https://github.com/n1k0m0/AES-and-Text-Based-AES

  # Steps of original AES
      plaintext
          ↓
      AddRoundKey (initial round key with Key Expansion)
          ↓
      SubBytes                                               |
          ↓                                                  |
      ShiftRows                                              |
          ↓                                                  |- 9, 11 or 13 rounds
      MixColumns                                             |
          ↓                                                  |
      AddRoundKey (i-th round key with Key Expansion)        |
          ↓
      SubBytes                                               |
          ↓                                                  |
      ShiftRows                                              |- Final round (without MixColumns)
          ↓                                                  |
      AddRoundKey (last round key with Key Expansion)        |
          ↓
      CipherText

    OBS:
    - uses a state of 16 bytes
    - **AddRoundKey** -
    - **SubBytes** -
    - **ShiftRows** - (bitwise operation)
    - **MixColumns** -
    - **Round** -
    - **Key Expansion** -

  # Steps of this implementation of text-based AES
      plaintext
          ↓
      AddRoundKey (initial round key with Key Expansion)
          ↓
      SubBigrams                                             |
          ↓                                                  |
      ShiftRows                                              |
          ↓                                                  |- 9 rounds
      MixColumns                                             |
          ↓                                                  |
      AddRoundKey (i-th round key with Key Expansion)        |
          ↓
      SubBigrams                                             |
          ↓                                                  |
      ShiftRows                                              |- Final round (without MixColumns)
          ↓                                                  |
      AddRoundKey (last round key with Key Expansion)        |
          ↓
      CipherText

    OBS:
    - uses a state of 16 letters
    - **AddRoundKey** -
    - **SubBigrams** -
    - **ShiftRows** -
    - **MixColumns** -
    - **Round** -
    - **Key Expansion** -

'''

def Mod(num, modr):
  return ((num % modr) + modr) % modr

def mapNumbersIntoTextSpace(nums, alphabet):
  text = ''

  for i in nums:
    text += alphabet[i]

  return text

def mapTextIntoNumberSpace(text, alphabet):
  nums = []

  for letter in text:
    nums.append(alphabet.index(letter))

  return nums

def genSBoxAndInverse():
  sbox = []
  sbox_inverse = []

  # fill s-box with numbers
  for i in range(0, len(ALPHABET) * 2):
    sbox.append(i)

  n = len(sbox)

  # shuffle s-box
  while (n > 1):
    n -= 1

    k = random.randint(0, n)
    temp = sbox[n]
    sbox[n] = sbox[k]
    sbox[k] = temp

  # create inverse s-box
  for i in range(len(sbox)):
    sbox_inverse[sbox[i]] = i

def addRoundKey(data, round_key):
  for i in range(0, len(data)):
    data[i] = Mod(data[i] + round_key[i], len(ALPHABET))

def subtractRoundKey(data, round_key):
  for i in range(0, len(data)):
    data[i] = Mod(data[i] - round_key[i], len(ALPHABET))

def subBigrams(data):
  def subBigram(bigram):
    offset = bigram[0] * len(ALPHABET) + bigram[1]
    num = SBOX[offset]

    return [num // len(ALPHABET), num % len(ALPHABET)]

  for i in range(0, len(data), 2):
    sub = subBigram([data[i], data[i + 1]])
    data[i] = sub[0]
    data[i + 1] = sub[1]

  return data

def subBigramsInverse(data):
  def subBigramInverse(bigram):
    offset = bigram[0] * len(ALPHABET) + bigram[1]
    num = SBOX_INVERSE[offset]

    return [num // len(ALPHABET), num % len(ALPHABET)]

  for i in range(0, len(data), 2):
    sub = subBigramInverse([data[i], data[i + 1]])
    data[i] = sub[0]
    data[i + 1] = sub[1]

  return data

def shiftRows(data):
  # 0   4   8  12
  # 1   5   9  13 <- 1 letter to left circular shift
  # 2   6  10  14 <- 2 letter to left circular shift
  # 3   7  11  15 <- 3 letter to left circular shift

  # 1 row: do nothing
  # 2 row: shift one to the left
  swap     = data[1]
  data[1]  = data[5]
  data[5]  = data[9]
  data[9]  = data[13]
  data[13] = swap

  # 3 row: shift two to the left = exchange every 2nd
  swap     = data[2]
  data[2]  = data[10]
  data[10] = swap
  swap     = data[6]
  data[6]  = data[14]
  data[14] = swap

  # 4 row: shift three to the left = shift to the right
  swap     = data[15]
  data[15] = data[11]
  data[11] = data[7]
  data[7]  = data[3]
  data[3]  = swap

def shiftRowsInverse(data):
  # 0   4   8  12
  # 1   5   9  13 <- 1 letter to right circular shift
  # 2   6  10  14 <- 2 letter to right circular shift
  # 3   7  11  15 <- 3 letter to right circular shift

  # 1 row: do nothing
  # 2 row: shift one to the right
  swap     = data[13]
  data[13] = data[9]
  data[9]  = data[5]
  data[5]  = data[1]
  data[1]  = swap

  # 3 row: shift two to the right = exchange every 2nd
  swap     = data[2]
  data[2]  = data[10]
  data[10] = swap
  swap     = data[6]
  data[6]  = data[14]
  data[14] = swap

  # 4 row: shift three to the right = shift to the left
  swap     = data[3]
  data[3]  = data[7]
  data[7]  = data[11]
  data[11] = data[15]
  data[15] = swap

def mixColumns(data):
  for i in range(0, 16, 4):
    b0 = data[i]
    b1 = data[i + 1]
    b2 = data[i + 2]
    b3 = data[i + 3]

    for y in range(0, 4):
      data[i + y] = (HILL_CIPHER_MATRIX[y] * b0 + HILL_CIPHER_MATRIX[y + 4] * b1 + HILL_CIPHER_MATRIX[y + 8] * b2 + HILL_CIPHER_MATRIX[y + 12] * b3) % len(ALPHABET)

def mixColumnsInverse(data):
  for i in range(0, 16, 4):
    b0 = data[i]
    b1 = data[i + 1]
    b2 = data[i + 2]
    b3 = data[i + 3]

    for y in range(0, 4):
      data[i + y] = (HILL_CIPHER_MATRIX_INVERSE[y] * b0 + HILL_CIPHER_MATRIX_INVERSE[y + 4] * b1 + HILL_CIPHER_MATRIX_INVERSE[y + 8] * b2 + HILL_CIPHER_MATRIX_INVERSE[y + 12] * b3) % len(ALPHABET)

# AES round constants here we just take a letter from the alphabet
def rcon(i):
  return [Mod(i, len(ALPHABET)), 0x00, 0x00, 0x00]

# extract a 4 letter word from the giver offset
def getWord(data, offset):
  word = []

  for i in range(0, 4):
    word.append(data[int(offset) * 4 + i])

  return word

# set a 4 letter word at the giver offset
def setWord(data, word, offset):
  for i in range(0, 4):
    data[offset * 4 + i] = int(word[i])

# adds two given 4 letters words MOD alphabet length
def add(w1, w2):
  word = []

  for i in range(0, 4):
    word.append(Mod(w1[i] + w2[i], len(ALPHABET)))

  return word

# rotWord operation of keyschedule of AES
def rotWord(data):
  ret = []

  ret.append(data[1])
  ret.append(data[2])
  ret.append(data[3])
  ret.append(data[0])

  return ret

def subWord(data):
  def subBigram(bigram):
    offset = bigram[0] * len(ALPHABET) + bigram[1]
    num = SBOX[offset]

    return [num // len(ALPHABET), num % len(ALPHABET)]

  ret = [0] * 4

  for i in range(0, len(data), 2):
    sub = subBigram([data[i], data[i + 1]])
    ret[i] = sub[0]
    ret[i + 1] = sub[1]

  return ret

def keyExpansion(k, r):
  n = len(k) / 4
  w = [0] * 4 * 4 * r

  for i in range(0, 4 * r):
    if (i < n):
      setWord(w, getWord(k, i), i)
    elif (i >= n and i % n == 0):
      word = add(getWord(w, i - n), subWord(rotWord(getWord(w, i - 1))))
      word = add(word, rcon(i / n))
      setWord(w, word, i)
    elif (i >= n and n > 6 and i % n == 4):
      word = add(getWord(w, i - n), subWord(getWord(w, i - 1)))
      setWord(w, word, i)
    else:
      word = add(getWord(w, i - n), getWord(w, i - 1))
      setWord(w, word, i)

  return w

def preparePlaintext(plaintext):
   return plaintext.upper().replace(' ', SEPARATOR)

def removeSeparatorFromPlaintext(plaintext):
  return plaintext.replace(SEPARATOR, ' ')

def encrypt(text, key, r):
  def getRoundKey(data, offset):
    word = []

    for i in range(0, 16):
      word.append(data[offset * 16 + i])

    return word


  # key expansion => make multiple out of the given key
  round_keys = keyExpansion(key, r + 1)
  # add 0 key
  addRoundKey(text, getRoundKey(round_keys, 0))


  for i in range(1, r):
    subBigrams(text)
    shiftRows(text)
    mixColumns(text)
    addRoundKey(text, getRoundKey(round_keys, i))

  # final round without mix columns
  subBigrams(text)
  shiftRows(text)
  addRoundKey(text, getRoundKey(round_keys, r))

  return text

def decrypt(text, key, r):
  def getRoundKey(data, offset):
    word = []

    for i in range(0, 16):
      word.append(data[offset * 16 + i])

    return word

  # key expansion => make multiple out of the given key
  round_keys = keyExpansion(key, r + 1)

  # final round without mix columns
  subtractRoundKey(text, getRoundKey(round_keys, r))
  shiftRowsInverse(text)
  subBigramsInverse(text)

  for i in range(r - 1, 0, -1):
    subtractRoundKey(text, getRoundKey(round_keys, i))
    mixColumnsInverse(text)
    shiftRowsInverse(text)
    subBigramsInverse(text)

  # # subtract 0 key
  subtractRoundKey(text, getRoundKey(round_keys, 0))

  return text

def encryptBlock(plaintext, key):
  if (len(plaintext) != 16):
    raise Exception('Plaintext length is different of 16')

  if (len(key) != 16):
    raise Exception('Key length is different of 16')

  numtext = mapTextIntoNumberSpace(plaintext, ALPHABET)
  numkey = mapTextIntoNumberSpace(key, ALPHABET)
  ciphertext = encrypt(numtext, numkey, 10)

  return mapNumbersIntoTextSpace(ciphertext, ALPHABET)

def decryptBlock(ciphertext, key):
  if (len(ciphertext) != 16):
    raise Exception('Cipher text length is different of 16')

  if (len(key) != 16):
    raise Exception('Key length is different of 16')

  numtext = mapTextIntoNumberSpace(ciphertext, ALPHABET)
  numkey = mapTextIntoNumberSpace(key, ALPHABET)
  plaintext = decrypt(numtext, numkey, 10)

  return mapNumbersIntoTextSpace(plaintext, ALPHABET)

def encryptECB(plaintext, key):
  while len(plaintext) % 16 > 0:
    plaintext += SEPARATOR

  string = ''

  for i in range(0, len(plaintext), 16):
    string += encryptBlock(plaintext[i:16 + i], key)

  return string

def decryptECB(cipherText, key):
  if (len(cipherText) % 16 != 0):
    raise Exception('Cipher text length is no multiple of 16')

  string = ''

  for i in range(0, len(cipherText), 16):
    string += decryptBlock(cipherText[i:16 + i], key)

  return string
