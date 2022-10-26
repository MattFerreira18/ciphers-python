import random
from ciphers.utils import preparePlaintext, removeSeparatorFromPlaintext
from ciphers.constants import ALPHABET, HILL_CIPHER_MATRIX, HILL_CIPHER_MATRIX_INVERSE, SBOX, SBOX_INVERSE, SEPARATOR

def Mod(num, modr):
  return ((num % modr) + modr) % modr

def mapNumbersIntoTextSpace(nums, alphabet):
  result = ''

  for i in nums:
    result += alphabet[i]

  return result

def mapTextIntoNumberSpace(text, alphabet):
  result = []

  for letter in text:
    result.append(alphabet.index(letter))

  return result

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
  result = []

  for i in range(0, 4):
    result.append(data[int(offset) * 4 + i])

  return result

# set a 4 letter word at the giver offset
def setWord(data, word, offset):
  for i in range(0, 4):
    data[offset * 4 + i] = int(word[i])

# adds two given 4 letters words MOD alphabet length
def add(w1, w2):
  result = []

  for i in range(0, 4):
    result.append(Mod(w1[i] + w2[i], len(ALPHABET)))

  return result

# rotWord operation of keyschedule of AES
def rotWord(data):
  # TODO rename to `result`
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

# TODO rename to `result`
  ret = [0] * 4

  for i in range(0, len(data), 2):
    sub = subBigram([data[i], data[i + 1]])
    ret[i] = sub[0]
    ret[i + 1] = sub[1]

  return ret

def keyExpansion(k, r):
  n = len(k) / 4
  result = [0] * 4 * 4 * r

  for i in range(0, 4 * r):
    if (i < n):
      setWord(result, getWord(k, i), i)
    elif (i >= n and i % n == 0):
      word = add(getWord(result, i - n), subWord(rotWord(getWord(result, i - 1))))
      word = add(word, rcon(i / n))
      setWord(result, word, i)
    elif (i >= n and n > 6 and i % n == 4):
      word = add(getWord(result, i - n), subWord(getWord(result, i - 1)))
      setWord(result, word, i)
    else:
      word = add(getWord(result, i - n), getWord(result, i - 1))
      setWord(result, word, i)

  return result

def encrypt(text, key, r):
  def getRoundKey(data, offset):
    result = []

    for i in range(0, 16):
      result.append(data[offset * 16 + i])

    return result


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
  plaintext = preparePlaintext(plaintext)

  while len(plaintext) % 16 > 0:
    plaintext += SEPARATOR

  result = ''

  for i in range(0, len(plaintext), 16):
    result += encryptBlock(plaintext[i:16 + i], key)

  return result

def decryptECB(ciphertext, key):
  if (len(ciphertext) % 16 != 0):
    raise Exception('Cipher text length is no multiple of 16')

  result = ''

  for i in range(0, len(ciphertext), 16):
    result += decryptBlock(ciphertext[i:16 + i], key)

  return removeSeparatorFromPlaintext(result)
