import sys
import random
# from Crypto import Random
# from Crypto.Cipher import AES
# from base64 import b64encode, b64decode
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

# obs: This implementation works only on text data (Latin Alphabet A-Z)
ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
SBOX = [
  19,  534, 428, 602, 545, 271, 675, 490, 14,  606, 471, 621, 637, 234, 414, 299, 180, 669, 221, 127, 636, 371, 482, 34,  648, 487,
  440, 336, 508, 472, 370, 69,  563, 105, 114, 656, 539, 311, 661, 259, 48,  530, 660, 150, 202, 181, 191, 139, 627, 231, 655, 323,
  214, 164, 52,  642, 349, 535, 320, 128, 448, 454, 625, 501, 145, 222, 338, 102, 445, 667, 168, 84,  142, 555, 75,  546, 481, 646,
  594, 213, 192, 92,  162, 495, 79,  367, 601, 16,  499, 518, 671, 613, 94,  528, 64,  407, 289, 657, 189, 592, 558, 233, 398, 649,
  268, 266, 474, 381, 303, 511, 264, 172, 54,  479, 163, 569, 504, 658, 91,  295, 196, 122, 347, 104, 24,  316, 375, 260, 182, 600,
  252, 106, 604, 18,  515, 135, 157, 281, 622, 548, 588, 71,  470, 411, 331, 599, 28,  350, 73,  346, 496, 255, 304, 136, 580, 126,
  99,  633, 146, 251, 87,  537, 639, 452, 361, 653, 95,  390, 169, 460, 582, 373, 360, 185, 166, 348, 368, 246, 227, 20,  590, 86,
  467, 207, 378, 219, 98,  125, 629, 355, 391, 570, 244, 449, 170, 549, 240, 206, 193, 359, 210, 177, 663, 547, 220, 248, 129, 195,
  261, 670, 280, 276, 41,  394, 208, 90,  556, 258, 80,  282, 573, 560, 620, 319, 632, 83,  292, 559, 587, 116, 332, 364, 132, 302,
  575, 513, 212, 584, 245, 30,  334, 353, 115, 526, 585, 198, 81,  458, 269, 461, 120, 579, 450, 437, 50,  451, 298, 309, 345, 341,
  328, 242, 26,  8,   117, 645, 243, 293, 31,  567, 538, 497, 176, 507, 553, 229, 23,  286, 429, 56,  533, 226, 322, 60,  357, 400,
  25,  138, 647, 45,   7,  611, 469, 510, 2,   595, 294, 167, 641, 541, 358, 65,  576, 477, 62,  517, 211, 593, 6,   431, 134, 354,
  96,  532, 313, 197, 287, 29,  343, 608, 425, 296, 239, 557, 404, 199, 388, 422, 160, 230, 275, 443, 652, 369, 492, 610, 509, 254,
  616, 43,  640, 310, 137, 188, 93,  224, 317, 638, 284, 173, 238, 290, 27,  39,  175, 78,  36,  152, 659, 183, 418, 352, 473, 484,
  200, 257, 77,  82,  416, 300, 44,  551, 536, 525, 617, 419, 53,  318, 512, 237, 384, 111, 119, 483, 46,  148, 589, 335, 506, 421,
  498, 397, 133, 396, 315, 118, 88,  550, 156, 438, 485, 634, 235, 51,  201, 514, 522, 596, 424, 253, 505, 329, 430, 141, 305, 392,
  612, 615, 403, 395, 565, 204, 110, 527, 475, 263, 165, 55,  415, 426, 402, 383, 278, 586, 420, 457, 568, 256, 441, 628, 609, 324,
  154, 171, 184, 283, 465, 666, 159, 476, 130, 70,  597, 462, 520, 109, 480, 374, 326, 650, 668, 247, 15,  151, 572, 74,  651, 66,
  32,  42,  654, 265, 624, 186, 491, 399, 344, 674, 339, 493, 578, 571, 488, 502, 153, 455, 22,  552, 321, 17,  466, 463, 72,  312,
  236, 618, 519, 35,  272, 61,  144, 10 , 0,   9,   673, 306, 529, 623, 643, 500, 140, 598, 389, 442, 447, 187, 432, 314, 591, 581,
  147, 377, 85,  37,  544, 250, 89,  521, 459, 47,  542, 635, 4,   249, 273, 386, 342, 270, 554, 385, 262, 178, 435, 446, 58,  33,
  228, 174, 340, 190, 664, 218, 38,  307, 619, 444, 413, 356, 291, 209, 179, 325, 564, 566, 453, 216, 516, 100, 101, 279, 405, 131,
  1,   267, 59,  503, 301, 523, 410, 366, 494, 285, 330, 626, 3,   365, 223, 540, 379, 406, 124, 205, 433, 362, 665, 351, 121, 194,
  644, 489, 417, 161, 486, 113, 12,  241, 11,  274, 288, 143, 297, 583, 603, 155, 605, 308, 103, 631, 149, 327, 123, 376, 277, 614,
  423, 456, 393, 13,  577, 363, 68,  5,   543, 439, 562, 531, 630, 468, 436, 158, 97,  372, 337, 57,  434, 574, 49,  232, 409, 63,
  108, 203, 217, 382, 333, 380, 67,  524, 607, 464, 427, 112, 21,  662, 672, 107, 561, 40,  408, 412, 401, 225, 215, 387, 76,  478
]

SBOX_INVERSE = [
  502, 572, 294, 584, 532, 631, 308, 290, 263, 503, 501, 606, 604, 627, 8,   462, 87,  489, 133, 0,   179, 662, 486, 276, 124, 286,
  262, 352, 146, 317, 239, 268, 468, 545, 23,  497, 356, 523, 552, 353, 667, 212, 469, 339, 370, 289, 384, 529, 40,  646, 254, 403,
  54,  376, 112, 427, 279, 643, 544, 574, 283, 499, 304, 649, 94,  301, 467, 656, 630, 31,  451, 141, 492, 148, 465, 74,  674, 366,
  355, 84,  218, 246, 367, 225, 71,  522, 181, 160, 396, 526, 215, 118, 81,  344, 92,  166, 312, 640, 186, 156, 567, 568, 67,  616,
  123, 33,  131, 665, 650, 455, 422, 381, 661, 603, 34,  242, 229, 264, 395, 382, 250, 596, 121, 620, 590, 187, 155, 19,  59,  206,
  450, 571, 232, 392, 310, 135, 153, 342, 287, 47,  510, 413, 72,  609, 500, 64,  158, 520, 385, 618, 43,  463, 357, 484, 442, 613,
  398, 136, 639, 448, 328, 601, 82,  114, 53,  426, 174, 297, 70,  168, 194, 443, 111, 349, 547, 354, 272, 201, 541, 560, 16,  45,
  128, 359, 444, 173, 473, 515, 343, 98,  549, 46,  80,  198, 597, 207, 120, 315, 245, 325, 364, 404, 44,  651, 421, 591, 197, 183,
  214, 559, 200, 306, 236, 79,  52,  672, 565, 652, 551, 185, 204, 18,  65,  586, 345, 671, 281, 178, 546, 275, 329, 49,  647, 101,
  13,  402, 494, 379, 350, 322, 196, 605, 261, 266, 192, 238, 177, 461, 205, 533, 525, 159, 130, 409, 337, 151, 437, 365, 217, 39,
  127, 208, 540, 425, 110, 471, 105, 573, 104, 248, 537, 5,   498, 534, 607, 330, 211, 622, 432, 569, 210, 137, 219, 445, 348, 581,
  277, 316, 608, 96,  351, 558, 226, 267, 296, 119, 321, 610, 256, 15,  369, 576, 233, 108, 152, 414, 505, 553, 615, 257, 341, 37,
  493, 314, 517, 394, 125, 346, 377, 223, 58,  488, 282, 51,  441, 561, 458, 619, 260, 411, 582, 144, 230, 654, 240, 387, 27,  642,
  66,  478, 548, 259, 536, 318, 476, 258, 149, 122, 175, 56,  147, 595, 361, 241, 311, 189, 557, 284, 300, 199, 172, 164, 593, 629,
  231, 585, 579, 85,  176, 333, 30,  21,  641, 171, 457, 126, 621, 521, 184, 588, 655, 107, 653, 431, 380, 539, 535, 673, 326, 512,
  167, 190, 415, 626, 213, 419, 393, 391, 102, 475, 285, 670, 430, 418, 324, 570, 589, 95,  668, 648, 578, 143, 669, 556, 14,  428,
  368, 600, 360, 375, 434, 389, 327, 624, 408, 320, 429, 660, 2,   278, 412, 309, 516, 592, 644, 542, 638, 253, 399, 633, 26,  438,
  513, 331, 555, 68,  543, 514, 60,  193, 252, 255, 163, 564, 61,  485, 625, 435, 247, 528, 169, 249, 453, 491, 659, 446, 490, 182,
  637, 292, 142, 10,  29,  362, 106, 424, 449, 303, 675, 113, 456, 76,  22,  383, 363, 400, 602, 25,  482, 599, 7,   474, 334, 479,
  580, 83,  150, 271, 390, 88,  509, 63,  483, 575, 116, 410, 388, 273, 28,  336, 293, 109, 378, 235, 405, 134, 566, 305, 89,  496,
  454, 527, 406, 577, 657, 373, 243, 423, 93,  506, 41,  635, 313, 280, 1,   57,  372, 161, 270, 36,  587, 299, 530, 632, 524, 4,
  75,  203, 139, 195, 397, 371, 487, 274, 538, 73,  216, 323, 100, 227, 221, 666, 634, 32,  562, 420, 563, 269, 436, 115, 191, 481,
  464, 220, 645, 234, 302, 628, 480, 251, 154, 519, 170, 611, 237, 244, 433, 228, 140, 386, 180, 518, 99,  307, 78,  295, 407, 452,
  511, 145, 129, 86,  3,   612, 132, 614, 9,   658, 319, 440, 335, 291, 416, 91,  623, 417, 338, 374, 495, 554, 222, 11,  138, 507,
  472, 62,  583, 48,  439, 188, 636, 617, 224, 157, 401, 531, 20,  12,  347, 162, 340, 298, 55,  508, 598, 265, 77,  288, 24,  103,
  459, 466, 332, 165, 470, 50,  35,  97,  117, 358, 42,  38,  663, 202, 550, 594, 447, 69,  460, 17,  209, 90,  664, 504, 477, 6
]

HILL_CIPHER_MATRIX = [
  2, 3, 1, 1,
  1, 2, 3, 1,
  1, 1, 2, 3,
  3, 1, 1, 2,
]

HILL_CIPHER_MATRIX_INVERSE = [
  14, 9, 19, 25,
  25, 14, 9, 19,
  19, 25, 14, 9,
  9, 19, 25, 14,
]

# Is necessary to be a latin letter and in UPPER case
SEPARATOR = 'J'

# TODO rename
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

def genRandomTextKey():
  text = ''

  for i in range(0, 16):
    text += ALPHABET[random.randint(0, len(ALPHABET) - 1)]

  return text

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

    data[i]     = (HILL_CIPHER_MATRIX[0] * b0 + HILL_CIPHER_MATRIX[4] * b1 + HILL_CIPHER_MATRIX[8] * b2 + HILL_CIPHER_MATRIX[12] * b3) % len(ALPHABET)
    data[i + 1] = (HILL_CIPHER_MATRIX[1] * b0 + HILL_CIPHER_MATRIX[5] * b1 + HILL_CIPHER_MATRIX[9] * b2 + HILL_CIPHER_MATRIX[13] * b3) % len(ALPHABET)
    data[i + 2] = (HILL_CIPHER_MATRIX[2] * b0 + HILL_CIPHER_MATRIX[6] * b1 + HILL_CIPHER_MATRIX[10] * b2 + HILL_CIPHER_MATRIX[14] * b3) % len(ALPHABET)
    data[i + 3] = (HILL_CIPHER_MATRIX[3] * b0 + HILL_CIPHER_MATRIX[7] * b1 + HILL_CIPHER_MATRIX[11] * b2 + HILL_CIPHER_MATRIX[15] * b3) % len(ALPHABET)

def mixColumnsInverse(data):
  for i in range(0, 16, 4):
    b0 = data[i]
    b1 = data[i + 1]
    b2 = data[i + 2]
    b3 = data[i + 3]

    data[i]     = (HILL_CIPHER_MATRIX_INVERSE[0] * b0 + HILL_CIPHER_MATRIX_INVERSE[4] * b1 + HILL_CIPHER_MATRIX_INVERSE[8] * b2 + HILL_CIPHER_MATRIX_INVERSE[12] * b3) % len(ALPHABET)
    data[i + 1] = (HILL_CIPHER_MATRIX_INVERSE[1] * b0 + HILL_CIPHER_MATRIX_INVERSE[5] * b1 + HILL_CIPHER_MATRIX_INVERSE[9] * b2 + HILL_CIPHER_MATRIX_INVERSE[13] * b3) % len(ALPHABET)
    data[i + 2] = (HILL_CIPHER_MATRIX_INVERSE[2] * b0 + HILL_CIPHER_MATRIX_INVERSE[6] * b1 + HILL_CIPHER_MATRIX_INVERSE[10] * b2 + HILL_CIPHER_MATRIX_INVERSE[14] * b3) % len(ALPHABET)
    data[i + 3] = (HILL_CIPHER_MATRIX_INVERSE[3] * b0 + HILL_CIPHER_MATRIX_INVERSE[7] * b1 + HILL_CIPHER_MATRIX_INVERSE[11] * b2 + HILL_CIPHER_MATRIX_INVERSE[15] * b3) % len(ALPHABET)

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

  word.append(Mod(w1[0] + w2[0], len(ALPHABET)))
  word.append(Mod(w1[1] + w2[1], len(ALPHABET)))
  word.append(Mod(w1[2] + w2[2], len(ALPHABET)))
  word.append(Mod(w1[3] + w2[3], len(ALPHABET)))

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

    word.append(data[offset * 16])
    word.append(data[offset * 16 + 1])
    word.append(data[offset * 16 + 2])
    word.append(data[offset * 16 + 3])
    word.append(data[offset * 16 + 4])
    word.append(data[offset * 16 + 5])
    word.append(data[offset * 16 + 6])
    word.append(data[offset * 16 + 7])
    word.append(data[offset * 16 + 8])
    word.append(data[offset * 16 + 9])
    word.append(data[offset * 16 + 10])
    word.append(data[offset * 16 + 11])
    word.append(data[offset * 16 + 12])
    word.append(data[offset * 16 + 13])
    word.append(data[offset * 16 + 14])
    word.append(data[offset * 16 + 15])

    return word


  # key expansion => make multiple out of the given key
  roundKeys = keyExpansion(key, r + 1)
  # add 0 key
  addRoundKey(text, getRoundKey(roundKeys, 0))


  for i in range(1, r):
    subBigrams(text)
    shiftRows(text)
    mixColumns(text)
    addRoundKey(text, getRoundKey(roundKeys, i))

  # final round without mix columns
  subBigrams(text)
  shiftRows(text)
  addRoundKey(text, getRoundKey(roundKeys, r))

  return text

def decrypt(text, key, r):
  def getRoundKey(data, offset):
    word = []

    word.append(data[offset * 16 + 0])
    word.append(data[offset * 16 + 1])
    word.append(data[offset * 16 + 2])
    word.append(data[offset * 16 + 3])
    word.append(data[offset * 16 + 4])
    word.append(data[offset * 16 + 5])
    word.append(data[offset * 16 + 6])
    word.append(data[offset * 16 + 7])
    word.append(data[offset * 16 + 8])
    word.append(data[offset * 16 + 9])
    word.append(data[offset * 16 + 10])
    word.append(data[offset * 16 + 11])
    word.append(data[offset * 16 + 12])
    word.append(data[offset * 16 + 13])
    word.append(data[offset * 16 + 14])
    word.append(data[offset * 16 + 15])

    return word

  # key expansion => make multiple out of the given key
  roundKeys = keyExpansion(key, r + 1)

  # final round without mix columns
  subtractRoundKey(text, getRoundKey(roundKeys, r))
  shiftRowsInverse(text)
  subBigramsInverse(text)

  for i in range(r - 1, 0, -1):
    subtractRoundKey(text, getRoundKey(roundKeys, i))
    mixColumnsInverse(text)
    shiftRowsInverse(text)
    subBigramsInverse(text)

  # # subtract 0 key
  subtractRoundKey(text, getRoundKey(roundKeys, 0))

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

def unitTests():
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

  main();

sys.modules[__name__] = { encrypt, decrypt }
