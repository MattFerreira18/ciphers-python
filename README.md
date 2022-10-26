## Ciphers in Python

(work in progress)

### Intro

(work in progress)

### How it works?

(work in progress)

#### Text-based AES Cipher

(work in progress)

#### Asymmetric Cipher

(work in progress)

### How to use it?

(work in progress)

#### Commands to run

(start server in dev mode)
flask --app src/app.py --debug run

python3 -m flask --app ./src/app.py --debug run

# TODO explanation

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
