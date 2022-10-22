'''
  # Steps of original AES
      PlainText
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
    - **ShiftRows** - (bitwase operation)
    - **MixColumns** - 
    - **Round** - 
    - **Key Expansion** - 

  # Steps of this implementation of text-based AES
      PlainText
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
def main():
  example = 'Hello World'
  hashed = 'Hello World'
  decrypted = 'Hello World'

  print('original  - ', example)
  print('hashed    - ', hashed)
  print('decrypted - ', decrypted)

main()
