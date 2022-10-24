from flask import render_template, redirect, url_for, request
from utils import isEncryptionAllowed, hasOnlyLetters, isAESKeyLengthValid


def home():
    return render_template('index.html')


def result(encryption):
  try:
    data = request.get_json()
    plaintext = data['plaintext']
    key = data['key']

    if (not (encryption) or not (isEncryptionAllowed(encryption))):
        raise Exception('invalid encryption method')

    if (not(plaintext) or not(key)):
        raise Exception('fields can be filled')

    if (encryption == 'aes'):
      if (not(isAESKeyLengthValid(key)) or not(hasOnlyLetters(plaintext)) or not(hasOnlyLetters(key))):
        raise Exception('invalid fields')

      # TODO realize AES cryptograph
    else:
      # TODO realize Asymmetric cryptograph
      print()

    return render_template('encryption-result.html', encryption=encryption.upper())
  except:
    return redirect(url_for('error_page'))


def error():
    return render_template('error.html')
