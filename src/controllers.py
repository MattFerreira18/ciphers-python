from flask import render_template, redirect, url_for, request
from ciphers.aes import encryptECB as encryptAES
from ciphers.rsa.main import mensagemCifrada as encryptRSA
from utils import hasOnlyLetters

# TODO move to .env
AES_KEY = 'CFPLGAABCDEFMKOC'

def home():
    return render_template('index.html')

def encryption_result():
  try:
    plaintext = request.form.get('plaintext')

  # TODO fix regex
    if (not(plaintext) or not(hasOnlyLetters(plaintext))):
      return redirect(url_for('error_page'))

    aes_result = encryptAES(plaintext, AES_KEY)
    asymmetric_result = encryptRSA(plaintext)
    print(aes_result)

    return redirect(url_for('result', aes=aes_result, asymmetric=asymmetric_result))
  except:
    return redirect(url_for('error_page'))

def result():
  aes = request.args.get('aes')
  asymmetric = request.args.get('asymmetric')

  return render_template('encryption-result.html', aes=aes, asymmetric=asymmetric)


def error():
    return render_template('error.html')
