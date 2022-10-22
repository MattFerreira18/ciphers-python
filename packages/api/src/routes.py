import app
from flask import Flask, render_template, redirect, url_for


@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')


def isEncryptionAllowed(name):
    return name in ['aes', 'asymmetric']


@app.route('/result', methods=['GET'])
@app.route('/result/<encryption>', methods=['GET'])
def encryption_result(encryption=None):
    print(encryption, isEncryptionAllowed(encryption))
    if (not (encryption) or not (isEncryptionAllowed(encryption))):
        return redirect(url_for('error_page'))

    return render_template('encryption-result.html', encryption=encryption)


@app.route('/500', methods=['GET'])
def error_page():
    return render_template('error.html')
