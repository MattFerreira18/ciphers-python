from flask import render_template, redirect, url_for
from utils import isEncryptionAllowed


def home():
    return render_template('index.html')


def result(encryption):
    if (not (encryption) or not (isEncryptionAllowed(encryption))):
        return redirect(url_for('error_page'))

    return render_template('encryption-result.html', encryption=encryption)


def error():
    return render_template('error.html')
