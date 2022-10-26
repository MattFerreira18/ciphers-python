
import controllers

from flask import Flask

app = Flask(__name__)


@app.route('/', methods=['GET'])
def home():
  return controllers.home()

@app.route('/result', methods=['GET'])
def result():
  return controllers.result()

@app.route('/encryption-result', methods=['POST'])
def encryption_result():
  return controllers.encryption_result()


@app.route('/500', methods=['GET'])
def error_page():
  return controllers.error()
