
import main

from flask import Flask

app = Flask(__name__)


@app.route('/', methods=['GET'])
def main():
  return main.home()

@app.route('/result', methods=['GET'])
def result():
  return main.result()

@app.route('/encryption-result', methods=['POST'])
def encryption_result():
  return main.encryption_result()


@app.route('/500', methods=['GET'])
def error_page():
  return main.error()
