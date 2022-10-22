
import controllers

from flask import Flask

app = Flask(__name__)


@app.route('/', methods=['GET'])
def main():
    return controllers.home()


@app.route('/result', methods=['GET'])
@app.route('/result/<encryption>', methods=['GET'])
def result_page(encryption=None):
    return controllers.result(encryption)


@app.route('/500', methods=['GET'])
def error_page():
    return controllers.error()
