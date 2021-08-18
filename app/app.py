# app.py

import os
import logging

from flask import Flask

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

logging.basicConfig(level=LOG_LEVEL)

app = Flask(__name__)

@app.route('/')
def hello_world():
    logging.debug('YES !')
    return 'Hello super world!'

if __name__ == '__main__':
    app.run(debug=(LOG_LEVEL == "DEBUG"))