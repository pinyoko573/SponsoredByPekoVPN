from flask import Flask, jsonify, render_template
from session import session_start, get_ap_list
import subprocess

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/session')
def session():
    return render_template('session.html')

@app.route('/session/start')
def session_start_api():
    session_start()
    return '', 200

@app.route('/session/get_ap')
def session_get_ap():
    return jsonify(get_ap_list())

if __name__ == '__main__':
    app.run(port=5000, debug='true')