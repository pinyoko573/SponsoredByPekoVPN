from flask import Flask, render_template
from session import session_start

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

if __name__ == '__main__':
    app.run(port=5000, debug='true')