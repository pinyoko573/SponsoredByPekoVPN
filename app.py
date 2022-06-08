from flask import Flask, jsonify, redirect, render_template, request, url_for, flash
from session import get_session_list, session_start, get_ap_list, get_client_list, force_eapol_handshake, session_stop
import messages

from models import *
from database import engine, Base

# Only use this when you want to generate database!
# Base.metadata.create_all(bind=engine)

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/session')
def session():
    return render_template('session/session_index.html')

@app.route('/session/create', methods=['GET', 'POST'])
def session_create():
    if request.method == 'GET':
        return render_template('session/session_create.html')
    elif request.method == 'POST':
        # Received headers: passphrase, apInfo
        apInfo = request.form.get('apInfo')
        passphrase = request.form.get('passphrase')

        # Calls session start
        session_id = session_start(apInfo, passphrase)

        if(session_id != -1):
            # Stores information to database and redirect to modify page
            flash(messages.session_create_success, 'success')
            return redirect(url_for('session_modify', session_id = session_id))

@app.route('/session/stop', methods=['POST'])
def session_end():
    # Received headers: session_id
    session_id = request.headers.get('session_id')
    output = session_stop(session_id)
    if output == True:
        return jsonify({'output': True, 'message': messages.session_stop_success})
    else:
        return jsonify({'output': False, 'message': messages.session_stop_failed})
    
@app.route('/session/modify/<session_id>', methods=['GET', 'POST'])
def session_modify(session_id):
    if request.method == 'GET':
        return render_template('session/session_modify.html', session_id=session_id)
    elif request.method == 'POST':
        output = force_eapol_handshake(session_id, request.headers['client_data'])
        if output == True:
            return jsonify({'output': True, 'message': messages.handshake_success})
        else:
            return jsonify({'output': False, 'message': messages.handshake_failed})

@app.route('/session/get_session')
def session_get_session():
    return jsonify(get_session_list())

@app.route('/session/get_ap')
def session_get_ap():
    return jsonify(get_ap_list())

@app.route('/session/get_client')
def session_get_client():
    session_id = request.args.get('session_id')
    return jsonify(get_client_list(session_id))

if __name__ == '__main__':
    app.secret_key = '12345'
    app.run(port=5000, debug='true')