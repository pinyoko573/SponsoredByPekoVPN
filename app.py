from flask import Flask, jsonify, redirect, render_template, request, url_for, flash
from session import session_start, get_ap_list, get_client_list, force_eapol_handshake

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
        # Stores information to database and redirect to modify page
        return redirect(url_for('session_modify', session_id = 1))

@app.route('/session/modify/<session_id>', methods=['GET', 'POST'])
def session_modify(session_id):
    if request.method == 'GET':
        return render_template('session/session_modify.html', session_id=session_id)
    elif request.method == 'POST':
        return jsonify(force_eapol_handshake(request.headers['client_mac'], request.headers['ap_mac']))

@app.route('/session/get_ap')
def session_get_ap():
    return jsonify(get_ap_list())

@app.route('/session/get_client')
def session_get_client():
    ap_mac = request.args.get('mac')
    return jsonify(get_client_list(ap_mac))

if __name__ == '__main__':
    app.secret_key = '12345'
    app.run(port=5000, debug='true')