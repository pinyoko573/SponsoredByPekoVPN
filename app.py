from flask import Flask, jsonify, redirect, render_template, request, url_for, flash
from werkzeug.utils import secure_filename
from packet import decap
from session import get_is_active, get_session_list, session_erase, session_start, get_ap_list, get_client_list, force_eapol_handshake, session_stop, session_upload_create, session_upload_decrypt
from pstatistics import get_arp_list, get_clients, get_dns_list, get_protocol_list, get_timestamp_list, get_website_list
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
        # Check if any other session is active
        if get_is_active():
            flash(messages.session_is_active, 'failed')
            return redirect(url_for('session'))
        else:
            return render_template('session/session_create.html')
    elif request.method == 'POST':
        # Received data: passphrase, apInfo
        apInfo = request.form.get('apInfo')
        passphrase = request.form.get('passphrase')

        # Calls session start
        session_id = session_start(apInfo, passphrase)

        if(session_id != -1):
            # Stores information to database and redirect to modify page
            flash(messages.session_create_success, 'success')
            return redirect(url_for('session_modify', session_id = session_id))

@app.route('/session/upload', methods=['GET', 'POST'])
def session_upload():
    if request.method == 'GET':
        return render_template('session/session_upload.html')
    elif request.method == 'POST':
        try:
            # Received data: essid, passphrase, authentication and a file
            essid = request.form.get('essid')
            passphrase = request.form.get('passphrase')
            authentication = request.form.get('authentication')

            # Generate session_id with information on top
            session_id = session_upload_create(essid, passphrase, authentication)
            
            # Get file and save, then decrypt file and scan all mac addresses
            file = request.files['file']
            filename = 'session-{}.cap'.format(session_id)
            file.save(secure_filename(filename))
            session_upload_decrypt(session_id, essid, passphrase)

            # Finally, decrypt all the packets
            decap(session_id)
        except Exception as e:
            print(e)
            flash(messages.session_upload_failed, 'error')
        else:
            flash(messages.session_upload_success, 'success')

        return redirect(url_for('session'))

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

@app.route('/session/delete', methods=['POST'])
def session_delete():
    session_id = request.headers.get('session_id')
    output = session_erase(session_id)
    if output == True:
        return jsonify({'output': True, 'message': messages.session_delete_success})
    else:
        return jsonify({'output': False, 'message': messages.session_delete_failed})

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

@app.route('/packet/summary', defaults={'session_id': None})
@app.route('/packet/summary/<session_id>')
def packet_summary(session_id):
    return render_template('packet/summary.html', session_id=session_id)

@app.route('/packet/website', defaults={'session_id': None})
@app.route('/packet/website/<session_id>')
def packet_website(session_id):
    return render_template('packet/website.html', session_id=session_id)

@app.route('/packet/arp', defaults={'session_id': None})
@app.route('/packet/arp/<session_id>')
def packet_arp(session_id):
    return render_template('packet/arp.html', session_id=session_id)

@app.route('/packet/dns', defaults={'session_id': None})
@app.route('/packet/dns/<session_id>')
def packet_dns(session_id):
    return render_template('packet/dns.html', session_id=session_id)

@app.route('/statistics/get_protocol')
def statistics_get_protocol():
    session_id = request.args.get('session_id')
    return jsonify(get_protocol_list(session_id))

@app.route('/statistics/get_timestamp')
def statistics_get_timestamp():
    session_id = request.args.get('session_id')
    return jsonify(get_timestamp_list(session_id))

@app.route('/statistics/get_clients')
def statistics_get_clients():
    session_id = request.args.get('session_id')
    return jsonify(get_clients(session_id))

@app.route('/statistics/get_websites')
def statistics_get_websites():
    session_id = request.args.get('session_id')
    return jsonify(get_website_list(session_id))

@app.route('/statistics/get_arps')
def statistics_get_arps():
    session_id = request.args.get('session_id')
    return jsonify(get_arp_list(session_id))

@app.route('/statistics/get_dnss')
def statistics_get_dnss():
    session_id = request.args.get('session_id')
    return jsonify(get_dns_list(session_id))

if __name__ == '__main__':
    app.secret_key = '12345'
    app.run(port=5000, debug='true')