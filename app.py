from flask import Flask, jsonify, render_template, request
from session import session_start, get_ap_list, get_client_list

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
        print(request.data)

# @app.route('/session/start')
# def session_start_api():
#     session_start()
#     return '', 200

@app.route('/session/get_ap')
def session_get_ap():
    return jsonify(get_ap_list())

@app.route('/session/get_client')
def session_get_client():
    ap_mac = request.args.get('mac')
    return jsonify(get_client_list(ap_mac))

if __name__ == '__main__':
    app.run(port=5000, debug='true')