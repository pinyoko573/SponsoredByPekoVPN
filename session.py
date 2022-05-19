import subprocess

def session_start():
    test = subprocess.Popen('ls')
    # test.terminate()