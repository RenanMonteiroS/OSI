from flask import current_app
import time, threading, sys, os
def restartSystem(**kwargs):
    time.sleep(5)
    runFile = os.path.join(kwargs.get('rootPath'), '..', 'run.py')
    os.system(f"{sys.executable} {runFile}")
            
restartSystemThread = threading.Thread(target=restartSystem, kwargs={'rootPath': current_app.config["ROOT_PATH"]})