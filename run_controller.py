#!/usr/bin/env python3

import subprocess

if __name__ == "__main__":
    s3 = subprocess.Popen('python3 mycontroller.py 2 127.0.0.1:50053'.split())
    try:
        s3.wait()
    except KeyboardInterrupt:
        s3.terminate()