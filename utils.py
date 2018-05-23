import signal
import sys

def register_atexit():
    signal.signal(signal.SIGINT, atexit)

def atexit(*_):
        sys.exit(0)

class timeout:
    def __init__(self, seconds):
        self.seconds = seconds

    def __enter__(self):
        try:
            signal.signal(signal.SIGALRM, self.on_alarm)
        except ValueError:
            sys.exit("Could not set an alarm")  # sigalrm is unix-only
        signal.alarm(self.seconds)

    def __exit__(self, *_):
        signal.alarm(0)  # 0 cancels any alarms previously set

    def on_alarm(self, *_):
        raise TimeoutError()  # catch this when parsing
