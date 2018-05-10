import signal
import sys


class timeout:
    def __init__(self, seconds):
        self.seconds = seconds

    def __enter__(self):
        try:
            signal.signal(signal.SIGALRM, self.onAlarm)
        except ValueError:
            sys.exit("Could not set an alarm")  # sigalrm is unix-only
        signal.alarm(self.seconds)

    def __exit__(self, *_):
        signal.alarm(0)  # 0 cancels any alarms previously set

    def onAlarm(self, *_):
        raise TimeoutError()  # catch this when parsing
