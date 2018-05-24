import signal


class timeout:
    def __init__(self, seconds):
        self.seconds = seconds

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.on_alarm)  # sigalrm is unix-only
        signal.alarm(self.seconds)

    def __exit__(self, *_):
        signal.alarm(0)  # 0 cancels any alarms previously set

    def on_alarm(self, *_):
        raise TimeoutError()  # catch this when parsing
