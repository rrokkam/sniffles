import signal
import sys

from datetime import datetime
import calendar

def raw_socket(interface, bind_addr=0):
    socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                    socket.ntohs(0x0003))  # all packets
    socket.bind((interface, bind_addr))
    return socket

def current_time():
    return calendar.timegm(datetime.now().timetuple()) * 10**6  # microseconds to seconds

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