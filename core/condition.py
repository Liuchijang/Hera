import socket
import ctypes

def is_admin():
        try:
                return ctypes.windll.shell32.IsUserAnAdmin()
        except:
                return False
        
def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result == 0 