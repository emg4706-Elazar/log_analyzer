from reader import load_file
from config import sensitive_ports

# check_external_ip
def external_ip(f): # 'f' = file with list of lists
    ips = [lst[1] for lst in f if not lst[1].startswith("192.168") and not lst[1].startswith("10.")]
    return ips

def get_suspicious_lines(f):
    suspicious_lines = [line for line in f if line[3] in sensitive_ports]
    return suspicious_lines

