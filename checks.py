from reader import load_file
from config import sensitive_ports,large_packet

# check_external_ip
def external_ip(data): # 'f' = file with list of lists
    ips = [lst[1] for lst in data if not lst[1].startswith("192.168") and not lst[1].startswith("10.")]
    return ips

def get_suspicious_lines(data):
    suspicious_lines = list(filter(lambda line: line[3] in sensitive_ports,data))
    return suspicious_lines

def get_lines_by_size(data):
    large_packets = list(filter(lambda line: int(line[-1])>large_packet, data))
    return large_packets

def get_traffic_labeling(data):
    labeled_packets =  [ line + ["LARGE"] if int(line[-1]) > large_packet else line + ["NORMAL"] for line in data]
    return labeled_packets



