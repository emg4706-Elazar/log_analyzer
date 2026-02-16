from reader import load_file
from config import sensitive_ports,large_packet

# returns dict with number of requests by ip
def count_requests(data):
    ips = [line[1] for line in data]
    num_requests_ip = {ip: ips.count(ip) for ip in set(ips) }
    return num_requests_ip

def protocol_by_port(data):
    all_ports = [[line[3],line[4]] for line in data]
    dict_port = { port[0]: port[1] for port in all_ports }
    return dict_port

# returns dict with list suspicious flags
def flag_suspicious_ips(data):
    dicti = {}
    for line in data:
        dicti[line[1]] = []
        # check night activity
        hour = line[0][11] + line[0][12]
        if "00" <= hour <"06":
            dicti[line[1]].append("NIGHT_ACTIVITY")
        # check external ip
        if not line[1].startswith("192.168") and not line[1].startswith("10."):
            dicti[line[1]].append("EXTERNAL_IP")
        # check sensitive_port
        if line[3] in sensitive_ports:
            dicti[line[1]].append("SENSITIVE_PORT")
        # check large packet
        if int(line[-1]) > large_packet:
            dicti[line[1]].append("LARGE_PACKET")
    return dicti

# returns in dict only ip addresses with 2 or more suspicious
def filter_suspicious_ips(data):
    dicti_ips = flag_suspicious_ips(data)
    dicti_after = {}
    for ip in dicti_ips:
        if len(dicti_ips[ip]) >= 2:
            dicti_after[ip] = dicti_ips[ip]
    return dicti_after