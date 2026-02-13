from reader import load_file
from config import sensitive_ports,large_packet


def count_requests(data):
    ips = [line[1] for line in data]
    list_requests = {ip: ips.count(ip) for ip in set(ips) }
    return list_requests

def protocol_by_port(data):
    all_ports = [[line[3],line[4]] for line in data]
    dict_port = { port[0]: port[1] for port in all_ports }
    return dict_port

# return dict with list suspicious flags
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
        if int(line[-1]) > large_packet:
            dicti[line[1]].append("LARGE_PACKET")
        if not dicti[line[1]]:
            dicti[line[1]].append(None)
    return dicti