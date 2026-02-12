


def count_requests(data):
    ips = [line[1] for line in data]
    list_requests = {ip: ips.count(ip) for ip in set(ips) }
    return list_requests

def protokol_by_port(data):
    all_ports = [[line[3],line[4]] for line in data]
    dict_port = { port[0]: port[1] for port in all_ports }
    return dict_port