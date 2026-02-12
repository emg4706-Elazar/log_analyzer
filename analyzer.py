


def count_requests(data):
    ips = [line[1] for line in data]
    list_requests = {ip: ips.count(ip) for ip in set(ips) }
    return list_requests