from reader import load_file
from config import sensitive_ports,large_packet
from analyzer import count_requests

# check_external_ip
def get_external_ip(data): # 'f' = file with list of lists
    ips = [lst[1] for lst in data if not lst[1].startswith("192.168") and not lst[1].startswith("10.")]
    return ips

def get_sensitive_port_traffic(data):
    suspicious_lines = list(filter(lambda line: line[3] in sensitive_ports,data))
    return suspicious_lines

def get_large_packets(data):
    large_packets = list(filter(lambda line: int(line[-1])>large_packet, data))
    return large_packets

def get_traffic_labeling(data):
    labeled_packets =  [ line + ["LARGE"] if int(line[-1]) > large_packet else line + ["NORMAL"] for line in data]
    return labeled_packets

def night_activity(data):
    get_time = lambda n: n[0].strip().split()
    night_packets = filter(lambda line: "00"<= (get_time(line)[1].split(":")[0])<"06" , data)
    return list(night_packets)

suspicion_checks = {
    "EXTERNAL_IP": lambda row: not row[1].startswith("192.168") and not row[1].startswith("10."),
    "NIGHT_ACTIVITY": lambda row: "00"<=row[0].strip().split()[1].split(":")[0]<"06",
    "SENSITIVE_PORT": lambda row: row[3] in sensitive_ports,
    "LARGE PACKET": lambda row: int(row[5])>large_packet
    }

def flag_suspicious_row(row, checks: dict):
    lst = list(filter(lambda sus: checks[sus](row),checks))
    return lst


file_as_lists = load_file("network_traffic.log")

# process log , return iterator points on 'file_as_list' with flags
processed_log1 = map(lambda row: flag_suspicious_row(row, suspicion_checks), file_as_lists)

# filter log for getting log only with suspicious
processed_log2 = list(filter(lambda row: row, processed_log1))



