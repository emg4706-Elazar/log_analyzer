from reader import load_file

# check_external_ip
def external_ip(f): # 'f' = file with list of lists
    ips = [lst[1] for lst in f if not lst[1].startswith("192.168") and not lst[1].startswith("10.")]
    return ips

