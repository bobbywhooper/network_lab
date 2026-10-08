""""
events = [
    {
        "src_ip": "10.0.0.50",
        "dst_ip": "10.0.0.10",
        "dst_port": 22
    },
    {
        "src_ip": "10.0.0.50",
        "dst_ip": "10.0.0.11",
        "dst_port": 22
    },
    {
        "src_ip": "10.0.0.50",
        "dst_ip": "10.0.0.12",
        "dst_port": 22
    },
    {
        "src_ip": "10.0.0.8",
        "dst_ip": "10.0.0.20",
        "dst_port": 443
    }
]

connection_count = {}
destinations = {}

for event in events:
    src_ip = event["src_ip"]
    dst_ip = event["dst_ip"]

    connection_count[src_ip] = connection_count.get(src_ip, 0) + 1

    if src_ip not in destinations:
        destinations[src_ip] = set()
    destinations[src_ip].add(dst_ip)

threshold = 5
for src_ip, dst_ips in destinations.items():
    unique_dst = len(dst_ips)
    if unique_dst >= threshold:
        print(
            f"Possible scanning activity: "
            f"{src_ip} contacted {unique_dst} unique destinations"
        )
"""""

events = [
    {"time": 1,  "src_ip": "10.0.0.50", "dst_ip": "10.0.0.10", "dst_port": 22},
    {"time": 2,  "src_ip": "10.0.0.50", "dst_ip": "10.0.0.11", "dst_port": 22},
    {"time": 3,  "src_ip": "10.0.0.8",  "dst_ip": "10.0.0.20", "dst_port": 443},
    {"time": 3,  "src_ip": "10.0.0.50", "dst_ip": "10.0.0.12", "dst_port": 22},
    {"time": 4,  "src_ip": "10.0.0.50", "dst_ip": "10.0.0.13", "dst_port": 22},
    {"time": 5,  "src_ip": "10.0.0.50", "dst_ip": "10.0.0.14", "dst_port": 22},
    {"time": 20, "src_ip": "10.0.0.50", "dst_ip": "10.0.0.30", "dst_port": 22},
]

activity = {}

for event in events:
    src_ip = event["src_ip"]
    timestamp = event["time"]

    if src_ip not in activity:
        activity[src_ip] = [] 

    activity[src_ip].append(timestamp)