import csv
import re
from collections import Counter

logfile = "sample.log"

ip_counter = Counter()
status_counter = Counter()
alerts = []

pattern = r'(\d+\.\d+\.\d+\.\d+).*"(GET|POST) (.*?) HTTP.*" (\d+)'

with open(logfile, 'r') as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            method = match.group(2)
            path = match.group(3)
            status = match.group(4)

            ip_counter[ip] += 1
            status_counter[status] += 1

            # rule 1: admin failures
            if path == "/admin" and status == "403":
                alerts.append([ip, "failed admin login"])

            # rule 2: sensitive path
            if path in ["/phpmyadmin", "/admin", "/login"]:
                alerts.append([ip, f"sensitive path accessed: {path}"])

# rule 3: too many requests
for ip, count in ip_counter.items():
    if count >= 3:
        alerts.append([ip, "high request volume"])

# print report
print("=== top IPs ===")
for ip, count in ip_counter.most_common():
    print(ip, count)

print("\n=== status codes ===")
for code, count in status_counter.items():
    print(code, count)

print("\n=== alerts ===")
for a in alerts:
    print(a)

# save alerts to csv
with open("alerts.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["IP", "Alert"])
    writer.writerows(alerts) 