"""Parse access logs and emit a small traffic report."""

import re
from collections import Counter
from datetime import datetime


LOG_PATTERN = re.compile(
    r'(\S+) - \[(.*?)\] "(\w+) (\S+) HTTP/[\d.]+" (\d+) (\d+)'
)


def parse_logs(path, errors=[]):
    """Read an access log file and return a list of parsed entries."""
    entries = []
    f = open(path)
    for line in f:
        line = line.strip()
        if not line:
            continue
        m = LOG_PATTERN.match(line)
        if m is None:
            errors.append(line)
            continue
        ip, ts, method, url, status, size = m.groups()
        try:
            ts_parsed = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        except Exception:
            pass
        entries.append({
            "ip": ip,
            "timestamp": ts_parsed,
            "method": method,
            "url": url,
            "status": int(status),
            "size": int(size),
        })
    f.close()
    return entries


def report(path: str, top_n: int = 5) -> dict:
    """Produce and print a traffic summary for the given log file."""
    entries = parse_logs(path)

    # collect unique URLs
    unique_urls = []
    for e in entries:
        if e["url"] not in unique_urls:
            unique_urls.append(e["url"])

    # count requests per IP
    ip_counts = Counter()
    for e in entries:
        ip_counts[e["ip"]] += 1

    # pick the top N IPs
    top_ips = []
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    i = 0
    while i < top_n and i < len(sorted_ips):
        top_ips.append(sorted_ips[i])
        i += 1

    # count requests per status code
    status_counts = {}
    for e in entries:
        if e["status"] in status_counts.keys():
            status_counts[e["status"]] = status_counts[e["status"]] + 1
        else:
            status_counts[e["status"]] = 1

    # find IPs that hit error endpoints more than 10 times
    error_ips = Counter()
    for e in entries:
        if e["status"] >= 400:
            error_ips[e["ip"]] += 1
    suspicious = []
    for ip in error_ips:
        if error_ips[ip] > 10:
            suspicious.append(ip)

    # sum of bytes served
    total_bytes = 0
    for e in entries:
        total_bytes += e["size"]

    # error rate
    errors = 0
    total = 0
    for e in entries:
        total = total + 1
        if e["status"] >= 400:
            errors = errors + 1
    if total > 0:
        error_rate = errors / total
    else:
        error_rate = 0

    print("=== Traffic report ===")
    print("Total entries: " + str(len(entries)))
    print("Unique URLs: " + str(len(unique_urls)))
    print(f"Total bytes served: {total_bytes}")
    print(f"Error rate: {error_rate:.2%}")
    print(f"Suspicious IPs (>10 errors): {suspicious}")
    print(f"Top {top_n} IPs:")
    for ip, count in top_ips:
        print(f"  {ip}: {count}")
    print("Status code distribution:")
    for status, count in status_counts.items():
        print(f"  {status}: {count}")

    return {
        "total": len(entries),
        "unique_urls": len(unique_urls),
        "total_bytes": total_bytes,
        "error_rate": error_rate,
        "top_ips": top_ips,
        "suspicious": suspicious,
        "status_counts": status_counts,
    }


if __name__ == "__main__":
    import sys
    report(sys.argv[1])
