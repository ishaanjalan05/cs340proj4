import json
import sys
from collections import Counter


PART2_KEY_ORDER = [
    "scan_time",
    "ipv4_addresses",
    "ipv6_addresses",
    "http_server",
    "insecure_http",
    "redirect_to_https",
    "hsts",
    "tls_versions",
    "root_ca",
    "rdns_names",
    "rtt_range",
    "geo_locations",
]

TLS_VERSION_ORDER = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]


def format_value(value):
    return json.dumps(value, sort_keys=True)


def make_table(headers, rows):
    str_rows = [[str(cell) for cell in row] for row in rows]
    widths = []
    for i, header in enumerate(headers):
        col_values = [header]
        col_values.extend(row[i] for row in str_rows)
        widths.append(max(len(v) for v in col_values))

    border = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    header_line = "| " + " | ".join(headers[i].ljust(widths[i]) for i in range(len(headers))) + " |"

    lines = [border, header_line, border]
    for row in str_rows:
        lines.append("| " + " | ".join(row[i].ljust(widths[i]) for i in range(len(headers))) + " |")
    lines.append(border)
    return "\n".join(lines)


def build_domain_sections(scan_data):
    lines = []
    for domain in sorted(scan_data.keys()):
        result = scan_data[domain]
        lines.append(f"Domain: {domain}")
        lines.append("-" * (8 + len(domain)))

        keys = []
        for key in PART2_KEY_ORDER:
            if key in result:
                keys.append(key)
        for key in sorted(result.keys()):
            if key not in keys:
                keys.append(key)

        for key in keys:
            lines.append(f"{key}: {format_value(result[key])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_rtt_table(scan_data):
    rows = []
    for domain, result in scan_data.items():
        rtt = result.get("rtt_range")
        if isinstance(rtt, list) and len(rtt) == 2:
            rows.append((domain, rtt[0], rtt[1]))

    rows.sort(key=lambda x: (x[1], x[2], x[0]))
    table_rows = [[domain, rtt_min, rtt_max] for domain, rtt_min, rtt_max in rows]
    return make_table(["Domain", "RTT Min (ms)", "RTT Max (ms)"], table_rows)


def build_counter_table(scan_data, key_name, title_name):
    counter = Counter()
    for result in scan_data.values():
        value = result.get(key_name)
        if value is not None:
            counter[value] += 1

    rows = sorted(counter.items(), key=lambda x: (-x[1], x[0]))
    table_rows = [[name, count] for name, count in rows]
    return make_table([title_name, "Count"], table_rows)


def supports_feature(result, feature):
    if feature in TLS_VERSION_ORDER:
        versions = result.get("tls_versions")
        return isinstance(versions, list) and feature in versions
    if feature == "plain http":
        return result.get("insecure_http") is True
    if feature == "https redirect":
        return result.get("redirect_to_https") is True
    if feature == "hsts":
        return result.get("hsts") is True
    if feature == "ipv6":
        ipv6 = result.get("ipv6_addresses")
        return isinstance(ipv6, list) and len(ipv6) > 0
    return False


def build_percentage_table(scan_data):
    total = len(scan_data)
    features = TLS_VERSION_ORDER + ["plain http", "https redirect", "hsts", "ipv6"]
    rows = []
    for feature in features:
        supported_count = sum(1 for result in scan_data.values() if supports_feature(result, feature))
        percent = 0.0 if total == 0 else (100.0 * supported_count / total)
        rows.append([feature, supported_count, f"{percent:.1f}%"])
    return make_table(["Feature", "Supported Domains", "Percent"], rows)


def build_report(scan_data):
    sections = []
    sections.append("Network Scan Report")
    sections.append("===================")
    sections.append("")
    sections.append("Per-Domain Scan Results")
    sections.append("-----------------------")
    sections.append(build_domain_sections(scan_data))

    sections.append("RTT Ranges (Fastest to Slowest)")
    sections.append("-------------------------------")
    sections.append(build_rtt_table(scan_data))
    sections.append("")

    sections.append("Root Certificate Authority Popularity")
    sections.append("-------------------------------------")
    sections.append(build_counter_table(scan_data, "root_ca", "Root CA"))
    sections.append("")

    sections.append("HTTP Server Popularity")
    sections.append("----------------------")
    sections.append(build_counter_table(scan_data, "http_server", "HTTP Server"))
    sections.append("")

    sections.append("Security Feature Support")
    sections.append("------------------------")
    sections.append(build_percentage_table(scan_data))
    sections.append("")

    return "\n".join(sections)


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 report.py [input_file.json] [output_file.txt]", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r") as f:
        scan_data = json.load(f)

    report_text = build_report(scan_data)
    with open(output_file, "w") as f:
        f.write(report_text)


if __name__ == "__main__":
    main()
