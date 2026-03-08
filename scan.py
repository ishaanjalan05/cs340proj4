import json
import ipaddress
import http.client
import re
import socket
import ssl
import shutil
import subprocess
import sys
import time
import urllib.parse


DNS_TIMEOUT_SECONDS = 2
HTTP_TIMEOUT_SECONDS = 5
TLS_TIMEOUT_SECONDS = 5


def run_nslookup(domain, record_type):
    cmd = ["nslookup", domain]
    if record_type == "AAAA":
        cmd = ["nslookup", "-type=AAAA", domain]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DNS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""

    return (result.stdout or "") + "\n" + (result.stderr or "")


def lookup_dns(domain, record_type):
    addresses = set()
    print(f"  Querying {record_type}", file=sys.stderr)
    output = run_nslookup(domain, record_type)
    in_answer = False

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        lower = line.lower()
        tokens_to_check = []

        if "non-authoritative answer" in lower:
            in_answer = True
            continue

        if lower.startswith("name:"):
            in_answer = True
            continue

        if " has address " in lower:
            in_answer = True
            tokens_to_check.append(line.rsplit(" ", 1)[-1])
        elif " has aaaa address " in lower:
            in_answer = True
            tokens_to_check.append(line.rsplit(" ", 1)[-1])
        elif in_answer and lower.startswith("address:"):
            tokens_to_check.append(line.split(":", 1)[1].strip())
        elif in_answer and lower.startswith("addresses:"):
            tokens_to_check.extend(line.split(":", 1)[1].strip().split())
        elif in_answer:
            tokens_to_check.extend(line.split())
        else:
            continue

        for token in tokens_to_check:
            token = token.strip().strip(",;()[]")
            if "#53" in token:
                token = token.split("#", 1)[0]
            if not token:
                continue

            try:
                ip = ipaddress.ip_address(token)
            except ValueError:
                continue

            if record_type == "A" and ip.version == 4:
                addresses.add(str(ip))
            if record_type == "AAAA" and ip.version == 6:
                addresses.add(str(ip))

    return sorted(addresses)


def lookup_http_server(domain):
    for use_https in [True, False]:
        conn = None
        try:
            if use_https:
                conn = http.client.HTTPSConnection(domain, timeout=HTTP_TIMEOUT_SECONDS)
            else:
                conn = http.client.HTTPConnection(domain, timeout=HTTP_TIMEOUT_SECONDS)

            conn.request("GET", "/", headers={"Host": domain, "Connection": "close"})
            response = conn.getresponse()
            return response.getheader("Server")
        except Exception:
            continue
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    return None


def check_insecure_http(domain):
    sock = None
    try:
        sock = socket.create_connection((domain, 80), timeout=HTTP_TIMEOUT_SECONDS)
        return True
    except Exception:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def follow_redirect_chain(domain):
    current_url = f"http://{domain}/"

    for _ in range(10):
        parsed = urllib.parse.urlparse(current_url)
        if parsed.scheme not in ["http", "https"]:
            return None, None

        host = parsed.hostname
        if host is None:
            return None, None

        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        path = parsed.path if parsed.path else "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        conn = None
        try:
            if parsed.scheme == "https":
                conn = http.client.HTTPSConnection(
                    host,
                    port,
                    timeout=HTTP_TIMEOUT_SECONDS,
                    context=ssl._create_unverified_context(),
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=HTTP_TIMEOUT_SECONDS)

            print(f"    Redirect URL: {current_url}", file=sys.stderr)
            conn.request("HEAD", path, headers={"Connection": "close"})
            response = conn.getresponse()
            location = response.getheader("Location")
            hsts_header = response.getheader("Strict-Transport-Security")

            print(f"    Status: {response.status}", file=sys.stderr)
            print(f"    Location: {location}", file=sys.stderr)
            print(f"    Strict-Transport-Security: {hsts_header}", file=sys.stderr)

            if response.status in [301, 302, 303, 307, 308]:
                if not location:
                    return None, None
                current_url = urllib.parse.urljoin(current_url, location)
                continue

            return current_url, hsts_header
        except Exception as e:
            print(f"    Redirect chain error: {e}", file=sys.stderr)
            return None, None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    return None, None


def supports_tls_version(domain, flag):
    cmd = [
        "openssl",
        "s_client",
        flag,
        "-connect",
        f"{domain}:443",
        "-servername",
        domain,
    ]

    try:
        result = subprocess.run(
            cmd,
            input=b"",
            capture_output=True,
            timeout=TLS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

    output = (result.stdout + result.stderr).decode(errors="ignore")
    output_lower = output.lower()

    if "unknown option" in output_lower or "no protocols available" in output_lower:
        return False
    if "handshake failure" in output_lower or "wrong version number" in output_lower:
        return False
    if "no peer certificate available" in output_lower:
        return False
    if "cipher is (none)" in output_lower:
        return False

    return re.search(r"protocol\s*:\s*", output_lower) is not None


def lookup_tls_versions(domain):
    versions = []
    tests = [
        ("SSLv2", "-ssl2"),
        ("SSLv3", "-ssl3"),
        ("TLSv1.0", "-tls1"),
        ("TLSv1.1", "-tls1_1"),
        ("TLSv1.2", "-tls1_2"),
        ("TLSv1.3", "-tls1_3"),
    ]

    for version_name, flag in tests:
        if supports_tls_version(domain, flag):
            versions.append(version_name)

    return versions


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py [input_file.txt] [output_file.json]", file=sys.stderr)
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(input_file, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    nslookup_available = shutil.which("nslookup") is not None
    if not nslookup_available:
        print("Error: nslookup not found; skipping ipv4/ipv6 DNS scans.", file=sys.stderr)

    openssl_available = shutil.which("openssl") is not None
    if not openssl_available:
        print("Error: openssl not found; skipping tls_versions scan.", file=sys.stderr)

    results = {}
    for domain in domains:
        if domain in results:
            continue

        domain_start = time.time()
        print(f"Scanning domain: {domain}", file=sys.stderr)

        domain_result = {
            "scan_time": time.time()
        }
        if nslookup_available:
            start_a = time.time()
            domain_result["ipv4_addresses"] = lookup_dns(domain, "A")
            print(
                f"  Finished A lookup for {domain} in {time.time() - start_a:.2f} seconds",
                file=sys.stderr,
            )

            start_aaaa = time.time()
            domain_result["ipv6_addresses"] = lookup_dns(domain, "AAAA")
            print(
                f"  Finished AAAA lookup for {domain} in {time.time() - start_aaaa:.2f} seconds",
                file=sys.stderr,
            )

        start_http = time.time()
        print("  Querying HTTP Server header", file=sys.stderr)
        domain_result["http_server"] = lookup_http_server(domain)
        print(
            f"  Finished HTTP server lookup for {domain} in {time.time() - start_http:.2f} seconds",
            file=sys.stderr,
        )

        start_insecure = time.time()
        print("  Checking insecure HTTP on port 80", file=sys.stderr)
        domain_result["insecure_http"] = check_insecure_http(domain)
        print(
            f"  Finished insecure HTTP check for {domain} in {time.time() - start_insecure:.2f} seconds",
            file=sys.stderr,
        )

        start_redirect = time.time()
        print("  Checking redirect to HTTPS", file=sys.stderr)
        final_url = None
        final_hsts_header = None
        if domain_result["insecure_http"]:
            final_url, final_hsts_header = follow_redirect_chain(domain)
            if final_url is not None and urllib.parse.urlparse(final_url).scheme == "https":
                domain_result["redirect_to_https"] = True
            else:
                domain_result["redirect_to_https"] = False
        else:
            domain_result["redirect_to_https"] = False
        print(
            f"  Finished redirect check for {domain} in {time.time() - start_redirect:.2f} seconds",
            file=sys.stderr,
        )

        start_hsts = time.time()
        print("  Checking HSTS", file=sys.stderr)
        if (
            final_url is not None
            and urllib.parse.urlparse(final_url).scheme == "https"
            and final_hsts_header is not None
        ):
            domain_result["hsts"] = True
        else:
            domain_result["hsts"] = False
        print(
            f"  Finished HSTS check for {domain} in {time.time() - start_hsts:.2f} seconds",
            file=sys.stderr,
        )

        if openssl_available:
            start_tls = time.time()
            print("  Checking TLS versions", file=sys.stderr)
            domain_result["tls_versions"] = lookup_tls_versions(domain)
            print(
                f"  Finished TLS version scan for {domain} in {time.time() - start_tls:.2f} seconds",
                file=sys.stderr,
            )

        results[domain] = domain_result
        print(
            f"Finished domain {domain} in {time.time() - domain_start:.2f} seconds",
            file=sys.stderr,
        )

    with open(output_file, "w") as f:
        json.dump(results, f, sort_keys=True, indent=4)


if __name__ == "__main__":
    main()
