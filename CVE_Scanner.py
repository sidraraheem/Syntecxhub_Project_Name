import requests
import time

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def build_cpe(product, version):
    """
    Convert product name to simple CPE format.
    Example: Apache HTTP Server -> apache:http_server
    """
    vendor = product.split()[0].lower()
    product_name = product.lower().replace(" ", "_")

    cpe = f"cpe:2.3:a:{vendor}:{product_name}:{version}:*:*:*:*:*:*:*"
    return cpe


def search_cves(product, version):

    cpe = build_cpe(product, version)

    params = {
        "cpeName": cpe,
        "resultsPerPage": 10
    }

    try:
        response = requests.get(NVD_API_URL, params=params, timeout=10)

        if response.status_code == 200:
            return response.json()

        else:
            print(f"[!] API Error: {response.status_code}")
            return {}

    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return {}


def parse_cve_results(data):

    results = []

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")

        description = ""
        if cve.get("descriptions"):
            description = cve["descriptions"][0].get("value", "")

        # default values in case metrics are missing or incomplete
        severity = "Unknown"
        score = "N/A"

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
            score = cvss.get("baseScore", "N/A")
            severity = cvss.get("baseSeverity", "Unknown")
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0].get("cvssData", {})
            score = cvss.get("baseScore", "N/A")
            severity = cvss.get("baseSeverity", "Unknown")

        # add to results regardless of which metric was used
        results.append((cve_id, severity, score, description))

    return results


def main():

    print("=== CVE Vulnerability Scanner ===")

    product = input("Enter software/product name: ").strip()
    version = input("Enter version number: ").strip()

    print(f"\nScanning {product} {version}...\n")

    data = search_cves(product, version)
    cves = parse_cve_results(data)

    if cves:

        for cve_id, severity, score, desc in cves:

            print("--------------------------------------------------")
            print(f"CVE ID   : {cve_id}")
            print(f"Severity : {severity}")
            print(f"CVSS     : {score}")
            print(f"Details  : {desc[:200]}...")
            print("--------------------------------------------------")

    else:
        print("No CVEs found.")

        time.sleep(1.5)


if __name__ == "__main__":
    main()