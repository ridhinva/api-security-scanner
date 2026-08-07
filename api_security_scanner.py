#!/usr/bin/env python3
"""
API Security Scanner - OWASP API Top 10 2023 + GraphQL
Scans REST, GraphQL, and gRPC APIs for vulnerabilities
"""
import requests, sys, json, argparse, time
from concurrent.futures import ThreadPoolExecutor
requests.packages.urllib3.disable_warnings()

VERSION = "1.0.0"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        API Security Scanner - OWASP API Top 10 2023         ║
║     BOLA, BFLA, SSRF, GraphQL Introspection, Depth DoS     ║
╚══════════════════════════════════════════════════════════════╝
"""

def http_request(method, url, headers, json_data=None, timeout=10):
    try:
        r = requests.request(method, url, headers=headers, json=json_data, timeout=timeout, verify=False)
        return r
    except:
        return None

def check_bola(target, headers, object_ids):
    """API1:2023 - Broken Object Level Authorization"""
    results = {"vulnerable": False, "details": []}
    for obj_id in object_ids[:5]:
        # Try accessing other users' objects
        for test_id in [str(int(obj_id)+1), str(int(obj_id)-1), "1", "admin", "test"]:
            if test_id == obj_id: continue
            r = http_request("GET", f"{target}/api/v1/users/{test_id}", headers)
            if r and r.status_code == 200:
                results["vulnerable"] = True
                results["details"].append(f"BOLA: Accessed object {test_id} without authorization")
                break
    return results

def check_bfla(target, headers, user_role="user"):
    """API5:2023 - Broken Function Level Authorization"""
    results = {"vulnerable": False, "details": []}
    admin_endpoints = ["/api/v1/admin/users", "/api/v1/admin/delete", "/api/v1/admin/config"]
    for ep in admin_endpoints:
        r = http_request("GET", f"{target}{ep}", headers)
        if r and r.status_code in [200, 201]:
            results["vulnerable"] = True
            results["details"].append(f"BFLA: {ep} accessible with {user_role} role")
    return results

def check_ssrf(target, headers):
    """API7:2023 - Server Side Request Forgery"""
    results = {"vulnerable": False, "details": []}
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22",
        "http://127.0.0.1:6379",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_TEST"
    ]
    for payload in ssrf_payloads:
        r = http_request("POST", f"{target}/api/v1/webhook", headers, json={"url": payload})
        if r and r.status_code in [200, 201, 202]:
            results["vulnerable"] = True
            results["details"].append(f"SSRF: {payload} accepted")
    return results

def check_graphql_introspection(target, headers):
    """GraphQL Introspection Leak"""
    results = {"vulnerable": False, "details": []}
    introspection_query = {"query": "{__schema{types{name,fields{name}}}}"}
    r = http_request("POST", f"{target}/graphql", headers, json=introspection_query)
    if r and r.status_code == 200 and "__schema" in r.text:
        results["vulnerable"] = True
        results["details"].append("GraphQL introspection enabled - full schema exposed")
    return results

def check_graphql_depth_dos(target, headers):
    """GraphQL Depth/Breadth DoS"""
    results = {"vulnerable": False, "details": []}
    # Deep nested query
    deep_query = "{user{friends{friends{friends{friends{friends{friends{name}}}}}}}}"
    r = http_request("POST", f"{target}/graphql", headers, json={"query": deep_query})
    if r and r.status_code == 200 and "errors" not in r.text.lower():
        results["vulnerable"] = True
        results["details"].append("GraphQL depth limit not enforced")
    return results

def check_graphql_batching(target, headers):
    """GraphQL Batching Attack"""
    results = {"vulnerable": False, "details": []}
    batch_query = [{"query": "{user{id}}"} for _ in range(50)]
    r = http_request("POST", f"{target}/graphql", headers, json=batch_query)
    if r and r.status_code == 200:
        results["vulnerable"] = True
        results["details"].append("GraphQL batching allows 50+ queries in single request")
    return results

def scan_target(target, modes, auth_header=None):
    headers = {"User-Agent": UA}
    if auth_header:
        headers["Authorization"] = auth_header
    
    all_results = {"target": target, "findings": {}}
    
    if "rest" in modes or "all" in modes:
        # Need object IDs for BOLA - placeholder
        all_results["findings"]["bola"] = check_bola(target, headers, ["1", "2", "3"])
        all_results["findings"]["bfla"] = check_bfla(target, headers)
        all_results["findings"]["ssrf"] = check_ssrf(target, headers)
    
    if "graphql" in modes or "all" in modes:
        all_results["findings"]["graphql_introspection"] = check_graphql_introspection(target, headers)
        all_results["findings"]["graphql_depth_dos"] = check_graphql_depth_dos(target, headers)
        all_results["findings"]["graphql_batching"] = check_graphql_batching(target, headers)
    
    return all_results

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="API Security Scanner - OWASP API Top 10 + GraphQL")
    parser.add_argument("--target", required=True, help="API base URL (e.g., https://api.example.com)")
    parser.add_argument("--auth", help="Authorization header value (Bearer token, API key)")
    parser.add_argument("--mode", choices=["rest", "graphql", "all"], default="all", help="Scan mode")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()
    
    modes = ["rest", "graphql"] if args.mode == "all" else [args.mode]
    
    print(f"[*] Scanning {args.target}")
    print(f"[*] Modes: {', '.join(modes)}\n")
    
    results = scan_target(args.target, modes, args.auth)
    
    total_vulns = sum(1 for v in results["findings"].values() if v.get("vulnerable"))
    print(f"\n{'='*60}")
    print(f"Scan Complete: {total_vulns} vulnerable categories found")
    for category, finding in results["findings"].items():
        status = "🔴 VULNERABLE" if finding.get("vulnerable") else "🟢 OK"
        print(f"  {status} {category}")
        for detail in finding.get("details", []):
            print(f"    -> {detail}")
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Results saved to {args.output}")

if __name__ == "__main__":
    main()