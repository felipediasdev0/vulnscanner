import asyncio
import json
import ssl
import subprocess
import time
from dataclasses import dataclass, asdict
from typing import List, Optional

import aiohttp
from bs4 import BeautifulSoup
from yarl import URL

#Payloads 

SQLI_PAYLOADS_ERROR_BASED = [
    "' OR '1'='1", "' OR 1=1 -- ", "\" OR \"1\"=\"1\""
]

SQLI_PAYLOADS_TIME_BASED = [
    "' OR IF(1=1, SLEEP(5), 0) -- ",
    "'; WAITFOR DELAY '0:0:5'--"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]

LDAP_INJECTION_PAYLOADS = [
    "*)(|(objectclass=*",
]

SSRF_TEST_URL = "http://your-callback.example.com/"

WEAK_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("root", "root"), ("test", "test"),
    ("user", "user"), ("guest", "guest"), ("admin", "123456")
]

CSRF_TOKEN_NAMES = ["csrf_token", "csrfmiddlewaretoken", "token", "_token"]

SENSITIVE_FILES = [
    ".env", ".git/config", "backup.zip", "config.php.bak", "id_rsa", "id_dsa"
]

COMMON_PATHS = [
    "/admin", "/login", "/wp-login.php", "/.git/", "/backup.zip", "/.env"
]

#Data classes

@dataclass
class Finding:
    target: str
    category: str
    name: str
    severity: str
    detail: str
    evidence: Optional[str] = None

@dataclass
class Report:
    started_at: float
    finished_at: Optional[float]
    findings: List[Finding]

    def to_json(self):
        return json.dumps({
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "findings": [asdict(f) for f in self.findings],
        }, indent=2)

#

def is_url_https(url: str) -> bool:
    return url.lower().startswith("https://")

def normalize_url(url: str) -> str:
    parsed = URL(url)
    if not parsed.scheme:
        parsed = parsed.with_scheme("http")
    return str(parsed)

def extract_forms(html: str) -> List[BeautifulSoup]:
    soup = BeautifulSoup(html, "html.parser")
    return soup.find_all("form")

def extract_form_fields(form) -> List[str]:
    fields = set()
    for inp in form.find_all(["input", "textarea", "select"]):
        if inp.get("name"):
            fields.add(inp.get("name"))
    return list(fields)

async def fetch(session: aiohttp.ClientSession, method: str, url: str, **kwargs):
    try:
        async with session.request(method, url, **kwargs) as resp:
            text = await resp.text()
            return resp, text
    except Exception as e:
        return None, str(e)

# ----------------------------- Checks -----------------------------

async def check_security_headers(session: aiohttp.ClientSession, url: str) -> List[Finding]:
    findings = []
    try:
        async with session.get(url, timeout=20, ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            required = {
                "content-security-policy": "Content-Security-Policy",
                "x-content-type-options": "X-Content-Type-Options",
                "x-frame-options": "X-Frame-Options",
                "strict-transport-security": "Strict-Transport-Security",
                "referrer-policy": "Referrer-Policy",
                "permissions-policy": "Permissions-Policy",
                "feature-policy": "Feature-Policy",  # deprecated mas ainda usado
            }
            missing = [v for k, v in required.items() if k not in headers]
            if missing:
                findings.append(Finding(
                    target=url,
                    category="A05-Security Misconfiguration",
                    name="Missing security headers",
                    severity="Medium",
                    detail=f"Missing headers: {', '.join(missing)}",
                    evidence=json.dumps(dict(resp.headers))
                ))
            # Detectar headers que expõem info sensível
            if "server" in headers:
                findings.append(Finding(
                    target=url,
                    category="Information Disclosure",
                    name="Server header exposed",
                    severity="Low",
                    detail=f"Server header reveals: {headers['server']}"
                ))
            if "x-powered-by" in headers:
                findings.append(Finding(
                    target=url,
                    category="Information Disclosure",
                    name="X-Powered-By header exposed",
                    severity="Low",
                    detail=f"X-Powered-By reveals: {headers['x-powered-by']}"
                ))
    except Exception as e:
        findings.append(Finding(
            target=url,
            category="A05-Security Misconfiguration",
            name="Header check failed",
            severity="Info",
            detail=str(e)
        ))
    return findings

async def check_csrf_protection(session: aiohttp.ClientSession, url: str) -> List[Finding]:
    findings = []
    try:
        resp, text = await fetch(session, "GET", url, timeout=20, ssl=False)
        if resp is None:
            return findings
        forms = extract_forms(text)
        for form in forms:
            inputs = extract_form_fields(form)
            if not any(token in inputs for token in CSRF_TOKEN_NAMES):
                findings.append(Finding(
                    target=url,
                    category="A08-Data Integrity",
                    name="Form missing CSRF token",
                    severity="Medium",
                    detail="Form does not contain CSRF token fields, possible CSRF vulnerability."
                ))
    except Exception:
        pass
    return findings

async def check_tls(url: str) -> List[Finding]:
    findings = []
    if not is_url_https(url):
        findings.append(Finding(
            target=url,
            category="A02-Cryptographic Failures",
            name="No HTTPS",
            severity="High",
            detail="Target does not use HTTPS."
        ))
        return findings
    try:
        hostname = url.split("//", 1)[1].split("/", 1)[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(ssl.SSLSocket(), server_hostname=hostname):
            pass
    except Exception:
        findings.append(Finding(
            target=url,
            category="A02-Cryptographic Failures",
            name="TLS handshake issue or version unknown",
            severity="Medium",
            detail="Handshake check failed or requires deeper analysis (use testssl.sh)."
        ))
    return findings

async def test_sqli(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []

    base_url = normalize_url(base_url)

    try:
        resp, text = await fetch(session, "GET", base_url, timeout=20, ssl=False)
        if resp is None:
            return findings
        soup = BeautifulSoup(text, "html.parser")
        params = set()
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "textarea", "select"]):
                if inp.get("name"):
                    params.add(inp.get("name"))
        parsed_url = URL(base_url)
        for k in parsed_url.query.keys():
            params.add(k)

        if not params:
            return findings

        # Error-based SQLi
        for p in params:
            for payload in SQLI_PAYLOADS_ERROR_BASED:
                try:
                    params_dict = {p: payload}
                    r2, rtxt = await fetch(session, "GET", base_url, params=params_dict, timeout=15, ssl=False)
                    if r2 is None:
                        continue
                    low = rtxt.lower()
                    if any(x in low for x in ['sql syntax', 'mysql', 'syntax error', 'sqlstate']):
                        findings.append(Finding(
                            target=base_url,
                            category="A03-Injection",
                            name="SQL Injection (error-based)",
                            severity="High",
                            detail=f"Parameter: {p} payload: {payload}",
                            evidence=rtxt[:200]
                        ))
                except Exception:
                    continue

        # Time-based Blind SQLi
        for p in params:
            for payload in SQLI_PAYLOADS_TIME_BASED:
                try:
                    params_dict = {p: payload}
                    start = time.time()
                    r2, _ = await fetch(session, "GET", base_url, params=params_dict, timeout=20, ssl=False)
                    if r2 is None:
                        continue
                    elapsed = time.time() - start
                    if elapsed > 4:
                        findings.append(Finding(
                            target=base_url,
                            category="A03-Injection",
                            name="SQL Injection (time-based blind)",
                            severity="High",
                            detail=f"Parameter: {p} payload: {payload}",
                            evidence=f"Response delay of {elapsed:.2f}s detected"
                        ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings

async def test_xss(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    base_url = normalize_url(base_url)
    try:
        resp, text = await fetch(session, "GET", base_url, timeout=20, ssl=False)
        if resp is None:
            return findings
        soup = BeautifulSoup(text, "html.parser")
        params = set()
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "textarea"]):
                if inp.get("name"):
                    params.add(inp.get("name"))
        parsed_url = URL(base_url)
        for k in parsed_url.query.keys():
            params.add(k)

        if not params:
            return findings

        for p in params:
            for payload in XSS_PAYLOADS:
                try:
                    params_dict = {p: payload}
                    r2, rtxt = await fetch(session, "GET", base_url, params=params_dict, timeout=15, ssl=False)
                    if r2 is None:
                        continue
                    if payload in rtxt:
                        findings.append(Finding(
                            target=base_url,
                            category="A03-Injection",
                            name="Reflected XSS",
                            severity="High",
                            detail=f"Parameter: {p} payload: {payload}",
                            evidence=rtxt[:200]
                        ))
                except Exception:
                    continue

        # Teste XSS via User-Agent header
        for payload in XSS_PAYLOADS:
            try:
                headers = {"User-Agent": payload}
                r2, rtxt = await fetch(session, "GET", base_url, headers=headers, timeout=15, ssl=False)
                if r2 is None:
                    continue
                if payload in rtxt:
                    findings.append(Finding(
                        target=base_url,
                        category="A03-Injection",
                        name="Reflected XSS via User-Agent header",
                        severity="High",
                        detail=f"Payload: {payload}",
                        evidence=rtxt[:200]
                    ))
            except Exception:
                continue

    except Exception:
        pass
    return findings

async def test_ssrf(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    if SSRF_TEST_URL.startswith("http://your-callback"):
        return findings
    base_url = normalize_url(base_url)
    try:
        resp, text = await fetch(session, "GET", base_url, timeout=20, ssl=False)
        if resp is None:
            return findings
        soup = BeautifulSoup(text, "html.parser")
        params = set()
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "textarea"]):
                if inp.get("name"):
                    params.add(inp.get("name"))
        parsed_url = URL(base_url)
        for k in parsed_url.query.keys():
            params.add(k)

        for p in params:
            try:
                params_dict = {p: SSRF_TEST_URL}
                await session.get(base_url, params=params_dict, timeout=15, ssl=False)
            except Exception:
                continue

        findings.append(Finding(
            target=base_url,
            category="A10-SSRF",
            name="SSRF test executed (external verification needed)",
            severity="Medium",
            detail=f"Sent {SSRF_TEST_URL} to params: {list(params)}. Verifique seu servidor callback."
        ))
    except Exception:
        pass
    return findings

async def check_outdated_components(base_url: str) -> List[Finding]:
    findings = []
    try:
        proc = subprocess.run(["nuclei", "-u", base_url, "-silent"], capture_output=True, text=True, timeout=120)
        out = proc.stdout.strip()
        if out:
            findings.append(Finding(
                target=base_url,
                category="A06-Vulnerable Components",
                name="Nuclei findings",
                severity="Medium",
                detail=out[:1000]
            ))
    except FileNotFoundError:
        findings.append(Finding(
            target=base_url,
            category="A06-Vulnerable Components",
            name="Nuclei not installed",
            severity="Info",
            detail="Instale o ProjectDiscovery nuclei para checagens mais profundas."
        ))
    except subprocess.TimeoutExpired:
        findings.append(Finding(
            target=base_url,
            category="A06-Vulnerable Components",
            name="Nuclei timeout",
            severity="Info",
            detail="Nuclei demorou demais para este alvo."
        ))
    except Exception as e:
        findings.append(Finding(
            target=base_url,
            category="A06-Vulnerable Components",
            name="Nuclei execution error",
            severity="Info",
            detail=str(e)
        ))
    return findings

async def test_weak_auth(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    base_url = normalize_url(base_url)
    try:
        candidates = [base_url.rstrip('/') + p for p in COMMON_PATHS]
        for target in candidates:
            try:
                async with session.get(target, timeout=15, ssl=False) as resp:
                    if resp.status in (200, 401, 302):
                        for user, pwd in WEAK_CREDS:
                            try:
                                async with session.get(target, auth=aiohttp.BasicAuth(user, pwd), timeout=10, ssl=False) as r2:
                                    if r2.status == 200:
                                        findings.append(Finding(
                                            target=target,
                                            category="A07-Authentication",
                                            name="Weak credential succeeded",
                                            severity="High",
                                            detail=f"{user}:{pwd} allowed on {target}"
                                        ))
                            except Exception:
                                continue
            except Exception:
                continue
    except Exception:
        pass
    return findings

async def test_ldap_injection(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    base_url = normalize_url(base_url)
    try:
        resp, text = await fetch(session, "GET", base_url, timeout=20, ssl=False)
        if resp is None:
            return findings
        soup = BeautifulSoup(text, "html.parser")
        params = set()
        for form in soup.find_all("form"):
            for inp in form.find_all(["input", "textarea"]):
                if inp.get("name"):
                    params.add(inp.get("name"))
        parsed_url = URL(base_url)
        for k in parsed_url.query.keys():
            params.add(k)
        if not params:
            return findings
        for p in params:
            for payload in LDAP_INJECTION_PAYLOADS:
                try:
                    params_dict = {p: payload}
                    r2, rtxt = await fetch(session, "GET", base_url, params=params_dict, timeout=15, ssl=False)
                    if r2 is None:
                        continue
                    low = rtxt.lower()
                    if any(x in low for x in ['ldap', 'invalid filter', 'error']):
                        findings.append(Finding(
                            target=base_url,
                            category="Injection",
                            name="LDAP Injection",
                            severity="High",
                            detail=f"Parameter: {p} payload: {payload}",
                            evidence=rtxt[:200]
                        ))
                except Exception:
                    continue
    except Exception:
        pass
    return findings

async def test_deserialization(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    base_url = normalize_url(base_url)
    try:
        resp, text = await fetch(session, "GET", base_url, timeout=20, ssl=False)
        if resp is None:
            return findings
        keywords = ["deserialize", "pickle", "unmarshal", "marshal", "object injection"]
        if any(k in text.lower() for k in keywords):
            findings.append(Finding(
                target=base_url,
                category="Code Injection",
                name="Potential unsafe deserialization",
                severity="Medium",
                detail="Response contains keywords related to unsafe deserialization; manual review needed."
            ))
    except Exception:
        pass
    return findings

async def test_sensitive_files(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    base_url = normalize_url(base_url)
    try:
        for f in SENSITIVE_FILES:
            url = base_url.rstrip("/") + "/" + f
            try:
                async with session.get(url, timeout=10, ssl=False) as resp:
                    if resp.status == 200:
                        findings.append(Finding(
                            target=url,
                            category="Information Disclosure",
                            name="Sensitive file accessible",
                            severity="High",
                            detail=f"File {f} is publicly accessible at {url}."
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings

async def test_upload_points(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    try:
        resp, text = await fetch(session, "GET", base_url, timeout=20, ssl=False)
        if resp is None:
            return findings
        soup = BeautifulSoup(text, "html.parser")
        forms = extract_forms(text)
        for form in forms:
            inputs = extract_form_fields(form)
            if any("file" in f.lower() for f in inputs):
                findings.append(Finding(
                    target=base_url,
                    category="A08-Data Integrity",
                    name="Potential file upload form",
                    severity="Medium",
                    detail="Form contains file upload field; verificar validação e sanitização."
                ))
        # Keywords no corpo
        if any(k in text.lower() for k in ["upload", "file upload", "choose file"]):
            findings.append(Finding(
                target=base_url,
                category="A08-Data Integrity",
                name="Upload-related keywords found",
                severity="Low",
                detail="Texto da página contém palavras relacionadas a upload; revisar manualmente."
            ))
    except Exception:
        pass
    return findings

async def check_dependency_injection_points(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    try:
        resp, text = await fetch(session, "GET", base_url, timeout=20, ssl=False)
        if resp is None:
            return findings
        if any(keyword in text.lower() for keyword in ['update', 'upload', 'deserialize']):
            findings.append(Finding(
                target=base_url,
                category="A08-Data Integrity",
                name="Potential update/upload endpoints",
                severity="Medium",
                detail="Encontradas palavras como upload/update/deserialize na resposta; revisar manualmente."
            ))
    except Exception:
        pass
    return findings

async def check_logging_and_monitoring(session: aiohttp.ClientSession, base_url: str) -> List[Finding]:
    findings = []
    findings.append(Finding(
        target=base_url,
        category="A09-Logging & Monitoring",
        name="Automated check limitation",
        severity="Info",
        detail="Detecção automática de logging/monitoramento é limitada — revisão manual necessária."
    ))
    return findings

# ----------------------------- Orchestration -----------------------------

async def scan_target(sem: asyncio.Semaphore, url: str) -> List[Finding]:
    async with sem:
        findings = []
        timeout = aiohttp.ClientTimeout(total=60)
        conn = aiohttp.TCPConnector(limit_per_host=8, ssl=False)
        async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
            tasks = [
                check_security_headers(session, url),
                check_csrf_protection(session, url),
                test_sqli(session, url),
                test_xss(session, url),
                test_ssrf(session, url),
                test_weak_auth(session, url),
                test_ldap_injection(session, url),
                test_deserialization(session, url),
                test_sensitive_files(session, url),
                test_upload_points(session, url),
                check_dependency_injection_points(session, url),
                check_logging_and_monitoring(session, url),
            ]
            results = await asyncio.gather(*tasks)
            for r in results:
                findings.extend(r)
            findings.extend(await check_tls(url))
            findings.extend(await check_outdated_components(url))
            return findings

async def run_scan(targets: List[str], concurrency: int = 5) -> Report:
    started = time.time()
    sem = asyncio.Semaphore(concurrency)
    findings = []
    tasks = [scan_target(sem, normalize_url(t)) for t in targets]
    all_results = await asyncio.gather(*tasks)
    for res in all_results:
        findings.extend(res)
    finished = time.time()
    return Report(started_at=started, finished_at=finished, findings=findings)
