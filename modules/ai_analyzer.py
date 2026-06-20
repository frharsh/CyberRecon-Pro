"""
CyberRecon Pro - AI Security Analysis Module
Rule-based analysis engine for ports, services, technologies, and subdomains.
Provides risk scoring and actionable remediation advice.
"""

# ─── Port Risk Database ────────────────────────────────────────────────────────
PORT_ANALYSIS = {
    21:   ('Critical', 'FTP (File Transfer Protocol)', 'FTP transmits data in plaintext. Anonymous login may be enabled. Replace with SFTP/SCP. Check for CVE-2011-2523 (vsftpd backdoor).'),
    22:   ('Medium',   'SSH (Secure Shell)', 'SSH detected. Ensure root login is disabled (`PermitRootLogin no`), enforce key-based authentication, and restrict access via AllowUsers. Check for outdated OpenSSH versions.'),
    23:   ('Critical', 'Telnet', 'Telnet transmits all data including credentials in cleartext. Immediately replace with SSH. This service should never be exposed publicly.'),
    25:   ('High',     'SMTP (Mail Server)', 'SMTP server exposed. Check for open relay configuration which allows spam abuse. Ensure authentication is required. Verify SPF/DKIM/DMARC records.'),
    53:   ('Low',      'DNS (Domain Name System)', 'DNS service detected. Check for zone transfer vulnerabilities (AXFR). Ensure recursive queries are restricted to authorized clients.'),
    80:   ('Low',      'HTTP (Web Server)', 'Unencrypted HTTP detected. Force redirect to HTTPS. Check web server version for known CVEs. Look for sensitive files (/.git, /backup, /admin).'),
    110:  ('Medium',   'POP3 (Email)', 'POP3 email server detected. Ensure TLS is enforced (POP3S on 995). Credentials may be transmitted in plaintext.'),
    135:  ('High',     'Microsoft RPC (MSRPC)', 'Windows RPC endpoint mapper exposed. Associated with multiple high-severity vulnerabilities (MS03-026, EternalBlue chain). Restrict access via firewall.'),
    139:  ('High',     'NetBIOS Session Service', 'NetBIOS detected. Can enable SMB attacks, null session enumeration, and information leakage. Block from internet access.'),
    143:  ('Medium',   'IMAP (Email)', 'IMAP email server detected. Ensure IMAPS (port 993) is used instead. Check for credential brute-force exposure.'),
    443:  ('Info',     'HTTPS (Encrypted Web)', 'HTTPS detected. Check TLS version (ensure TLS 1.2+ only). Verify certificate validity, scan for misconfigurations with testssl.sh.'),
    445:  ('Critical', 'SMB (Windows File Sharing)', 'SMB directly exposed to internet. Extremely dangerous — vector for EternalBlue (MS17-010), WannaCry ransomware, and NotPetya. Block port 445 from internet immediately.'),
    1433: ('Critical', 'Microsoft SQL Server', 'MSSQL database exposed to internet. Should never be publicly accessible. Enforce strong SA password. Check for CVE-2020-0618.'),
    1521: ('Critical', 'Oracle Database', 'Oracle DB listener exposed. Check for default credentials (scott/tiger). Restrict to private network only.'),
    2375: ('Critical', 'Docker API (Unauthenticated)', 'Docker daemon API exposed without TLS. Full host compromise possible — attacker can spawn privileged containers. Close immediately.'),
    2376: ('High',     'Docker API (TLS)', 'Docker daemon with TLS. Verify client certificate authentication is enforced.'),
    3000: ('Medium',   'Development Server / Grafana', 'Common development port. May expose Grafana (check for CVE-2021-43798 path traversal) or Node.js app.'),
    3306: ('Critical', 'MySQL Database', 'MySQL exposed publicly. Databases should never be internet-facing. Restrict to localhost or private network. Change default root password. Review user privileges.'),
    3389: ('Critical', 'RDP (Remote Desktop Protocol)', 'RDP exposed to internet. High-value target — vulnerable to BlueKeep (CVE-2019-0708), DejaBlue, credential brute-force. Restrict with firewall, use NLA, enable MFA.'),
    4444: ('Critical', 'Metasploit Default Port', 'Port 4444 is Metasploit\'s default handler port. May indicate active compromise or pentesting framework.'),
    5432: ('Critical', 'PostgreSQL Database', 'PostgreSQL exposed publicly. Restrict to private network. Review pg_hba.conf for proper access controls.'),
    5900: ('High',     'VNC (Virtual Network Computing)', 'VNC server exposed. Often has weak/no authentication. Provides graphical desktop access. Restrict access immediately.'),
    5985: ('High',     'WinRM HTTP (Windows Remote Mgmt)', 'Windows Remote Management over HTTP. Can be used for remote PowerShell execution. Restrict to management networks.'),
    5986: ('High',     'WinRM HTTPS', 'WinRM over HTTPS detected. Verify certificate and access controls.'),
    6379: ('Critical', 'Redis (In-Memory Database)', 'Redis exposed without authentication. Full data exfiltration possible. Redis < 6.0 has no auth by default. Check CVE-2022-0543 for Lua sandbox escape.'),
    8080: ('Low',      'HTTP Alternate / Proxy', 'Alternative HTTP port. May expose admin panels, proxy servers, or development applications. Check for unauthorized services.'),
    8443: ('Low',      'HTTPS Alternate', 'Alternative HTTPS port. Check TLS configuration and exposed applications.'),
    8888: ('Medium',   'Jupyter Notebook', 'Jupyter Notebook commonly runs on 8888. If exposed, may allow arbitrary code execution. Ensure password/token authentication is set.'),
    9200: ('Critical', 'Elasticsearch', 'Elasticsearch HTTP API exposed. By default has no authentication (pre-6.8). Full data access possible. Apply X-Pack security or equivalent.'),
    27017:('Critical', 'MongoDB', 'MongoDB exposed publicly. No authentication enabled by default in older versions. Resulted in mass data breaches. Enable authentication and restrict to private network.'),
}

# ─── Technology Risk Database ───────────────────────────────────────────────────
TECH_ANALYSIS = {
    'wordpress': ('Medium', 'WordPress CMS detected. Check for outdated plugins/themes (most common attack vector). Run WPScan for detailed vulnerability assessment.'),
    'joomla':    ('Medium', 'Joomla CMS detected. Verify all extensions are updated. Check for SQL injection in core components.'),
    'drupal':    ('Medium', 'Drupal CMS detected. Check for Drupalgeddon vulnerabilities (CVE-2018-7600, CVE-2018-7602).'),
    'apache':    ('Low',    'Apache HTTP Server detected. Verify version and check for module-specific CVEs. Disable directory listing.'),
    'nginx':     ('Low',    'Nginx web server detected. Check for path traversal (CVE-2009-3898) in older versions. Review proxy configuration.'),
    'iis':       ('Medium', 'Microsoft IIS detected. Check for short filename enumeration vulnerability. Verify ASP.NET security headers.'),
    'php':       ('Low',    'PHP detected. Check version — PHP < 8.0 may have known vulnerabilities. Review exposed phpinfo() pages.'),
    'tomcat':    ('High',   'Apache Tomcat detected. Check for manager interface exposure with default credentials (admin/tomcat). CVE-2020-1938 (Ghostcat) if < 9.0.31.'),
    'jquery':    ('Low',    'jQuery detected. Ensure version ≥ 3.5.0 to avoid XSS vulnerabilities.'),
    'react':     ('Info',   'React.js frontend detected. Check for client-side security misconfigurations.'),
    'laravel':   ('Medium', 'Laravel framework detected. Check for debug mode enabled (exposes .env file contents). CVE-2021-3129 if < 8.4.3.'),
    'flask':     ('Low',    'Flask framework detected. Ensure DEBUG=False in production.'),
    'django':    ('Low',    'Django framework detected. Verify SECRET_KEY is not hardcoded. Ensure DEBUG=False.'),
    'spring':    ('High',   'Spring framework detected. Check for Spring4Shell (CVE-2022-22965) and Log4Shell if Log4j is used.'),
    'struts':    ('Critical','Apache Struts detected. Historically vulnerable to critical RCE (CVE-2017-5638, Equifax breach vector). Ensure latest version.'),
    'openssl':   ('Medium', 'OpenSSL detected. Verify version for Heartbleed (CVE-2014-0160) and recent OpenSSL CVEs.'),
}

# ─── Subdomain Risk Patterns ────────────────────────────────────────────────────
SUBDOMAIN_PATTERNS = {
    'admin':      ('High',   'Admin subdomain exposed. May expose administrative interfaces. Verify strong authentication and access controls.'),
    'vpn':        ('Medium', 'VPN gateway detected. Verify up-to-date firmware for CVEs (Pulse Secure, Fortinet, Citrix vulnerabilities).'),
    'mail':       ('Low',    'Mail server subdomain. Check SPF/DKIM/DMARC configuration and SMTP relay settings.'),
    'webmail':    ('Medium', 'Webmail interface detected. Assess for authentication brute-force and credential exposure.'),
    'staging':    ('High',   'Staging environment exposed. Often less hardened than production. May expose debug modes, verbose errors, or test credentials.'),
    'dev':        ('High',   'Development environment exposed publicly. Likely contains debug information, unpatched vulnerabilities, or test credentials.'),
    'test':       ('High',   'Test environment exposed. Same risks as dev — may have weaker security controls.'),
    'beta':       ('Medium', 'Beta environment detected. May have incomplete security controls.'),
    'api':        ('Medium', 'API subdomain detected. Test for authentication, authorization, and rate limiting issues.'),
    'jenkins':    ('Critical','Jenkins CI/CD server detected. Check for unauthenticated access (CVE-2018-1000861) and script console exposure.'),
    'gitlab':     ('High',   'GitLab instance detected. Check for CVE-2021-22205 (RCE) and exposed repositories.'),
    'jira':       ('Medium', 'Jira project management detected. Check for information disclosure in public boards.'),
    'confluence':  ('High',  'Confluence detected. Check for CVE-2022-26134 (critical RCE via OGNL injection).'),
    'kibana':     ('High',   'Kibana detected. Often exposes Elasticsearch data. Verify authentication is configured.'),
    'grafana':    ('High',   'Grafana detected. Check for CVE-2021-43798 (path traversal allowing credential reading).'),
    'backup':     ('Critical','Backup subdomain detected. Potential exposure of backup files and sensitive data.'),
    'old':        ('High',   'Legacy/old subdomain detected. Likely running outdated software with unpatched vulnerabilities.'),
    'ftp':        ('High',   'FTP subdomain detected. Verify encryption and disable anonymous access.'),
    'ssh':        ('Medium', 'SSH subdomain detected. Restrict access to known IPs.'),
    'db':         ('Critical','Database subdomain exposed. Should never be internet-facing.'),
    'mysql':      ('Critical','MySQL subdomain exposed. Restrict immediately.'),
    'phpmyadmin': ('Critical','phpMyAdmin interface exposed. Common target for brute-force and known CVEs. Restrict access.'),
}

# ─── DNS Record Analysis ────────────────────────────────────────────────────────
DNS_ANALYSIS = {
    'MX': ('Low',  'Mail exchange records found. Verify DMARC/DKIM/SPF for email security.'),
    'TXT': ('Info','TXT records may reveal SPF, DKIM, Google verification, or other configuration details.'),
    'AXFR': ('Critical', 'Zone transfer (AXFR) allowed! This exposes your entire DNS zone to any requester. Restrict AXFR to authorized secondary nameservers only.'),
    'NS': ('Low',  'Nameserver records. Verify no subdomain takeover risk via dangling NS records.'),
    'CNAME': ('Low','CNAME records present. Check for subdomain takeover if pointing to external services.'),
}


def analyze_results(result: dict) -> tuple:
    """
    Analyze a scan result and return (ai_analysis, risk_level).
    result must have 'type' key.
    """
    rtype = result.get('type', '').lower()

    if rtype == 'port':
        return _analyze_port(result)
    elif rtype == 'subdomain':
        return _analyze_subdomain(result)
    elif rtype == 'tech':
        return _analyze_tech(result)
    elif rtype == 'dns':
        return _analyze_dns(result)
    elif rtype == 'whois':
        return _analyze_whois(result)
    elif rtype == 'directory':
        return _analyze_directory(result)
    else:
        return ('No specific analysis available for this finding type.', 'informational')


def _analyze_port(result: dict) -> tuple:
    port    = int(result.get('port', 0))
    service = result.get('service', '').lower()
    version = result.get('version', '')

    if port in PORT_ANALYSIS:
        risk, svc_name, analysis = PORT_ANALYSIS[port]
        if version:
            analysis += f' Detected version: {version}. Check for known CVEs for this specific version.'
        return (analysis, risk.lower())

    # Unknown port heuristics
    if 'http' in service:
        return ('HTTP service on non-standard port. Investigate exposed web application.', 'low')
    if 'ssh' in service:
        return ('SSH on non-standard port. Verify version and access controls.', 'medium')
    if 'ftp' in service:
        return ('FTP on non-standard port. Ensure encryption and disable anonymous login.', 'high')

    return (f'Service "{service}" detected on port {port}. Manual investigation recommended.', 'informational')


def _analyze_subdomain(result: dict) -> tuple:
    subdomain = result.get('subdomain', result.get('value', '')).lower()
    for keyword, (risk, analysis) in SUBDOMAIN_PATTERNS.items():
        if keyword in subdomain:
            return (analysis, risk.lower())
    return (
        f'Subdomain {subdomain} discovered. Enumerate further for exposed services, admin panels, or outdated software.',
        'informational'
    )


def _analyze_tech(result: dict) -> tuple:
    tech = result.get('technology', result.get('name', '')).lower()
    for key, (risk, analysis) in TECH_ANALYSIS.items():
        if key in tech:
            return (analysis, risk.lower())
    return (f'Technology "{tech}" detected. Research version-specific CVEs.', 'informational')


def _analyze_dns(result: dict) -> tuple:
    record_type = result.get('record_type', result.get('type_label', '')).upper()
    if record_type in DNS_ANALYSIS:
        risk, analysis = DNS_ANALYSIS[record_type]
        return (analysis, risk.lower())
    return ('DNS record discovered. Verify configuration and check for misconfigurations.', 'informational')


def _analyze_whois(result: dict) -> tuple:
    raw = str(result.get('raw', '')).lower()
    findings = []

    if 'privacy' in raw or 'redacted' in raw:
        findings.append('Domain privacy protection is active — registrant info hidden.')
    if 'expired' in raw:
        findings.append('WARN: Domain may be expired — risk of domain hijacking!')

    if not findings:
        findings.append('WHOIS information retrieved. Review registrar, expiry date, and nameserver configuration.')

    return (' '.join(findings), 'informational')


def _analyze_directory(result: dict) -> tuple:
    path   = result.get('path', result.get('url', '')).lower()
    status = int(result.get('status', 200))

    high_value = ['.git', '.env', 'backup', 'admin', 'phpmyadmin', 'wp-admin',
                  'manager', 'console', 'config', 'secret', 'api/v1', 'debug',
                  'phpinfo', 'install', 'setup', 'database', 'db']

    for keyword in high_value:
        if keyword in path:
            return (
                f'Sensitive path "{path}" discovered (HTTP {status}). '
                f'Immediately investigate for information disclosure or unauthorized access.',
                'critical' if status == 200 else 'high'
            )

    if status == 200:
        return (f'Directory/file "{path}" is accessible (HTTP 200). Review for sensitive content.', 'medium')
    if status == 403:
        return (f'Path "{path}" returns 403 Forbidden. May be bypassable — test with path traversal or method override.', 'low')

    return (f'Path "{path}" found with HTTP {status}. Manual review recommended.', 'informational')


def get_risk_color(risk: str) -> str:
    """Return Bootstrap color class for a risk level."""
    mapping = {
        'critical':      'danger',
        'high':          'warning',
        'medium':        'info',
        'low':           'success',
        'informational': 'secondary',
        'info':          'secondary',
    }
    return mapping.get(risk.lower(), 'secondary')
