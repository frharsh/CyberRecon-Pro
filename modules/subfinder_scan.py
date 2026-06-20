"""
CyberRecon Pro - Subfinder Subdomain Enumeration Module
"""

import subprocess
import shlex
import threading


def run_subfinder(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """Run subfinder for subdomain enumeration."""
    domain = target.domain or target.name
    if not domain:
        raise ValueError('Target has no domain configured.')

    all_sources  = options.get('all_sources', False)
    recursive    = options.get('recursive', False)
    timeout      = int(options.get('timeout', 30))

    cmd = ['subfinder', '-d', domain, '-silent', '-timeout', str(timeout)]
    if all_sources:
        cmd.append('-all')
    if recursive:
        cmd.append('-recursive')

    cmd_str = shlex.join(cmd)
    _buffer_append(buffers, lock, scan_id, f'[*] Starting Subfinder on {domain}')
    _buffer_append(buffers, lock, scan_id, f'[*] Command: {cmd_str}')

    try:
        proc = subprocess.Popen(
            cmd, shell=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True
        )
        subdomains = []
        if proc.stdout:
            for line in proc.stdout:
                sub = line.strip()
                if sub:
                    subdomains.append(sub)
                    _buffer_append(buffers, lock, scan_id, f'[+] {sub}')

        proc.wait()
        _buffer_append(buffers, lock, scan_id, f'[+] Found {len(subdomains)} subdomains.')

        results = [{'type': 'subdomain', 'subdomain': s, 'source': 'subfinder'} for s in subdomains]
        raw = '\n'.join(subdomains)
        return results, raw

    except FileNotFoundError:
        raise RuntimeError('Subfinder is not installed. Install from: https://github.com/projectdiscovery/subfinder')


def _buffer_append(buffers, lock, scan_id, line):
    with lock:
        if scan_id in buffers:
            buffers[scan_id].append(line)
