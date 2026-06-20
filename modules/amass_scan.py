"""
CyberRecon Pro - Amass Subdomain Enumeration Module
"""

import subprocess
import shlex
import threading
import re


def run_amass(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """Run amass enum for subdomain discovery."""
    domain = target.domain or target.name
    if not domain:
        raise ValueError('Target has no domain configured.')

    passive  = options.get('passive', True)
    brute    = options.get('brute', False)

    cmd = ['amass', 'enum', '-d', domain]
    if passive:
        cmd.append('-passive')
    if brute:
        cmd.append('-brute')

    cmd_str = shlex.join(cmd)
    _buffer_append(buffers, lock, scan_id, f'[*] Starting Amass on {domain}')
    _buffer_append(buffers, lock, scan_id, f'[*] Command: {cmd_str}')
    _buffer_append(buffers, lock, scan_id, '[*] Amass may take several minutes...')

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
                # Amass output can include source info — extract subdomain
                sub = re.sub(r'\s+\(.*?\)', '', sub).strip()
                if sub and domain in sub:
                    subdomains.append(sub)
                    _buffer_append(buffers, lock, scan_id, f'[+] {sub}')

        proc.wait()
        _buffer_append(buffers, lock, scan_id, f'[+] Found {len(subdomains)} subdomains via Amass.')

        results = [{'type': 'subdomain', 'subdomain': s, 'source': 'amass'} for s in subdomains]
        return results, '\n'.join(subdomains)

    except FileNotFoundError:
        raise RuntimeError('Amass is not installed. Install from: https://github.com/owasp-amass/amass')


def _buffer_append(buffers, lock, scan_id, line):
    with lock:
        if scan_id in buffers:
            buffers[scan_id].append(line)
