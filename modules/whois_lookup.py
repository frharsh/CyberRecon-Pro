"""
CyberRecon Pro - Whois / Nslookup / Dig Information Gathering Module
Uses subprocess + python-whois library with graceful fallbacks.
"""

import subprocess
import shlex
import threading
import re


# ─── Whois ─────────────────────────────────────────────────────────────────────
def run_whois(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """Run whois lookup on target domain."""
    domain = target.domain or target.name
    if not domain:
        raise ValueError('Target has no domain configured.')

    _buffer_append(buffers, lock, scan_id, f'[*] Running WHOIS lookup on {domain}')

    raw = ''
    result_data = {'type': 'whois', 'domain': domain}

    # Try python-whois first
    try:
        import whois as pywhois
        w = pywhois.whois(domain)
        raw = str(w.text) if hasattr(w, 'text') else str(w)
        result_data.update({
            'registrar':        str(w.registrar or ''),
            'creation_date':    str(w.creation_date or ''),
            'expiration_date':  str(w.expiration_date or ''),
            'updated_date':     str(w.updated_date or ''),
            'name_servers':     list(w.name_servers or []),
            'registrant':       str(w.org or w.name or ''),
            'emails':           list(w.emails or []),
            'country':          str(w.country or ''),
            'raw':              raw,
        })
        _buffer_append(buffers, lock, scan_id, f'[+] Registrar: {result_data["registrar"]}')
        _buffer_append(buffers, lock, scan_id, f'[+] Expiry: {result_data["expiration_date"]}')
        _buffer_append(buffers, lock, scan_id, f'[+] Name servers: {result_data["name_servers"]}')
    except Exception:
        # Fallback to subprocess whois
        try:
            proc = subprocess.run(
                ['whois', domain], shell=False,
                capture_output=True, text=True, timeout=30
            )
            raw = proc.stdout or proc.stderr
            result_data['raw'] = raw
            for line in raw.splitlines()[:20]:
                _buffer_append(buffers, lock, scan_id, line)
        except Exception as e:
            raw = str(e)
            result_data['raw'] = raw

    _buffer_append(buffers, lock, scan_id, '[+] WHOIS lookup complete.')
    return [result_data], raw


# ─── Nslookup ──────────────────────────────────────────────────────────────────
def run_nslookup(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """Run nslookup for DNS queries."""
    domain = target.domain or target.name
    if not domain:
        raise ValueError('Target has no domain configured.')

    record_types = options.get('record_types', ['A', 'MX', 'NS', 'TXT', 'AAAA'])
    _buffer_append(buffers, lock, scan_id, f'[*] Running Nslookup on {domain}')

    results = []
    raw_all = []

    for rtype in record_types:
        try:
            proc = subprocess.run(
                ['nslookup', f'-type={rtype}', domain],
                shell=False, capture_output=True, text=True, timeout=15
            )
            raw = proc.stdout or ''
            raw_all.append(f'=== {rtype} ===\n{raw}')

            _buffer_append(buffers, lock, scan_id, f'[*] {rtype} records:')
            for line in raw.splitlines():
                if line.strip() and not line.startswith(('Server', 'Address', '>>')):
                    _buffer_append(buffers, lock, scan_id, f'    {line}')

            results.append({
                'type': 'dns',
                'domain': domain,
                'record_type': rtype,
                'raw': raw,
                'type_label': rtype,
            })
        except Exception as e:
            _buffer_append(buffers, lock, scan_id, f'[-] {rtype} lookup failed: {e}')

    return results, '\n'.join(raw_all)


# ─── Dig ───────────────────────────────────────────────────────────────────────
def run_dig(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """Run dig for DNS enumeration including zone transfer attempt."""
    domain = target.domain or target.name
    if not domain:
        raise ValueError('Target has no domain configured.')

    record_types = options.get('record_types', ['A', 'MX', 'NS', 'TXT', 'AAAA', 'SOA'])
    attempt_axfr = options.get('attempt_axfr', True)

    _buffer_append(buffers, lock, scan_id, f'[*] Running Dig on {domain}')

    results = []
    raw_all = []

    for rtype in record_types:
        try:
            proc = subprocess.run(
                ['dig', domain, rtype, '+short'],
                shell=False, capture_output=True, text=True, timeout=15
            )
            raw = proc.stdout or ''
            raw_all.append(f'=== DIG {rtype} ===\n{raw}')

            values = [l.strip() for l in raw.splitlines() if l.strip()]
            _buffer_append(buffers, lock, scan_id, f'[+] {rtype}: {", ".join(values) or "No records"}')

            results.append({
                'type': 'dns',
                'domain': domain,
                'record_type': rtype,
                'values': values,
                'raw': raw,
                'type_label': rtype,
            })
        except Exception as e:
            _buffer_append(buffers, lock, scan_id, f'[-] dig {rtype} failed: {e}')

    # Attempt zone transfer
    if attempt_axfr:
        _buffer_append(buffers, lock, scan_id, '[*] Attempting zone transfer (AXFR)...')
        try:
            # Get NS first
            ns_proc = subprocess.run(
                ['dig', domain, 'NS', '+short'],
                shell=False, capture_output=True, text=True, timeout=10
            )
            nameservers = [l.strip() for l in ns_proc.stdout.splitlines() if l.strip()]
            for ns in nameservers[:3]:  # Try first 3 NS
                axfr_proc = subprocess.run(
                    ['dig', f'@{ns}', domain, 'AXFR'],
                    shell=False, capture_output=True, text=True, timeout=15
                )
                axfr_raw = axfr_proc.stdout
                raw_all.append(f'=== AXFR via {ns} ===\n{axfr_raw}')
                if 'Transfer failed' not in axfr_raw and 'connection timed out' not in axfr_raw:
                    _buffer_append(buffers, lock, scan_id, f'[!!!] ZONE TRANSFER SUCCEEDED via {ns}! CRITICAL VULNERABILITY!')
                    results.append({
                        'type': 'dns', 'domain': domain,
                        'record_type': 'AXFR', 'type_label': 'AXFR',
                        'raw': axfr_raw, 'ns': ns,
                    })
                else:
                    _buffer_append(buffers, lock, scan_id, f'[+] AXFR via {ns}: Transfer refused (good)')
        except Exception as e:
            _buffer_append(buffers, lock, scan_id, f'[-] AXFR attempt failed: {e}')

    return results, '\n'.join(raw_all)


def _buffer_append(buffers, lock, scan_id, line):
    with lock:
        if scan_id in buffers:
            buffers[scan_id].append(line)
