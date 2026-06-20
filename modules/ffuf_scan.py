"""
CyberRecon Pro - FFUF Directory/File Discovery Module
"""

import subprocess
import shlex
import json
import threading
import os


def run_ffuf(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """Run FFUF for directory and file discovery."""
    domain   = target.domain or target.ip_address or target.name
    if not domain:
        raise ValueError('Target has no domain or IP configured.')

    url      = options.get('url', f'http://{domain}/FUZZ')
    wordlist = options.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
    threads  = int(options.get('threads', 40))
    timeout  = int(options.get('timeout', 10))
    ext      = options.get('extensions', '')

    # Windows wordlist fallback
    if not os.path.exists(wordlist):
        alt_paths = [
            r'C:\tools\wordlists\common.txt',
            r'C:\wordlists\common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirb/common.txt',
        ]
        for p in alt_paths:
            if os.path.exists(p):
                wordlist = p
                break

    cmd = [
        'ffuf', '-u', url,
        '-w', wordlist,
        '-t', str(threads), '-timeout', str(timeout),
        '-of', 'json', '-o', '-'
    ]
    if ext:
        cmd.extend(['-e', ext])

    cmd_str = shlex.join(cmd)
    _buffer_append(buffers, lock, scan_id, f'[*] Starting FFUF on {url}')
    _buffer_append(buffers, lock, scan_id, f'[*] Wordlist: {wordlist}')
    _buffer_append(buffers, lock, scan_id, f'[*] Command: {cmd_str}')

    try:
        proc = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, timeout=300
        )
        raw = proc.stdout or ''

        results = []
        try:
            data = json.loads(raw)
            for item in data.get('results', []):
                result = {
                    'type':   'directory',
                    'url':    item.get('url', ''),
                    'path':   item.get('input', {}).get('FUZZ', ''),
                    'status': item.get('status', 0),
                    'length': item.get('length', 0),
                    'words':  item.get('words', 0),
                    'lines':  item.get('lines', 0),
                }
                results.append(result)
                _buffer_append(buffers, lock, scan_id,
                    f'[+] {result["status"]} {result["length"]:>8}B  {result["url"]}')
        except json.JSONDecodeError:
            # Parse text output fallback
            for line in raw.splitlines():
                if '[Status:' in line or '200' in line or '301' in line:
                    results.append({'type': 'directory', 'raw_line': line})
                    _buffer_append(buffers, lock, scan_id, f'[+] {line}')

        _buffer_append(buffers, lock, scan_id, f'[+] FFUF found {len(results)} paths.')
        return results, raw

    except FileNotFoundError:
        raise RuntimeError('FFUF is not installed. Install from: https://github.com/ffuf/ffuf')
    except subprocess.TimeoutExpired:
        raise RuntimeError('FFUF scan timed out.')


def _buffer_append(buffers, lock, scan_id, line):
    with lock:
        if scan_id in buffers:
            buffers[scan_id].append(line)
