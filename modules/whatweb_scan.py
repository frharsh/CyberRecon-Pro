"""
CyberRecon Pro - WhatWeb Technology Detection Module
"""

import subprocess
import shlex
import json
import threading
import re


def run_whatweb(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """Run WhatWeb for technology stack detection."""
    domain = target.domain or target.ip_address or target.name
    if not domain:
        raise ValueError('Target has no domain or IP configured.')

    url      = options.get('url', f'http://{domain}')
    if not url.startswith(('http://', 'https://')):
        url = f'http://{domain}'

    aggression = int(options.get('aggression', 1))
    cmd = ['whatweb', '--log-json=-', '--no-errors', '-a', str(aggression), url]
    cmd_str = shlex.join(cmd)

    _buffer_append(buffers, lock, scan_id, f'[*] Starting WhatWeb on {url}')
    _buffer_append(buffers, lock, scan_id, f'[*] Command: {cmd_str}')

    try:
        proc = subprocess.run(
            cmd, shell=False, capture_output=True, text=True, timeout=60
        )
        raw = proc.stdout or ''

        results = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                # WhatWeb JSON format: list of [url, http_status, plugins_dict]
                if isinstance(entry, list) and len(entry) >= 3:
                    target_url = entry[0]
                    plugins    = entry[2] if isinstance(entry[2], dict) else {}
                    for plugin_name, plugin_data in plugins.items():
                        tech_result = {
                            'type':       'tech',
                            'technology': plugin_name,
                            'url':        target_url,
                            'details':    plugin_data,
                        }
                        # Extract version if available
                        if isinstance(plugin_data, dict):
                            version = plugin_data.get('version', [''])
                            tech_result['version'] = version[0] if version else ''

                        results.append(tech_result)
                        _buffer_append(buffers, lock, scan_id, f'[+] {plugin_name}: {tech_result.get("version", "")}')
            except json.JSONDecodeError:
                # Try to parse plain text output
                if '[' in line:
                    _buffer_append(buffers, lock, scan_id, line)
                    techs = re.findall(r'(\w+)\[([^\]]*)\]', line)
                    for tech, detail in techs:
                        results.append({
                            'type': 'tech',
                            'technology': tech,
                            'details': detail,
                        })

        if not results and proc.stderr:
            # Try stderr for any output
            for line in proc.stderr.splitlines()[:10]:
                _buffer_append(buffers, lock, scan_id, line)

        _buffer_append(buffers, lock, scan_id, f'[+] WhatWeb detected {len(results)} technologies.')
        return results, raw

    except FileNotFoundError:
        raise RuntimeError('WhatWeb is not installed. Install from: https://github.com/urbanadventurer/WhatWeb')
    except subprocess.TimeoutExpired:
        raise RuntimeError('WhatWeb scan timed out.')


def _buffer_append(buffers, lock, scan_id, line):
    with lock:
        if scan_id in buffers:
            buffers[scan_id].append(line)
