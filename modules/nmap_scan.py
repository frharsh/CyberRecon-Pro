"""
CyberRecon Pro - Nmap Port Scanner Module
Runs nmap and parses results into structured data.
"""

import subprocess
import shlex
import json
import re
import threading
import xml.etree.ElementTree as ET


def run_nmap(target, options: dict, scan_id: int, buffers: dict, lock: threading.Lock):
    """
    Execute nmap against a target and return structured results.
    Returns: (results_list, raw_output_str)
    """
    domain = target.domain or target.ip_address or target.name
    if not domain:
        raise ValueError('Target has no domain or IP address configured.')

    # Build nmap command
    scan_type = options.get('scan_type', 'basic')
    custom    = options.get('custom_flags', '')

    if scan_type == 'basic':
        cmd = ['nmap', '-sV', '-sC', '-T4', '-oX', '-', domain]
    elif scan_type == 'full':
        cmd = ['nmap', '-sV', '-sC', '-p-', '-T4', '-oX', '-', domain]
    elif scan_type == 'stealth':
        cmd = ['nmap', '-sS', '-sV', '-T2', '-oX', '-', domain]
    elif scan_type == 'udp':
        cmd = ['nmap', '-sU', '-sV', '--top-ports', '100', '-oX', '-', domain]
    elif scan_type == 'vuln':
        cmd = ['nmap', '-sV', '--script=vuln', '-T4', '-oX', '-', domain]
    elif scan_type == 'custom' and custom:
        cmd = ['nmap'] + shlex.split(custom) + ['-oX', '-', domain]
    else:
        cmd = ['nmap', '-sV', '-T4', '--top-ports', '1000', '-oX', '-', domain]

    cmd_str = shlex.join(cmd)
    _buffer_append(buffers, lock, scan_id, f'[*] Starting Nmap scan on {domain}')
    _buffer_append(buffers, lock, scan_id, f'[*] Command: {cmd_str}')

    try:
        proc = subprocess.Popen(
            cmd, shell=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True
        )

        # Read stderr for progress
        stderr_lines = []
        if proc.stderr:
            for line in proc.stderr:
                line = line.strip()
                if line:
                    stderr_lines.append(line)
                    _buffer_append(buffers, lock, scan_id, line)

        stdout, _ = proc.communicate()
        raw = stdout

        if proc.returncode != 0 and not stdout:
            raise RuntimeError(f'Nmap failed: {" ".join(stderr_lines)}')

        results = _parse_nmap_xml(raw, scan_id, buffers, lock)
        _buffer_append(buffers, lock, scan_id, f'[+] Scan complete. Found {len(results)} port results.')
        return results, raw

    except FileNotFoundError:
        raise RuntimeError('Nmap is not installed or not found in PATH. Please install nmap.')


def _parse_nmap_xml(xml_data: str, scan_id, buffers, lock) -> list:
    """Parse nmap XML output into a list of result dicts."""
    results = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('host'):
            # Get IP / hostname
            address = host.find('address')
            ip = address.get('addr') if address is not None else 'unknown'

            hostname_el = host.find('.//hostname')
            hostname = hostname_el.get('name') if hostname_el is not None else ''

            # Get OS
            os_el = host.find('.//osmatch')
            os_name = os_el.get('name') if os_el is not None else ''

            # Get open ports
            for port_el in host.findall('.//port'):
                state_el  = port_el.find('state')
                state     = state_el.get('state') if state_el is not None else 'unknown'
                if state != 'open':
                    continue

                port_num  = int(port_el.get('portid', 0))
                protocol  = port_el.get('protocol', 'tcp')

                service_el = port_el.find('service')
                service    = service_el.get('name', '')    if service_el is not None else ''
                product    = service_el.get('product', '') if service_el is not None else ''
                version    = service_el.get('version', '') if service_el is not None else ''
                extra_info = service_el.get('extrainfo','') if service_el is not None else ''

                # Scripts
                scripts = {}
                for script in port_el.findall('script'):
                    scripts[script.get('id')] = script.get('output')

                result = {
                    'type':       'port',
                    'ip':         ip,
                    'hostname':   hostname,
                    'port':       port_num,
                    'protocol':   protocol,
                    'service':    service,
                    'product':    product,
                    'version':    version,
                    'extra_info': extra_info,
                    'os':         os_name,
                    'scripts':    scripts,
                    'state':      'open',
                }
                results.append(result)
                _buffer_append(buffers, lock, scan_id,
                    f'[+] {ip}:{port_num}/{protocol} open {service} {product} {version}'.strip())

    except ET.ParseError as e:
        # Fallback: try plain text parsing
        results = _parse_nmap_text(xml_data, scan_id, buffers, lock)

    return results


def _parse_nmap_text(text: str, scan_id, buffers, lock) -> list:
    """Fallback text parser for nmap output."""
    results = []
    port_re = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?')
    for line in text.splitlines():
        m = port_re.match(line.strip())
        if m:
            port, proto, svc, rest = m.groups()
            result = {
                'type':     'port',
                'port':     int(port),
                'protocol': proto,
                'service':  svc,
                'version':  rest.strip() if rest else '',
                'state':    'open',
            }
            results.append(result)
    return results


def _buffer_append(buffers, lock, scan_id, line):
    with lock:
        if scan_id in buffers:
            buffers[scan_id].append(line)
