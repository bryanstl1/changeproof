import argparse
import fnmatch
import html
import json
import sys
import socket
import ipaddress
import http.client
import ssl
from urllib.parse import urlsplit
from pathlib import Path
from urllib.error import HTTPError, URLError


def compare(old, new, path='$', ignored=(), array_key=None):
    if any(fnmatch.fnmatchcase(path, pattern) for pattern in ignored):
        return []
    if type(old) is not type(new):
        return [{'path': path, 'kind': 'type_changed', 'before': type(old).__name__, 'after': type(new).__name__, 'breaking': True}]
    changes = []
    if isinstance(old, dict):
        for key in sorted(old.keys() | new.keys()):
            p = f'{path}.{key}'
            if any(fnmatch.fnmatchcase(p, pattern) for pattern in ignored):
                continue
            if key not in new:
                changes.append({'path': p, 'kind': 'removed', 'breaking': True})
            elif key not in old:
                changes.append({'path': p, 'kind': 'added', 'breaking': False})
            else:
                changes.extend(compare(old[key], new[key], p, ignored, array_key))
    elif isinstance(old, list):
        if array_key and all(isinstance(v, dict) and array_key in v for v in old + new):
            def index(items):
                keys = [str(v[array_key]) for v in items]
                return dict(zip(keys, items)) if len(keys) == len(set(keys)) else None
            a, b = index(old), index(new)
            if a is not None and b is not None:
                for key in sorted(a.keys() | b.keys()):
                    p = f'{path}[{array_key}={key}]'
                    if key not in b:
                        changes.append({'path': p, 'kind': 'removed', 'breaking': True})
                    elif key not in a:
                        changes.append({'path': p, 'kind': 'added', 'breaking': False})
                    else:
                        changes.extend(compare(a[key], b[key], p, ignored, array_key))
                return changes
        for i in range(min(len(old), len(new))):
            changes.extend(compare(old[i], new[i], f'{path}[{i}]', ignored, array_key))
        if len(old) != len(new):
            changes.append({'path': path, 'kind': 'array_length_changed', 'before': len(old), 'after': len(new), 'breaking': False})
    elif old != new:
        changes.append({'path': path, 'kind': 'value_changed', 'before': old, 'after': new, 'breaking': False})
    return changes


def fetch_json(url, timeout=10, max_bytes=2_000_000):
    """Fetch a public HTTPS endpoint, pinning DNS to validated public addresses.

    Redirects and credentials in URLs are intentionally unsupported.
    """
    if not isinstance(url, str) or len(url) > 8192:
        raise ValueError('Invalid URL length')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.hostname.endswith('.'):
        raise ValueError('A public HTTPS URL without credentials or fragments is required')
    if timeout <= 0 or max_bytes <= 0:
        raise ValueError('Timeout and size limit must be positive')
    if parsed.port not in (None, 443):
        raise ValueError('Only HTTPS port 443 is supported')
    host = parsed.hostname
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in url):
        raise ValueError('Control characters are prohibited in URLs')
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError('Hostname did not resolve')
    ips = {a[4][0] for a in addresses}
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError('Private, reserved, or loopback addresses are prohibited')

    class PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            family = socket.AF_INET6 if ':' in ip else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((ip, 443))
                self.sock = self._context.wrap_socket(sock, server_hostname=host)
            except Exception:
                sock.close()
                raise

    ip = sorted(ips)[0]
    conn = PinnedHTTPSConnection(host, timeout=timeout, context=ssl.create_default_context())
    try:
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        conn.request('GET', path, headers={'Host': host, 'Accept': 'application/json', 'User-Agent': 'ChangeProof/0.6', 'Accept-Encoding': 'identity'})
        response = conn.getresponse()
        if 300 <= response.status < 400:
            raise ValueError('Redirects are disabled for safety')
        if response.getheader('Content-Encoding', 'identity').lower() not in ('identity', ''):
            raise ValueError('Compressed responses are unsupported')
        if response.status != 200:
            raise ValueError(f'Unexpected HTTP status: {response.status}')
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError('Response exceeds size limit')
        content_type = response.getheader('Content-Type', '').lower().split(';')[0].strip()
        if content_type not in ('application/json',) and not content_type.endswith('+json'):
            raise ValueError('Endpoint did not return a JSON content type')
        return json.loads(data.decode('utf-8'))
    finally:
        conn.close()


def save_report(changes, html_path=None, json_path=None):
    report = {'breaking_changes': sum(c['breaking'] for c in changes), 'changes': changes}
    if json_path:
        Path(json_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
    if html_path:
        rows = ''.join('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(html.escape(c['path']), html.escape(c['kind']), 'Yes' if c['breaking'] else 'No') for c in changes)
        page = '<!doctype html><html lang="en"><meta charset="utf-8"><title>ChangeProof report</title><style>body{{font:16px system-ui;margin:3rem;max-width:900px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:12px;border-bottom:1px solid #ddd;text-align:left}}</style><h1>ChangeProof report</h1><p>Potential breaking changes: {}</p><table><tr><th>Path</th><th>Change</th><th>Potentially breaking</th></tr>{}</table></html>'.format(report['breaking_changes'], rows)
        Path(html_path).write_text(page, encoding='utf-8')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description='Capture and compare JSON API snapshots')
    sub = parser.add_subparsers(dest='command')
    capture = sub.add_parser('capture', help='Capture a public HTTPS JSON response')
    capture.add_argument('url')
    capture.add_argument('output', type=Path)
    capture.add_argument('--timeout', type=int, default=10)
    diff = sub.add_parser('compare', help='Compare two JSON files')
    diff.add_argument('before', type=Path)
    diff.add_argument('after', type=Path)
    diff.add_argument('--ignore', action='append', default=[])
    diff.add_argument('--array-key', help='Match objects in arrays by this unique field instead of position')
    diff.add_argument('--html', type=Path)
    diff.add_argument('--json', type=Path)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    try:
        if args.command == 'capture':
            result = fetch_json(args.url, args.timeout)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            print('Snapshot saved:', args.output)
            return 0
        before = json.loads(args.before.read_text(encoding='utf-8'))
        after = json.loads(args.after.read_text(encoding='utf-8'))
        report = save_report(compare(before, after, ignored=args.ignore, array_key=args.array_key), args.html, args.json)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 1 if report['breaking_changes'] else 0
    except (OSError, ValueError, json.JSONDecodeError, HTTPError, URLError) as error:
        print('ChangeProof error:', error, file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
