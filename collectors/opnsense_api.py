# -*- coding: utf-8 -*-
"""Minimal OPNsense REST API client (stdlib only, so it survives PyInstaller
and the tiny OpenWRT/FreeBSD packages without pulling in requests).

Authentication is HTTP Basic with an API key/secret pair created under
System -> Access -> Users -> API keys.
"""
import base64
import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger('unifi-gateway')


class OPNsenseAPIError(Exception):
    pass


class OPNsenseAPI:

    def __init__(self, url, key, secret, verify_ssl=False, timeout=30):
        self.base = url.rstrip('/')
        if not self.base.endswith('/api'):
            self.base += '/api'
        token = base64.b64encode(('%s:%s' % (key, secret)).encode('utf-8'))
        self._auth = 'Basic ' + token.decode('ascii')
        self.timeout = timeout
        if verify_ssl:
            self._ssl = ssl.create_default_context()
        else:
            self._ssl = ssl.create_default_context()
            self._ssl.check_hostname = False
            self._ssl.verify_mode = ssl.CERT_NONE

    @property
    def host(self):
        return urllib.parse.urlparse(self.base).hostname or ''

    def _request(self, method, path, payload=None, params=None, timeout=None):
        url = '%s/%s' % (self.base, path.lstrip('/'))
        if params:
            url += '?' + urllib.parse.urlencode(params)
        headers = {'Authorization': self._auth, 'Accept': 'application/json'}
        data = None
        if method in ('POST', 'PUT', 'PATCH'):
            data = json.dumps(payload if payload is not None else {}).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(
                req, timeout=timeout or self.timeout, context=self._ssl
            ) as resp:
                body = resp.read().decode('utf-8', errors='replace')
        except urllib.error.HTTPError as e:
            raise OPNsenseAPIError('%s %s: HTTP %s' % (method, path, e.code))
        except (urllib.error.URLError, OSError) as e:
            raise OPNsenseAPIError('%s %s: %s' % (method, path, e))
        return self._decode(body)

    @staticmethod
    def _decode(body):
        body = body.strip()
        if not body:
            return {}
        try:
            result = json.loads(body)
        except ValueError:
            return body
        # Some plugin endpoints return configd output (a JSON document) as a
        # JSON string; unwrap one level so callers always get structured data.
        if isinstance(result, str):
            try:
                return json.loads(result)
            except ValueError:
                return result
        return result

    def get(self, path, params=None, timeout=None):
        return self._request('GET', path, params=params, timeout=timeout)

    def post(self, path, payload=None, timeout=None):
        return self._request('POST', path, payload=payload, timeout=timeout)

    def put(self, path, payload=None, params=None, timeout=None):
        """Plugin APIs such as Zenarmor use PUT for policy updates."""
        return self._request('PUT', path, payload=payload, params=params, timeout=timeout)

    def search(self, path, params=None, timeout=None):
        """Return all rows of a search endpoint (searchBase/searchRecordsetBase)."""
        query = {'current': 1, 'rowCount': -1}
        if params:
            query.update(params)
        result = self.get(path, params=query, timeout=timeout)
        if isinstance(result, dict):
            return result.get('rows', [])
        return []

    @staticmethod
    def check_saved(result, what):
        """Raise if an add/set/del call did not succeed."""
        if isinstance(result, dict) and result.get('result') in ('saved', 'deleted'):
            return result
        raise OPNsenseAPIError('%s failed: %s' % (what, json.dumps(result)[:500]))
