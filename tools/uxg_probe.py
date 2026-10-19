"""Test-only UXG-Max emulator: informs the controller, logs every response.
Never touches OPNsense. State in state.json next to this file."""
import configparser, json, os, sys, time, urllib.request, urllib.error
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import unifi_protocol as up

HERE = os.environ.get('PROBE_STATE_DIR', os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '.uxg-probe'))
os.makedirs(HERE, exist_ok=True)
STATE = os.path.join(HERE, 'state.json')
LOG = os.path.join(HERE, 'responses.jsonl')
URL = os.environ['PROBE_URL']  # e.g. http://<lab-controller>:18080/inform
MAC = '74:ac:b9:5e:00:01'          # test identity (Ubiquiti OUI, not a real device here)
IP = '10.0.5.250'
MODEL, DISPLAY, VERSION = 'UXGB', 'UniFi Gateway Max', '5.1.26.33914'

def load():
    try: return json.load(open(STATE))
    except Exception: return {'adopted': False, 'key': None, 'gcm': False, 'cfgversion': ''}

def save(s): json.dump(s, open(STATE, 'w'), indent=1)

def cfg(s):
    c = configparser.RawConfigParser()
    c.read_dict({'gateway': {'is_adopted': str(s['adopted']), 'key': s['key'] or '', 'use_aes_gcm': str(s['gcm']), 'lan_mac': MAC}})
    return c

def payload(s, extra=None):
    base = {'mac': MAC, 'ip': IP, 'model': MODEL, 'model_display': DISPLAY, 'version': VERSION,
            'serial': MAC.replace(':', ''), 'inform_url': URL, 'uptime': int(time.time()) % 100000,
            'hostname': 'uxg-probe', 'required_version': '4.0.0', 'board_rev': 1}
    if not s['adopted']:
        base.update({'state': 0, 'default': True, 'discovery_response': False})
    else:
        base.update({'state': 2, 'default': False, 'cfgversion': s['cfgversion'], 'time': int(time.time()),
                     'connect_request_ip': IP, 'connect_request_port': '36424'})
    base.update(extra or {})
    return json.dumps(base)

def inform(s, extra=None):
    c = cfg(s)
    body = up.encode_inform(c, payload(s, extra))
    req = urllib.request.Request(URL, body, {'Content-Type': 'application/x-binary', 'User-Agent': 'AirControl Agent v1.0'})
    try:
        raw = urllib.request.urlopen(req, timeout=30).read()
    except urllib.error.HTTPError as e:
        return {'_type': 'httperror', 'code': e.code}
    return up.decode_inform(c, raw)

def handle(s, r):
    with open(LOG, 'a') as f:
        f.write(json.dumps({'t': time.time(), 'resp': r}) + '\n')
    if r.get('_type') == 'setparam':
        for row in str(r.get('mgmt_cfg', '')).split('\n'):
            k, _, v = row.partition('=')
            if k == 'authkey': s['key'] = v; s['adopted'] = True
            if k == 'use_aes_gcm' and v == 'true': s['gcm'] = True
            if k == 'cfgversion': s['cfgversion'] = v
        save(s)

if __name__ == '__main__':
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    extra = json.loads(sys.argv[2]) if len(sys.argv) > 2 else None
    s = load()
    for _ in range(rounds):
        r = inform(s, extra)
        handle(s, r)
        summary = {k: (v if len(json.dumps(v)) < 120 else '<%d bytes>' % len(json.dumps(v))) for k, v in r.items()}
        print(json.dumps(summary))
        time.sleep(3)
