#!/usr/local/bin/python3
"""Switch the production emulator from USG (UGW3) to UXG-Max (UXGB). Run as root.

  python3 /home/glenm/uxg-migrate/migrate.py            # migrate
  python3 /home/glenm/uxg-migrate/migrate.py rollback   # restore the USG setup

Backups go to /usr/local/etc/unifi-gateway/backup-uxg-20261020/.
"""
import configparser
import glob
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = '/usr/local/lib/unifi-gateway'
ETC = '/usr/local/etc/unifi-gateway'
CONF = ETC + '/unifi-gateway.conf'
BACKUP = ETC + '/backup-uxg-20261020'
GW = '/usr/local/bin/unifi-gateway'


def sh(*cmd, check=True):
    print('+', ' '.join(cmd))
    return subprocess.run(cmd, check=check)


def rollback():
    sh('service', 'unifi_gateway', 'stop', check=False)
    shutil.rmtree(LIB)
    shutil.copytree(BACKUP + '/lib', LIB)
    shutil.copy2(BACKUP + '/unifi-gateway.conf', CONF)
    shutil.copy2(BACKUP + '/opnsense_state.json', ETC + '/opnsense_state.json')
    sh('service', 'unifi_gateway', 'start')
    print('Rolled back to the USG files. The USG was forgotten in UniFi: restore the '
          'controller backup, or adopt it again from the Devices page.')


def controller(cfg):
    sys.path.insert(0, LIB)
    from collectors.unifi_mirror import UniFiController
    u = cfg['unifi']
    return UniFiController(u['url'], u['username'], u['password'], site=u.get('site', 'default'))


def main():
    if os.geteuid() != 0:
        sys.exit('run as root')
    if len(sys.argv) > 1 and sys.argv[1] == 'rollback':
        return rollback()

    cfg = configparser.RawConfigParser()
    cfg.read(CONF)
    gw = cfg['gateway']
    mac = gw['lan_mac'].lower()
    url = gw['url']
    print('gateway', mac, gw.get('device'), url)

    # 1. stop and back up
    sh('service', 'unifi_gateway', 'stop', check=False)
    if not os.path.exists(BACKUP):
        os.makedirs(BACKUP, mode=0o700)
        shutil.copytree(LIB, BACKUP + '/lib')
        for name in ('unifi-gateway.conf', 'opnsense_state.json'):
            shutil.copy2(os.path.join(ETC, name), BACKUP)
    print('backup in', BACKUP)

    # 2. install the UXG code
    src = os.path.join(HERE, 'src')
    for path in glob.glob(src + '/*.py') + glob.glob(src + '/collectors/*.py'):
        dst = os.path.join(LIB, os.path.relpath(path, src))
        shutil.copy2(path, dst)
        os.chown(dst, 0, 0)
        os.chmod(dst, 0o644)
    for cache in glob.glob(LIB + '/**/__pycache__', recursive=True):
        shutil.rmtree(cache)

    # 3. UXG-Max identity: WAN on eth4 (port 5), LANs on eth0..eth3
    ports = json.loads(gw['ports'])
    lans = iter('eth%d' % i for i in range(4))
    for port in ports:
        port['ifname'] = 'eth4' if port.get('type') == 'wan' else next(lans)
    gw['ports'] = json.dumps(ports)
    gw['device'] = 'UXGB'
    gw['device_display'] = 'UniFi Gateway Max'
    gw['firmware'] = '5.1.26.33914'
    gw['is_adopted'] = 'False'
    gw.pop('key', None)
    cfg.remove_section('provisioned')
    cfg.add_section('provisioned')
    with open(CONF, 'w') as f:
        cfg.write(f)
    os.chmod(CONF, 0o600)
    # the stored hash belongs to the USG config; let the first UXG push apply
    state_path = ETC + '/opnsense_state.json'
    state = json.load(open(state_path))
    state.pop('system_cfg_hash', None)
    json.dump(state, open(state_path, 'w'), indent=2)
    print('ports', gw['ports'])

    # 4. forget the USG, then adopt the same MAC as a UXG-Max
    ctl = controller(cfg)
    if any(d['mac'] == mac for d in ctl.call('GET', 'stat/device')):
        ctl.call('POST', 'cmd/sitemgr', {'cmd': 'delete-device', 'mac': mac})
        print('forgot the USG', mac)
        time.sleep(15)
    env = dict(os.environ, UNIFI_GW_CONFIG=CONF)
    for attempt in range(30):
        subprocess.run([GW, 'set-adopt', '-s', url], env=env)
        cfg.read(CONF)
        if cfg.getboolean('gateway', 'is_adopted'):
            break
        pending = [d for d in ctl.call('GET', 'stat/device')
                   if d['mac'] == mac and not d.get('adopted')]
        if pending:
            print('pending as', pending[0].get('model'), '- adopting')
            ctl.call('POST', 'cmd/devmgr', {'cmd': 'adopt', 'mac': mac})
        time.sleep(10)
    else:
        sys.exit('adoption did not complete; check the Devices page, or roll back')

    # 5. run
    sh('service', 'unifi_gateway', 'start')
    print('UXG-Max adopted and running; log: /var/log/unifi-gateway.log')


if __name__ == '__main__':
    main()
