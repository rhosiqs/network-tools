"""
tcp53_config.py
------------------------------------------------------------------
Loads config/tcp53.config.json -- the same file the PowerShell scripts
read, one directory up from this one -- and turns its target list into
concrete servers.

Keeping a single configuration for both platforms is deliberate: a
Windows laptop and a Linux workstation on the same network have to
probe the same servers with the same query, or their logs cannot be
compared against each other.
"""

import json
import os
from types import SimpleNamespace

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_CONFIG_PATH = os.path.join(REPO_ROOT, 'config', 'tcp53.config.json')


def load_config(path=None):
    """Reads the JSON configuration, tolerating a UTF-8 BOM."""
    path = path or DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        raise SystemExit('Configuration file not found: %s' % path)
    with open(path, 'r', encoding='utf-8-sig') as handle:
        return json.load(handle)


def resolve_log_directory(config, script_root, override=None):
    """Absolute log directory, relative paths anchored at the script."""
    directory = override or config.get('LogDirectory') or 'logs'
    directory = os.path.expanduser(directory)
    if not os.path.isabs(directory):
        directory = os.path.join(script_root, directory)
    return os.path.normpath(directory)


def split_target_filter(values):
    """--target accepts a repeated flag, a comma list, or both."""
    names = []
    for value in values or []:
        for part in str(value).replace(';', ',').split(','):
            part = part.strip()
            if part:
                names.append(part)
    return names


def resolve_targets(config, gateway_ip=None, only=None, warn=None):
    """Expands the configured targets, dropping the ones we cannot probe.

    AUTO_GATEWAY becomes the default gateway: the local router is the
    device most likely to be both running a DNS forwarder and holding
    the rule, so it is worth probing under whatever address it has today.
    """
    only = only or []
    targets = []

    for entry in config.get('Targets', []):
        if not entry.get('Enabled', True):
            continue
        if only and entry.get('Name') not in only:
            continue

        server = entry.get('Server')
        if server == 'AUTO_GATEWAY':
            server = gateway_ip
            if not server:
                if warn:
                    warn("Target '%s' skipped: no default gateway could be determined."
                         % entry.get('Name'))
                continue

        targets.append(SimpleNamespace(name=entry.get('Name'), server=server,
                                       note=entry.get('Note')))
    return targets
