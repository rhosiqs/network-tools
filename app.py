import os
import re
import platform
import subprocess
import time
import csv
import threading
import json
import socket
import webbrowser
from threading import Timer
from datetime import datetime
from datetime import datetime
from flask import Flask, jsonify, render_template, request, Response, stream_with_context

app = Flask(__name__)

# ======= Adjustable Monitoring Parameters (Default) =======
default_config = {
    'monitor_minutes': 10,
    'monitor_minutes': 10,
    'interval_seconds': 10,
    'continuous_monitoring_seconds': 60,
    'ping_frequency': 3, # Perform ping every N checks
    'target_gateway': 'AUTO',
    'target_isp_dns': '140.120.1.2',
    'target_hinet_dns': '168.95.1.1',
    'target_google_dns': '8.8.8.8',
    'target_resolution': 'www.google.com'
}
current_config = default_config.copy()
# =================================

# Global state to store the latest result and control the thread
current_status = {
    'running': False,
    'data': None,
    'log': [], # Stores full history for CSV export
    'display_log': [], # Short history for UI
    'error_mode': False
}

monitor_thread = None
stop_event = threading.Event()

def get_gateway():
    try:
        output = os.popen('ipconfig').read()
        lines = output.splitlines()
        ipv4 = None
        ipv6 = None
        for i, line in enumerate(lines):
            if 'Default Gateway' in line:
                # Check current line first
                m4 = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if m4 and m4.group(1) != '0.0.0.0':
                    ipv4 = m4.group(1)
                    break
                m6 = re.search(r'([a-fA-F0-9:]+)', line)
                if m6 and not ipv4:
                    ipv6 = m6.group(1)
                # Check next line (usually indented)
                if i + 1 < len(lines):
                    next_line = lines[i + 1].strip()
                    m4 = re.search(r'(\d+\.\d+\.\d+\.\d+)', next_line)
                    if m4 and m4.group(1) != '0.0.0.0':
                        ipv4 = m4.group(1)
                        break
                    m6 = re.search(r'([a-fA-F0-9:]+)', next_line)
                    if m6 and not ipv4:
                        ipv6 = m6.group(1)
        return ipv4 or ipv6
    except Exception:
        return None

def ping(host):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '2', host]
    try:
        # Create a startupinfo object to hide the console window
        startupinfo = None
        if platform.system().lower() == 'windows':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, encoding='utf-8', startupinfo=startupinfo)
        success = result.returncode == 0
        # Parse latency
        latency = None
        if success:
            # Windows: Average = XXms
            match = re.search(r'Average = (\d+)ms', result.stdout)
            if not match:
                # English system: Average = XXms
                match = re.search(r'Average = (\d+)ms', result.stdout)
            if match:
                latency = int(match.group(1))
            else:
                # Linux: time=XX ms
                match = re.search(r'time[=<]([\d\.]+) ?ms', result.stdout)
                if match:
                    latency = float(match.group(1))
        return success, latency
    except Exception:
        return False, None

def perform_test(test_name, target, do_ping, test_func=None):
    if do_ping:
        return ping(target)
    elif test_func:
        try:
            return test_func(target), None
        except Exception:
            return False, None
    return True, None

def check_network(do_ping=True):
    result = {key: None for key in [
        'time', 'loopback', 'loopback_latency',
        'gateway_ip', 'gateway', 'gateway_latency',
        'dns_isp', 'dns_isp_latency', 'dns_isp_ip',
        'dns_hinet', 'dns_hinet_latency', 'dns_hinet_ip',
        'dns_google', 'dns_google_latency', 'dns_google_ip',
        'dns_resolution', 'dns_resolution_latency', 'resolved_ip'
    ]}

    result['time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Loopback test
    result['loopback'], result['loopback_latency'] = perform_test('loopback', '127.0.0.1', do_ping)

    # Gateway test
    gateway = get_gateway()
    if current_config['target_gateway'] != 'AUTO' and current_config['target_gateway'].strip():
        gateway = current_config['target_gateway']
        
    result['gateway_ip'] = gateway if gateway else 'N/A'
    if gateway:
        result['gateway'], result['gateway_latency'] = perform_test('gateway', gateway, do_ping)
    else:
        result['gateway'] = False
        result['gateway_latency'] = None

    # ISP DNS test
    dns_isp_ip = current_config['target_isp_dns']
    result['dns_isp'], result['dns_isp_latency'] = perform_test('dns_isp', dns_isp_ip, do_ping)
    result['dns_isp_ip'] = dns_isp_ip

    # Hinet DNS test
    dns_hinet_ip = current_config['target_hinet_dns']
    result['dns_hinet'], result['dns_hinet_latency'] = perform_test('dns_hinet', dns_hinet_ip, do_ping)
    result['dns_hinet_ip'] = dns_hinet_ip

    # Google DNS test (8.8.8.8)
    dns_google_ip = current_config['target_google_dns']
    result['dns_google'], result['dns_google_latency'] = perform_test('dns_google', dns_google_ip, do_ping)
    result['dns_google_ip'] = dns_google_ip

    # DNS resolution test
    try:
        result['resolved_ip'] = socket.gethostbyname(current_config['target_resolution'])
        result['dns_resolution'] = True
    except Exception:
        result['resolved_ip'] = 'N/A'
        result['dns_resolution'] = False

    return result

def has_failure(result):
    test_keys = ['loopback', 'gateway', 'dns_isp', 'dns_hinet', 'dns_google', 'dns_resolution']
    for key in test_keys:
        if key in result and result[key] is False:
            return True
    return False

def get_failure_annotation(result):
    failures = []
    test_keys = ['loopback', 'gateway', 'dns_isp', 'dns_hinet', 'dns_google', 'dns_resolution']
    for key in test_keys:
        if key in result and result[key] is False:
            failures.append(key)
    if failures:
        return f"[ERROR] FAILED TESTS: {', '.join(failures)}"
    return ""

from flask import Flask, jsonify, render_template, Response, stream_with_context

# ... (existing imports)

def generate_csv(records):
    fieldnames = [
        'time', 'loopback', 'loopback_latency',
        'gateway_ip', 'gateway', 'gateway_latency',
        'dns_isp', 'dns_isp_latency', 'dns_isp_ip',
        'dns_hinet', 'dns_hinet_latency', 'dns_hinet_ip',
        'dns_google', 'dns_google_latency', 'dns_google_ip',
        'dns_resolution', 'dns_resolution_latency', 'resolved_ip',
        'failure_annotation'
    ]
    
    # Yield header
    yield ','.join(fieldnames) + '\n'
    
    # Yield rows
    for record in records:
        row = []
        for field in fieldnames:
            val = record.get(field, '')
            if val is None: val = ''
            row.append(str(val))
        yield ','.join(row) + '\n'

@app.route('/api/export_csv')
def export_csv():
    try:
        # Create a copy to avoid concurrency issues
        logs_to_export = list(current_status['log'])
        
        output = []
        # Generate header
        fieldnames = [
            'time', 'loopback', 'loopback_latency',
            'gateway_ip', 'gateway', 'gateway_latency',
            'dns_isp', 'dns_isp_latency', 'dns_isp_ip',
            'dns_hinet', 'dns_hinet_latency', 'dns_hinet_ip',
            'dns_google', 'dns_google_latency', 'dns_google_ip',
            'dns_resolution', 'dns_resolution_latency', 'resolved_ip',
            'failure_annotation'
        ]
        output.append(','.join(fieldnames))
        
        # Generate rows
        for record in logs_to_export:
            row = []
            for field in fieldnames:
                val = record.get(field, '')
                if val is None: val = ''
                row.append(str(val))
            output.append(','.join(row))
            
        csv_content = '\n'.join(output)
        
        return Response(
            '\ufeff' + csv_content, # Add BOM for Excel compatibility
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=network_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'}
        )
    except Exception as e:
        print(f"Export Error: {e}")
        return jsonify({'error': str(e)}), 500

def save_csv(records):
    # Legacy function - no longer used for auto-save, but kept for reference or local backup if needed
    pass

def monitor_loop():
    global current_status
    records = []
    current_status['running'] = True
    # current_status['log'] = [] # Don't clear logic on start, allows cumulative logs. OR clear if user wants fresh start.
    # Let's clear for now to match session-based expectation
    current_status['log'] = [] 
    current_status['display_log'] = []
    
    in_continuous_mode = False
    continuous_start_time = None
    continuous_success_start_time = None
    
    i = 0
    try:
        # Run indefinitely until stopped
        while not stop_event.is_set():
            do_ping = (i % current_config['ping_frequency'] == 0) or in_continuous_mode
            
            # (Loop content unchanged, just indented)
            # Perform check
            res = check_network(do_ping=do_ping)
            
            failure_detected = has_failure(res)
            failure_annotation = get_failure_annotation(res)
            res['failure_annotation'] = failure_annotation
            
            # Update logic similar to original script
            if failure_detected:
                if not in_continuous_mode:
                    in_continuous_mode = True
                    continuous_start_time = time.time()
                    continuous_success_start_time = None
                    current_status['error_mode'] = True
                else:
                    continuous_success_start_time = None
            elif in_continuous_mode:
                if continuous_success_start_time is None:
                    continuous_success_start_time = time.time()
                elif time.time() - continuous_success_start_time >= current_config['continuous_monitoring_seconds']:
                    in_continuous_mode = False
                    continuous_start_time = None
                    continuous_success_start_time = None
                    current_status['error_mode'] = False

            # Store result
            current_status['data'] = res
            records.append(res)
            
            # Store full history for CSV
            current_status['log'].append(res)
            
            # Store short history for UI display
            if len(current_status['display_log']) > 50:
                current_status['display_log'].pop(0)
            current_status['display_log'].append(res)

            if not in_continuous_mode:
                i += 1
                # Sleep in small chunks to allow responsive stop
                for _ in range(current_config['interval_seconds']):
                    if stop_event.is_set(): break
                    time.sleep(1)
            elif in_continuous_mode:
                time.sleep(1)
    except Exception as e:
        print(f"Monitor thread crashed: {e}")
    finally:
        # Check if we should save on exit (if manual stop or crash)
        # save_csv(records) # Removed per user preference
        current_status['running'] = False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    return jsonify(current_status)

@app.route('/api/start')
def start_monitoring():
    global monitor_thread
    if not current_status['running']:
        stop_event.clear()
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    return jsonify({'status': 'started'})

@app.route('/api/stop')
def stop_monitoring():
    if current_status['running']:
        stop_event.set()
    return jsonify({'status': 'stopping'})

@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify(current_config)

@app.route('/api/config', methods=['POST'])
def update_config():
    global current_config
    try:
        data = request.json
        # Update only valid keys
        for key in default_config:
            if key in data:
                if key == 'interval_seconds' or key == 'continuous_monitoring_seconds' or key == 'ping_frequency' or key == 'monitor_minutes':
                    current_config[key] = int(data[key])
                else:
                    current_config[key] = str(data[key])
        
        # Clear stale data so UI doesn't show mismatch
        current_status['data'] = None
        
        return jsonify({'status': 'updated', 'config': current_config})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    # Auto-open browser
    def open_browser():
        webbrowser.open_new('http://127.0.0.1:5000/')
        
    Timer(1.5, open_browser).start()
    app.run(debug=True, use_reloader=False) # use_reloader=False to avoid double threads
