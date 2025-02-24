import json
import os
import argparse
from datetime import datetime

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "pyLert.log")

class LogReader:
    def __init__(self, filter_process=None, filter_ip=None, filter_date=None, format_output='table'):
        self.filter_process = filter_process
        self.filter_ip = filter_ip
        self.filter_date = filter_date
        self.format_output = format_output

    def read_logs(self):
        if not os.path.exists(LOG_FILE):
            print("No log file found.")
            return []
        
        logs = []
        with open(LOG_FILE, 'r') as file:
            for line in file:
                try:
                    log_entry = json.loads(line.strip())
                    if self.apply_filters(log_entry):
                        logs.append(log_entry)
                except json.JSONDecodeError:
                    continue  # Skip malformed lines
        
        return logs

    def apply_filters(self, log_entry):
        if self.filter_process and self.filter_process.lower() not in log_entry['process'].lower():
            return False
        if self.filter_ip and (self.filter_ip != log_entry['local_ip'] and self.filter_ip != log_entry['remote_ip']):
            return False
        if self.filter_date and not log_entry['timestamp'].startswith(self.filter_date):
            return False
        return True

    def format_table(self, logs):
        header = f"{'Timestamp':25} {'Process':20} {'PID':6} {'Local IP':15} {'L.Port':6} {'Remote IP':15} {'R.Port':6} {'Direction':10} {'CDN':20}"
        separator = '-' * len(header)
        rows = [header, separator]
        for log in logs:
            rows.append(f"{log['timestamp']:25} {log['process']:20} {log['pid']:6} {log['local_ip']:15} {log['local_port']:6} {log['remote_ip']:15} {log['remote_port']:6} {log['direction']:10} {log['cdn']:20}")
        return '\n'.join(rows)
    
    def format_json(self, logs):
        return json.dumps(logs, indent=4)

    def display_logs(self):
        logs = self.read_logs()
        if not logs:
            print("No logs found matching criteria.")
            return
        
        if self.format_output == 'json':
            print(self.format_json(logs))
        else:
            print(self.format_table(logs))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read and filter pyLert logs.")
    parser.add_argument("--filter-process", type=str, help="Filter by process name.")
    parser.add_argument("--filter-ip", type=str, help="Filter by specific IP.")
    parser.add_argument("--filter-date", type=str, help="Filter by date (YYYY-MM-DD).")
    parser.add_argument("--json", action="store_true", help="Output in JSON format.")
    
    args = parser.parse_args()
    format_output = 'json' if args.json else 'table'
    
    reader = LogReader(filter_process=args.filter_process, filter_ip=args.filter_ip, filter_date=args.filter_date, format_output=format_output)
    reader.display_logs()
