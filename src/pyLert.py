import psutil
import socket
import json
import argparse
import os
from datetime import datetime, timedelta
from termcolor import colored

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "pyLert.log")
LOG_RETENTION_DAYS = 7  # Auto-delete logs older than this

class ConnectionMonitor:
    """
    A class to monitor active network connections on the system and log them.
    
    Attributes:
        output_format (str): The format for displaying output (table, json, pascal).
        filter_inbound (bool): Whether to filter only inbound connections.
        filter_outbound (bool): Whether to filter only outbound connections.
        filter_cdn (bool): Whether to filter only known CDN traffic.
        filter_process (str): Process name filter.
        filter_port (int): Port number filter.
        log_to_file (bool): Whether to log results to a file.
    """
    
    def __init__(self, output_format='table', filter_inbound=False, filter_outbound=False, filter_cdn=False, filter_process=None, filter_port=None, log_to_file=False):
        """
        Initializes the ConnectionMonitor with optional filters and logging settings.
        
        Args:
            output_format (str, optional): Output format (table, json, pascal). Defaults to 'table'.
            filter_inbound (bool, optional): Filter inbound connections. Defaults to False.
            filter_outbound (bool, optional): Filter outbound connections. Defaults to False.
            filter_cdn (bool, optional): Filter only CDN traffic. Defaults to False.
            filter_process (str, optional): Process name to filter connections. Defaults to None.
            filter_port (int, optional): Port number to filter connections. Defaults to None.
            log_to_file (bool, optional): Enable logging to file. Defaults to False.
        """
        self.output_format = output_format
        self.filter_inbound = filter_inbound
        self.filter_outbound = filter_outbound
        self.filter_cdn = filter_cdn
        self.filter_process = filter_process
        self.filter_port = filter_port
        self.log_to_file = log_to_file
        self.cdn_providers = {
            "Akamai": ["akamai.net", "akamaitechnologies.com"],
            "Cloudflare": ["cloudflare.com"],
            "Fastly": ["fastly.net"],
            "Amazon CloudFront": ["cloudfront.net"],
            "Google": ["google.com", "googleusercontent.com"],
            "Microsoft Azure": ["azureedge.net", "microsoft.com"],
            "Apple": ["apple.com", "icloud.com"],
            "Facebook": ["fbcdn.net", "facebook.com"]
        }
        self.ensure_log_directory()
        self.cleanup_old_logs()
    
    def ensure_log_directory(self):
        """Ensures the log directory exists."""
        if not os.path.exists(LOG_DIR):
            os.makedirs(LOG_DIR)
    
    def cleanup_old_logs(self):
        """
        Deletes log entries older than the retention period.
        """
        if not os.path.exists(LOG_FILE):
            return
        
        temp_logs = []
        cutoff_date = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
        
        with open(LOG_FILE, 'r') as file:
            for line in file:
                try:
                    log_entry = json.loads(line.strip())
                    log_time = datetime.fromisoformat(log_entry.get("timestamp", ""))
                    if log_time >= cutoff_date:
                        temp_logs.append(line)
                except (json.JSONDecodeError, ValueError):
                    continue  # Skip malformed log entries
        
        with open(LOG_FILE, 'w') as file:
            file.writelines(temp_logs)  # Rewrite only recent logs
    
    def get_connections(self):
        """
        Retrieves and filters network connections based on the specified criteria.
        
        Returns:
            list: A list of filtered network connection dictionaries.
        """
        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status not in ('ESTABLISHED', 'LISTEN'):
                continue

            local_ip, local_port = conn.laddr
            remote_ip, remote_port = conn.raddr if conn.raddr else (None, None)
            pid = conn.pid
            process_name = self.get_process_name(pid)
            direction = self.get_direction(local_ip, remote_ip)
            cdn_match = self.check_cdn(remote_ip)

            if self.filter_outbound and direction != "Outbound":
                continue
            if self.filter_inbound and direction != "Inbound":
                continue
            if self.filter_cdn and cdn_match == "Unknown":
                continue
            if self.filter_process and self.filter_process.lower() not in process_name.lower():
                continue
            if self.filter_port and (remote_port != self.filter_port and local_port != self.filter_port):
                continue
            
            conn_data = {
                "timestamp": datetime.now().isoformat(),
                "process": process_name,
                "pid": pid,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip if remote_ip else '-',
                "remote_port": remote_port if remote_port else '-',
                "direction": direction,
                "cdn": cdn_match
            }
            
            connections.append(conn_data)
            
        return connections
    
    def get_process_name(self, pid):
        """Retrieves the process name for a given PID."""
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "Unknown"

    def get_direction(self, local_ip, remote_ip):
        """Determines whether a connection is inbound or outbound."""
        if not remote_ip:
            return "Inbound"
        return "Outbound"

    def check_cdn(self, remote_ip):
        """Checks if a remote IP belongs to a known CDN provider."""
        if not remote_ip:
            return "Unknown"
        
        try:
            hostname = socket.gethostbyaddr(remote_ip)[0]
            for provider, domains in self.cdn_providers.items():
                if any(domain in hostname for domain in domains):
                    return provider
        except (socket.herror, socket.gaierror):
            return "Unknown"
        
        return "Unknown"
    
    def log_connections(self, connections):
        """Logs network connections to a file."""
        if not self.log_to_file:
            return
        
        with open(LOG_FILE, 'a') as log_file:
            for conn in connections:
                log_file.write(json.dumps(conn) + "\n")
    
    def run(self):
        """Executes the connection monitoring process."""
        connections = self.get_connections()
        self.log_connections(connections)
        print(json.dumps(connections, indent=4) if self.output_format == 'json' else connections)
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor active network connections with process correlation.")
    parser.add_argument("--log", action="store_true", help="Enable logging to file.")
    args = parser.parse_args()
    
    monitor = ConnectionMonitor(log_to_file=args.log)
    monitor.run()
