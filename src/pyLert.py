import psutil
import socket
import json
import argparse
from datetime import datetime

class ConnectionMonitor:
    def __init__(self, output_format='table', filter_inbound=False, filter_outbound=False, filter_cdn=False):
        self.output_format = output_format
        self.filter_inbound = filter_inbound
        self.filter_outbound = filter_outbound
        self.filter_cdn = filter_cdn
        self.cdn_providers = {"Akamai": ["akamai.net", "akamaitechnologies.com"],
                              "Cloudflare": ["cloudflare.com"],
                              "Fastly": ["fastly.net"]}
    
    def get_connections(self):
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
            if self.filter_cdn and not cdn_match:
                continue
            
            connections.append({
                "process": process_name,
                "pid": pid,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "direction": direction,
                "cdn": cdn_match or "Unknown"
            })
        
        return connections
    
    def get_process_name(self, pid):
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "Unknown"

    def get_direction(self, local_ip, remote_ip):
        if not remote_ip:
            return "Inbound"
        return "Outbound"

    def check_cdn(self, remote_ip):
        try:
            hostname = socket.gethostbyaddr(remote_ip)[0]
            for provider, domains in self.cdn_providers.items():
                if any(domain in hostname for domain in domains):
                    return provider
        except (socket.herror, socket.gaierror):
            return None
        return None
    
    def format_output(self, connections):
        if self.output_format == 'json':
            return json.dumps(connections, indent=4)
        elif self.output_format == 'pascal':
            return self.format_pascal(connections)
        else:
            return self.format_table(connections)
    
    def format_table(self, connections):
        header = f"{'Process':20} {'PID':6} {'Local IP':15} {'L.Port':6} {'Remote IP':15} {'R.Port':6} {'Direction':10} {'CDN':10}"
        separator = '-' * len(header)
        rows = [header, separator]
        for conn in connections:
            rows.append(f"{conn['process']:20} {conn['pid']:6} {conn['local_ip']:15} {conn['local_port']:6} {conn['remote_ip'] or '-':15} {conn['remote_port'] or '-':6} {conn['direction']:10} {conn['cdn']:10}")
        return '\n'.join(rows)
    
    def format_pascal(self, connections):
        pascal_str = "type Connection = record\n"
        for conn in connections:
            pascal_str += f"    Process: string := '{conn['process']}';\n"
            pascal_str += f"    PID: integer := {conn['pid']};\n"
            pascal_str += f"    LocalIP: string := '{conn['local_ip']}';\n"
            pascal_str += f"    LocalPort: integer := {conn['local_port']};\n"
            pascal_str += f"    RemoteIP: string := '{conn['remote_ip'] or '-'}';\n"
            pascal_str += f"    RemotePort: integer := {conn['remote_port'] or 0};\n"
            pascal_str += f"    Direction: string := '{conn['direction']}';\n"
            pascal_str += f"    CDN: string := '{conn['cdn']}';\n"
        pascal_str += "end;"
        return pascal_str
    
    def run(self):
        connections = self.get_connections()
        print(self.format_output(connections))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor active network connections with process correlation.")
    parser.add_argument("--json", action="store_true", help="Output in JSON format.")
    parser.add_argument("--pascal", action="store_true", help="Output in Pascal format.")
    parser.add_argument("--only-outbound", action="store_true", help="Filter only outbound connections.")
    parser.add_argument("--only-inbound", action="store_true", help="Filter only inbound connections.")
    parser.add_argument("--filter-cdn", action="store_true", help="Filter only known CDN traffic.")
    
    args = parser.parse_args()
    output_format = 'json' if args.json else 'pascal' if args.pascal else 'table'
    
    monitor = ConnectionMonitor(output_format=output_format,
                               filter_inbound=args.only_inbound,
                               filter_outbound=args.only_outbound,
                               filter_cdn=args.filter_cdn)
    monitor.run()
