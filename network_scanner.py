import socket
import threading
import json
from datetime import datetime
from queue import Queue
import sys

# Common ports and their default services
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

class NetworkScanner:
    def __init__(self, target, max_threads=100, timeout=1.0):
        self.target = target
        self.max_threads = max_threads
        self.timeout = timeout
        self.queue = Queue()
        self.open_ports = {}
        self.lock = threading.Lock()

    def get_banner(self, sock):
        try:
            sock.sendall(b'Hello\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "No banner grabbed"
        except:
            return "No banner grabbed"

    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown Service")
                banner = self.get_banner(sock)
                with self.lock:
                    self.open_ports[port] = {
                        "service": service,
                        "banner": banner
                    }
            sock.close()
        except Exception:
            pass

    def _worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()

    def start_scan(self, start_port=1, end_port=1024):
        print(f"[*] Initializing scan on target: {self.target}")
        print(f"[*] Scanning ports from {start_port} to {end_port}...")
        
        for port in range(start_port, end_port + 1):
            self.queue.put(port)

        threads = []
        for _ in range(min(self.max_threads, self.queue.qsize())):
            t = threading.Thread(target=self._worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
            
        print("[+] Scan completed successfully.")
        return self.open_ports

    def save_results(self, filename="scan_report.json"):
        report = {
            "target": self.target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "open_ports": self.open_ports
        }
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        print(f"[+] Diagnostic report saved to: {filename}")

if __name__ == "__main__":
    print("=== Advanced Network Security Scanner ===")
    target_host = input("Enter target IP or Domain (e.g., 127.0.0.1): ").strip()
    if not target_host:
        print("Error: Target host cannot be empty.")
        sys.exit(1)
        
    s_port = int(input("Enter start port (default 1): ") or 1)
    e_port = int(input("Enter end port (default 1024): ") or 1024)
    threads_count = int(input("Enter number of threads (default 100): ") or 100)

    scanner = NetworkScanner(target=target_host, max_threads=threads_count)
    results = scanner.start_scan(start_port=s_port, end_port=e_port)
    
    print("\n--- Scan Summary ---")
    if not results:
        print("No open ports found in the specified range.")
    else:
        for port, info in sorted(results.items()):
            print(f"Port {port}: [{info['service']}] -> {info['banner']}")
            
    scanner.save_results()
