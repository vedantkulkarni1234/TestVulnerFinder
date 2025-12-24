"""
PCAP parser utility for extracting network traffic metadata
"""

import io
from collections import Counter
from typing import Dict, List, Set


def summarize_pcap_bytes(pcap_bytes: bytes, max_packets: int = 4000) -> str:
    """
    Parse PCAP/PCAPNG bytes and return a text summary suitable for LLM analysis.
    
    Extracts:
    - Source/dest IPs
    - Source/dest ports
    - Protocols
    - DNS queries
    - HTTP requests
    - Suspicious patterns
    """
    try:
        import dpkt
        import socket
    except ImportError:
        return "[PCAP PARSER ERROR] dpkt library not installed. Install with: pip install dpkt"
    
    summary_lines = []
    
    # Statistics
    ip_sources: Counter = Counter()
    ip_dests: Counter = Counter()
    ports: Counter = Counter()
    protocols: Counter = Counter()
    dns_queries: Set[str] = set()
    http_requests: List[Dict] = []
    suspicious_ips: Set[str] = set()
    
    packet_count = 0
    
    try:
        # Try PCAP format
        try:
            pcap = dpkt.pcap.Reader(io.BytesIO(pcap_bytes))
        except Exception:
            # Try PCAPNG format
            pcap = dpkt.pcapng.Reader(io.BytesIO(pcap_bytes))
        
        for ts, buf in pcap:
            if packet_count >= max_packets:
                summary_lines.append(f"\n[NOTE] Truncated at {max_packets} packets for performance")
                break
            
            packet_count += 1
            
            try:
                # Parse Ethernet frame
                eth = dpkt.ethernet.Ethernet(buf)
                
                # Only process IP packets
                if not isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    continue
                
                ip = eth.data
                
                # Get IP addresses
                try:
                    src_ip = socket.inet_ntop(socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.src)
                    dst_ip = socket.inet_ntop(socket.AF_INET if isinstance(ip, dpkt.ip.IP) else socket.AF_INET6, ip.dst)
                except Exception:
                    continue
                
                ip_sources[src_ip] += 1
                ip_dests[dst_ip] += 1
                
                # Check for private vs public IPs
                if not _is_private_ip(dst_ip):
                    suspicious_ips.add(dst_ip)
                
                # Parse transport layer
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    protocols["TCP"] += 1
                    ports[tcp.dport] += 1
                    
                    # Check for HTTP
                    if tcp.dport == 80 or tcp.sport == 80:
                        try:
                            http = dpkt.http.Request(tcp.data)
                            http_requests.append({
                                "method": http.method,
                                "uri": http.uri,
                                "host": http.headers.get("host", dst_ip)
                            })
                        except Exception:
                            pass
                    
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    protocols["UDP"] += 1
                    ports[udp.dport] += 1
                    
                    # Check for DNS
                    if udp.dport == 53 or udp.sport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            if dns.qd:
                                for q in dns.qd:
                                    dns_queries.add(q.name)
                        except Exception:
                            pass
                
                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    protocols["ICMP"] += 1
                
            except Exception:
                continue
    
    except Exception as e:
        return f"[PCAP PARSER ERROR] {str(e)}"
    
    # Build summary
    summary_lines.append(f"=== PCAP ANALYSIS SUMMARY ===")
    summary_lines.append(f"Total Packets Analyzed: {packet_count}")
    summary_lines.append("")
    
    summary_lines.append("### PROTOCOL DISTRIBUTION")
    for proto, count in protocols.most_common():
        summary_lines.append(f"  {proto}: {count}")
    summary_lines.append("")
    
    summary_lines.append("### TOP SOURCE IPs")
    for ip, count in ip_sources.most_common(10):
        summary_lines.append(f"  {ip}: {count} packets")
    summary_lines.append("")
    
    summary_lines.append("### TOP DESTINATION IPs")
    for ip, count in ip_dests.most_common(10):
        summary_lines.append(f"  {ip}: {count} packets")
    summary_lines.append("")
    
    summary_lines.append("### TOP DESTINATION PORTS")
    for port, count in ports.most_common(15):
        port_name = _get_port_name(port)
        summary_lines.append(f"  {port} ({port_name}): {count}")
    summary_lines.append("")
    
    if dns_queries:
        summary_lines.append("### DNS QUERIES (Sample)")
        for query in list(dns_queries)[:20]:
            summary_lines.append(f"  {query}")
        if len(dns_queries) > 20:
            summary_lines.append(f"  ... and {len(dns_queries) - 20} more")
        summary_lines.append("")
    
    if http_requests:
        summary_lines.append("### HTTP REQUESTS (Sample)")
        for req in http_requests[:10]:
            summary_lines.append(f"  {req['method']} {req['host']}{req['uri']}")
        if len(http_requests) > 10:
            summary_lines.append(f"  ... and {len(http_requests) - 10} more")
        summary_lines.append("")
    
    if suspicious_ips:
        summary_lines.append("### EXTERNAL IPs (Potential IOCs)")
        for ip in list(suspicious_ips)[:30]:
            summary_lines.append(f"  {ip}")
        if len(suspicious_ips) > 30:
            summary_lines.append(f"  ... and {len(suspicious_ips) - 30} more")
        summary_lines.append("")
    
    return "\n".join(summary_lines)


def _is_private_ip(ip: str) -> bool:
    """Check if IP is in private ranges"""
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except Exception:
            pass
    if ip.startswith("127."):
        return True
    if ip.startswith("169.254."):
        return True
    return False


def _get_port_name(port: int) -> str:
    """Get common port names"""
    port_names = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    return port_names.get(port, "Unknown")
