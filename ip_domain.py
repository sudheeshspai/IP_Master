import whois
import dns.resolver
import nmap

def whois_lookup(target):
    try:
        domain_info = whois.whois(target)
        return domain_info
    except whois.parser.PywhoisError:
        return None

def dns_dump(target):
    try:
        answers = dns.resolver.resolve(target, 'ANY')
        return answers
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return "No such domain exists"
    except dns.resolver.NoNameservers:
        return "No nameservers found for the domain"

def nmap_scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments='-Pn')  # '-Pn' option skips host discovery
        return nm[target]
    except nmap.PortScannerError:
        return None

def main():
    target = input("Enter domain name or IP address: ")

    # WHOIS lookup
    print("WHOIS Lookup:")
    domain_info = whois_lookup(target)
    if domain_info:
        print(domain_info)
    else:
        print("Failed to perform WHOIS lookup.")

    # DNS Dump
    print("\nDNS Dump:")
    dns_info = dns_dump(target)
    if dns_info:
        for rdata in dns_info:
            print(rdata)
    else:
        print("Failed to perform DNS dump.")

    # Nmap scan
    print("\nNmap Scan:")
    nmap_result = nmap_scan(target)
    if nmap_result:
        print("Open ports:")
        for port in nmap_result['tcp'].keys():
            print(f"Port {port}: {nmap_result['tcp'][port]['state']}")
    else:
        print("Failed to perform Nmap scan.")

if __name__ == "__main__":
    main()
