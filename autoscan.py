#!/usr/bin/python3
import nmap
scanner = nmap.PortScanner()
print("AUTOSCAN")

print("This tool automates your network scan!")
print("<------------------------------------------------------->")

ip = input("Enter the ip address you want to scan: ")
print("The ip address is: ", ip)

options = input("""\nPlease enter the type of scan you want to run
                1)Fast TCP Scan
                2)Fast UDP Scan
                3)Aggressive TCP Scan \n""")

print("Selected option: ", options)

if options == '1':
        scanner.scan(ip, '1-1024', '-sS')
        print(scanner.scaninfo())
        print("IP Status: ", scanner[ip].state())
        print(scanner[ip].all_protocols())
        print("Open Ports: ", scanner[ip]['tcp'].keys())

elif options == '2':
        scanner.scan(ip, '1-1024', '-sU')
        print(scanner.scaninfo())
        print("IP Status: ", scanner[ip].state())
        print(scanner[ip].all_protocols())
        print("Open Ports: ", scanner[ip]['udp'].keys())

elif options == '3':
        scanner.scan(ip, '1-49151', '-sS -v -sV -T4 -A -O')
        print(scanner.scaninfo())
        print("IP Status: ", scanner[ip].state())
        print(scanner[ip].all_protocols())
        print("Open Ports: ", scanner[ip]['tcp'].keys())
        print("OS: ", scanner.scan(ip, '1-49151', '-sS -v -sV -T4 -A -O')['scan'][ip]['osmatch'])
        for proto in scanner[ip].all_protocols():
                print("Protocol: ", proto)
                ports = scanner[ip][proto].keys()
                for port in ports:
                        print("Service: ", (port, scanner[ip][proto][port]['name']))
