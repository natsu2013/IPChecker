# IPChecker

```
▄█ █ ▄▄  ▄█▄     ▄  █ ▄███▄   ▄█▄    █  █▀ ▄███▄   █▄▄▄▄
██ █   █ █▀ ▀▄  █   █ █▀   ▀  █▀ ▀▄  █▄█   █▀   ▀  █  ▄▀
██ █▀▀▀  █   ▀  ██▀▀█ ██▄▄    █   ▀  █▀▄   ██▄▄    █▀▀▌ 
▐█ █     █▄  ▄▀ █   █ █▄   ▄▀ █▄  ▄▀ █  █  █▄   ▄▀ █  █ 
 ▐  █    ▀███▀     █  ▀███▀   ▀███▀    █   ▀███▀     █  
     ▀            ▀                   ▀             ▀   
```

## Description
This Python tool provides a comprehensive overview of selected IP addresses by retrieving detailed reports from VirusTotal and additional information such as hostname, anycast, and region from IPInfo. It is designed to offer an overview analysis of IP addresses through a combination of these APIs.

## Usage

```bash

PS C:\Users\user01\ipchecker> python .\ipchecker.py
[+] - Enter some IP addresses here: 128.8.10.90 192.33.4.12 192.36.148.17 192.112.36.4 128.63.2.53
╒════════════════════╤═══════╤═════════════╤════════════╤══════════════╤═════════════════════════════╤═══════════╤══════════════════╕
│ ip                 │   asn │ malicious   │ harmless   │ undetected   │ hostname                    │ anycast   │ region           │
╞════════════════════╪═══════╪═════════════╪════════════╪══════════════╪═════════════════════════════╪═══════════╪══════════════════╡
│ 128.8.10.90 (US)   │    27 │ 0/90        │ 64/90      │ 26/90        │  Null                       │ False     │ Maryland         │
├────────────────────┼───────┼─────────────┼────────────┼──────────────┼─────────────────────────────┼───────────┼──────────────────┤
│ 192.33.4.12 (US)   │  2149 │ 2/90        │ 63/90      │ 25/90        │  c.root-servers.net         │ True      │ Washington, D.C. │
├────────────────────┼───────┼─────────────┼────────────┼──────────────┼─────────────────────────────┼───────────┼──────────────────┤
│ 192.36.148.17 (SE) │ 29216 │ 0/90        │ 64/90      │ 26/90        │  i.root-servers.net         │ True      │ Stockholm        │
├────────────────────┼───────┼─────────────┼────────────┼──────────────┼─────────────────────────────┼───────────┼──────────────────┤
│ 192.112.36.4 (US)  │  5927 │ 0/90        │ 64/90      │ 26/90        │  g.root-servers.net         │ False     │ Ohio             │
├────────────────────┼───────┼─────────────┼────────────┼──────────────┼─────────────────────────────┼───────────┼──────────────────┤
│ 128.63.2.53 (US)   │    13 │ 0/90        │ 64/90      │ 26/90        │  do-not-reuse.arl.army.mil  │ False     │ Maryland         │
╘════════════════════╧═══════╧═════════════╧════════════╧══════════════╧═════════════════════════════╧═══════════╧══════════════════╛

[!] - This tool is intended solely for coding practice and should be used as a reference only.
```
