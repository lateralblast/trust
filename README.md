Introduction
------------

Trust (To RUn SheeT) is a ruby script that transforms the CIS (and in future other)
security recommendations PDF into a run sheet template.

License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode

Features
--------

- Supoorts most recent CIS document format/layout
- Supports export in text, CSV, and XLS format
- The CSV format extracts commands where possible

Requirements
------------

Ruby modules:

- getopt/std
- pathname
- fileutils
- writeexcel

Tools:

- pdftotext
- dos2unix

Examples
--------

List Available PDFs:

```
$ trust.rb -l
/Users/spindler/Code/trust/pdfs/CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Apple_OSX_10.8_Benchmark_v1.0.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Apple_OSX_10.9_Benchmark_v1.0.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_CentOS_Linux_6_Benchmark_v1.0.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_IBM_AIX_5.3-6.1_Benchmark_v1.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_IBM_AIX_7.1_Benchmark_v1.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Microsoft_Windows_Server_2003_Benchmark_v3.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Microsoft_Windows_Server_2008_Benchmark_v2.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Microsoft_Windows_Server_2008_R2_Benchmark_v2.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Microsoft_Windows_Server_2012_Benchmark_v1.0.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Oracle_Solaris_10_Benchmark_v5.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Oracle_Solaris_11.1_Benchmark_v1.0.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Oracle_Solaris_11_Benchmark_v1.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Red_Hat_Enterprise_Linux_5_Benchmark_v2.1.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Red_Hat_Enterprise_Linux_6_Benchmark_v1.2.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_Red_Hat_Enterprise_Linux_7_Benchmark_v1.0.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_SUSE_Linux_Enterprise_Server_11_Benchmark_v1.0.0.pdf
/Users/spindler/Code/trust/pdfs/CIS_VMware_ESXi_5.1_Benchmark_v1.0.1.pdf
/Users/spindler/Code/trust/pdfs/CIS_VMware_ESXi_5.5_Benchmark_v1.0.0.pdf
```

XLS ouput:

```
$ trust.rb -x -f /Users/spindler/Code/trust/pdfs/CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf -o test.xls
```

Text output to STDOUT:

```
$ trust.rb -t -f /Users/spindler/Code/trust/pdfs/CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf

Resource:    CIS
File:        CIS_Apache_HTTP_Server_2.4_Benchmark_v1.1.0.pdf
Version      1.1.0
Section:     1.1.1
Page:        9
Test:        Pre-Installation Planning Checklist
Level:       1
Vendor:      Apache
OS:          HTTP Server
OS Rel:      2.4
Impact:
Description:
Review and implement the following items as appropriate:
Reviewed and implemented company's security policies as they relate to web
security.
Implemented a secure network infrastructure by controlling access to/from your
web server by using firewalls, routers and switches.
Harden the underlying Operating System of the web server, by minimizing listening
network services, applying proper patches and hardening the configurations as
recommended in the appropriate Center for Internet Security benchmark for the
platform.
Implement central log monitoring processes.
Implemented a disk space monitoring process and log rotation mechanism.
Educate developers, architects and testers about developing secure applications,
and integrate security into the software development
lifecycle. https://www.owasp.org/ http://www.webappsec.org/
Ensure the WHOIS Domain information registered for our web presence does not
reveal sensitive personnel information, which may be leveraged for Social
Engineering (Individual POC Names), War Dialing (Phone Numbers) and Brute
Force Attacks (Email addresses matching actual system usernames).
Ensure your Domain Name Service (DNS) servers have been properly secured to
prevent attacks, as recommended in the CIS BIND DNS Benchmark.
Implemented a Network Intrusion Detection System to monitor attacks against the
web server.
Rationale:
Audit:
Check:
Remediation:
Fix:
Impact:
```


Usage
-----

Getting usage information:

```
$ trust.rb -h

Usage: ./trust.rb -[acd:hf:lo:p:r:tvVx]

-V: Display version information
-h: Display usage information
-a: Process all PDFs
-d: Set PDF directory
-f: Process a file
-l: List all pdf files
-p: Set product
-r: Set release
-o: Output to file
-t: Output in TXT mode
-c: Output in CSV mode
-x: Output in XLS mode
-v: Verbose mode
```
