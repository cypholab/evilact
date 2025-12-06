# evilact

Fast vulnerability scanner for CVE-2025-55182 and CVE-2025-66478 in Next.js applications using React Server Components. Supports bulk scanning, RCE confirmation, and high-performance concurrent checks.

## Install
```bash
git clone https://github.com/orgs/cypholab/evilact.git
cd evilact
go build -o scanner main.go
```

## Usage
```bash
# Single URL
./scanner -url https://target.com

# Multiple URLs from file
./scanner -file targets.txt

# With RCE confirmation
./scanner -url https://target.com -confirm-rce

# Fast scan with 50 threads
./scanner -file targets.txt -threads 50
```

## Options
```
-url            Single target URL
-file           File with URLs (one per line)
-c              Command to execute (default: id)
-threads        Number of threads (default: 10)
-confirm-rce    Confirm RCE execution
-check-only     Safe check mode
-v              Verbose output
-t              Timeout in seconds (default: 10)
```

## Example
```bash
./scanner -file targets.txt -threads 20 -confirm-rce

[SCANNER] Loaded 100 URLs
[SCANNER] [VULNERABLE + RCE CONFIRMED] https://site1.com - Status: 303 (0.18s)
[SCANNER] [NOT VULNERABLE] https://site2.com - Status: 200 (0.15s)

Scanned 100 targets: 5 vulnerable, 5 RCE confirmed, 95 secure, 0 errors

Vulnerable targets:
  - https://site1.com [RCE CONFIRMED]
  - https://site3.com [RCE CONFIRMED]
```

## Disclaimer

For authorized testing only. Illegal use is prohibited.

## References

- High-Fidelity Detection Mechanism for RSC Next.js RCE (CVE-2025-55182 & CVE-2025-66478):
  https://slcyber.io/research-center/high-fidelity-detection-mechanism-for-rsc-next-js-rce-cve-2025-55182-cve-2025-66478/
