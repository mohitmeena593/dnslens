# DNSLens

``` text
██████╗ ███╗   ██╗███████╗██╗     ███████╗███╗   ██╗███████╗
██╔══██╗████╗  ██║██╔════╝██║     ██╔════╝████╗  ██║██╔════╝
██║  ██║██╔██╗ ██║███████╗██║     █████╗  ██╔██╗ ██║███████╗
██║  ██║██║╚██╗██║╚════██║██║     ██╔══╝  ██║╚██╗██║╚════██║
██████╔╝██║ ╚████║███████║███████╗███████╗██║ ╚████║███████║
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝
```

> **DNS & Reverse DNS Lookup Utility**

DNSLens is a lightweight web-based DNS utility for resolving domain
names to IPv4/IPv6 addresses and IP addresses to hostnames.

## Features

-   Domain → IPv4 lookup
-   Domain → IPv6 lookup
-   IPv4 → Reverse DNS / PTR lookup
-   IPv6 → Reverse DNS / PTR lookup
-   Automatic input detection
-   URL hostname extraction
-   Multiple input support
-   Copy lookup results
-   Export results
-   Responsive interface
-   Clean cyber-style UI

## How It Works

``` text
                 DNSLENS
                    │
          ┌─────────┴─────────┐
          │                   │
       DOMAIN                 IP
          │                   │
      A / AAAA                PTR
          │                   │
          ▼                   ▼
       IP ADDRESS          HOSTNAME
```

### Domain → IP

Enter a domain or URL:

``` text
example.com
```

DNSLens queries DNS records and displays available IPv4 and IPv6
addresses.

### IP → Domain

Enter an IP address:

``` text
8.8.8.8
```

DNSLens performs a reverse DNS/PTR lookup and displays the hostname when
a PTR record exists.

## Input Detection

DNSLens automatically detects:

``` text
DOMAIN
URL
IPv4
IPv6
INVALID INPUT
```

No manual mode selection is required.

## Project Structure

``` text
dnslens/
├── index.html
├── Style.css
├── Script.js
└── README.md
```

## Running Locally

Clone the repository:

``` bash
git clone https://github.com/YOUR-USERNAME/dnslens.git
cd dnslens
```

Then open `index.html` in a browser.

For best results, serve the project through a local HTTP server:

``` bash
python3 -m http.server 8000
```

Open:

``` text
http://localhost:8000
```

## Technology

-   HTML5
-   CSS3
-   Vanilla JavaScript
-   DNS-over-HTTPS
-   No backend required

## Security & Privacy

DNSLens is designed as a lightweight DNS lookup utility. It does not
perform port scanning, vulnerability scanning, exploitation, subdomain
enumeration, or unauthorized access.

DNS results are obtained from the configured DNS resolution service and
may change over time.

## Disclaimer

DNSLens is provided for legitimate network administration, development,
troubleshooting, educational, and authorized security research purposes.

Users are responsible for complying with applicable laws, regulations,
and third-party terms of service.

The author is not responsible for misuse of this software or for any
damage resulting from its use.

## Author

**Mohit Meena**

LinkedIn: https://www.linkedin.com/in/mohit-meena-08a239332/

------------------------------------------------------------------------

::: {align="center"}
**DNSLens --- Resolve. Reverse. Understand.**
:::
