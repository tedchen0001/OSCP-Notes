### **Bug Hunting Playbook**

A curated list of tools, commands, and resources for web application security testing and bug bounty hunting.

### **1. Reconnaissance & Discovery**

This phase focuses on gathering information and mapping the attack surface.

#### **1.1. Subdomain Enumeration**

*   **Subfinder**
    *   A fast and passive subdomain discovery tool.
    *   :star: **Note:** [Post-install configuration](https://docs.projectdiscovery.io/tools/subfinder/install#post-install-configuration) is recommended for optimal results.

    ```shell
    # Find subdomains silently and pipe to dnsx for resolution
    subfinder -silent -d <target domain> | dnsx -silent > /tmp/servers.txt
    
    # Use the list of resolved hosts for a TCP connect scan with nmap
    sudo nmap -iL /tmp/servers.txt -Pn -sT 
    ```

*   **ffuf (Fuzz Faster U Fool)**
    *   A versatile web fuzzer for subdomain discovery.

    ```shell
    # Fuzz for subdomains using a wordlist
    # Rate limiting is advised to prevent network issues
    ffuf -t 10 -c -ac -mc 200,204,301,307,401,405,400,302 -u https://FUZZ.<target domain> -H 'X-Forwarded-For: 0.0.0.0' -w <wordlist> -rate 20
    ```

    *   **Fuzzing through Tor**

    ```shell
    # Route ffuf traffic through a SOCKS5 proxy (Tor)
    ffuf -t 10 -c -ac -mc 200,204,301,307,401,405,400,302 -u https://FUZZ.<target domain> -H 'X-Forwarded-For: 0.0.0.0' -w <wordlist> -x socks5://127.0.0.1:9050 -rate 20
    ```

*   **BBOT**
    *   An automated OSINT framework that can be used for subdomain enumeration.

    ```shell
    # Run the subdomain enumeration module against a target
    bbot -t target.com -f subdomain-enum
    ```

#### **1.2. Port & Service Discovery**

*   **[Outgoing Port Tester](http://portquiz.net/)**: An online utility to test for open outgoing ports from a network.

#### **1.3. Content & Parameter Discovery**

*   **[dirsearch](https://github.com/maurosoria/dirsearch)**: A command-line tool designed to brute force directories and files in web servers.
*   **[Arjun](https://github.com/s0md3v/Arjun)**: A tool for finding hidden HTTP parameters.

#### **1.4. Historical Data**

*   **[Wayback Machine](https://wayback-api.archive.org/)**: Access historical snapshots of websites to find old or forgotten endpoints and files.

### **2. Scanning & Analysis**

This phase involves actively scanning for vulnerabilities and analyzing application behavior.

*   **[Nuclei](https://github.com/projectdiscovery/nuclei)**: :star: A powerful and fast template-based vulnerability scanner.
*   **[Google Maps API Scanner](https://github.com/ozguralp/gmapsapiscanner)**: A tool to find misconfigured Google Maps API implementations.
*   **Google Dorks**
    *   Utilize advanced Google search operators to uncover sensitive information.
    *   **Resource:** [taksec.github.io](https://taksec.github.io/google-dorks-bug-bounty/)

*   **IIS Short Filename (Tilde) Scanner**
    *   **[IIS-ShortName-Scanner](https://github.com/irsdl/iis-shortname-scanner)**
    *   **[Shortscan](https://github.com/bitquark/shortscan)**

### **3. Exploitation Techniques**

Specific methods and payloads for common vulnerability classes.

#### **3.1. Cross-Site Scripting (XSS)**

*   **Tools**
    *   **[dalfox](https://github.com/hahwul/dalfox)**: An open-source XSS scanner and parameter analysis tool.
    *   **[postMessage-tracker](https://github.com/fransr/postMessage-tracker)**: A Chrome extension to track and exploit `postMessage` vulnerabilities. See also: [postMessage XSS on a Private Program](https://medium.com/@youghourtaghannei/postmessage-xss-vulnerability-on-private-program-18e773e1a1ba).
    *   **[swagger-ui-xss](https://github.com/VictorNS69/swagger-ui-xss)**: A repository demonstrating XSS in outdated Swagger UI versions.

*   **Payloads**
    *   **[Open Bug Bounty](https://www.openbugbounty.org/)**: A great resource to learn about effective XSS payloads from public reports.

#### **3.2. Client-Side Template Injection (CSTI)**

*   **AngularJS Payloads**

    ```js
    ${1+1}
    {{constructor.constructor('alert(document.cookie)')()}}
    ```

#### **3.3. Bypasses (WAF & 403)**

*   **403 Bypass Tools**
    *   **[bypass-403](https://github.com/iamj0ker/bypass-403)**
    *   **[403jump](https://github.com/trap-bytes/403jump)**

*   **Header-based Bypasses**
    *   Try spoofing internal IP addresses to bypass access controls.
    ```
    X-Forwarded-For: <internal IP address>
    X-Originating-IP: <internal IP address>
    X-Remote-IP: <internal IP address>
    X-Remote-Addr: <internal IP address>
    ```

*   **WAF Origin IP Discovery**
    *   **Video Resource:** [Mastering Origin IP Discovery Behind WAF](https://www.youtube.com/watch?v=R3hmZpkvCmc)

#### **3.4. HTTP Parameter Pollution**

*   **Mitigation Methods to Test Against:**
    *   Whitelist validation
    *   Strong type validation
    *   Rejection of duplicate parameters
    *   Regular expression filtering

#### **3.5. Advanced Fuzzing**

*   **Stealthy Fuzzing with ffuf (Browser-like Behavior)**
    *   [useragents.io](https://useragents.io/random) is a useful resource for generating random User-Agent strings.
    ```shell
    ffuf -t 1 -rate 10 \
    -mc 200,204,301,307,401,405,400,302 \
    -u https://service.xxx.com/Home/FUZZ \
    -w words_alpha.txt \
    -H "X-Forwarded-For: 192.168.1.125" \
    -H "X-Originating-IP: 192.168.1.125" \
    -H "X-Remote-IP: 192.168.1.125" \
    -H "X-Remote-Addr: 192.168.1.125" \
    -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 7_8_2; like Mac OS X) AppleWebKit/602.20 (KHTML, like Gecko) Chrome/49.0.2772.226 Mobile Safari/603.8" \
    -H "Referer: https://service.xxx.com" \
    -H "Accept-Encoding: gzip, deflate" \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
    -fs 247,246
    ```

### **4. Wordlists & Payloads**

*   **Sources**
    *   **[Assetnote Wordlists](https://wordlists.assetnote.io/)**: High-quality wordlists, including `httparchive_subdomains_YYYY_MM_dd.txt`.
    *   **[hidden database files](https://github.com/dkcyberz/Harpy/blob/main/Hidden/database.txt)**
    *   **[Bug-Bounty-Wordlists](https://github.com/Karanxa/Bug-Bounty-Wordlists)**

*   **Wordlist Management**
    *   It is recommended to split large wordlists to avoid loading issues with some tools.

    ```bash
    # Set the input file name
    input_file="/tmp/httparchive_subdomains_YYYY_MM_dd.txt"

    # Set the number of lines per file
    lines_per_file=150000

    # Create a directory to store the split files
    mkdir -p /tmp/split_files

    # Split the input file into smaller chunks
    split --lines=$lines_per_file --numeric-suffixes=1 --suffix-length=4 --additional-suffix=".txt" "$input_file" /tmp/split_files/split_

    echo "Wordlist split completed."
    ```

### **5. Learning Resources**

*   **[vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist/tree/main)**: A comprehensive checklist for various vulnerabilities.
*   **[InsiderPhD](https://www.youtube.com/@InsiderPhD/videos)**: A YouTube channel with in-depth videos on bug hunting topics.
*   **[Hacking APIs](https://www.amazon.com/Hacking-APIs-Application-Programming-Interfaces/dp/1718502443)**: A book focused on the security of Application Programming Interfaces.