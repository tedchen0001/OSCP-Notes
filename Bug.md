### Bug Hunting

- Subdomains
    
    - Subfinder :star:[Post install configuration](https://docs.projectdiscovery.io/tools/subfinder/install#post-install-configuration)
    
        ```shell
        subfinder -silent -d <target domain> | dnsx -silent > /tmp/servers.txt
        sudo nmap -iL /tmp/servers.txt -Pn -sT 
        ```
    - Fuff

        ```shell
        # Providing a rate setting helps avoid network issues
        ffuf -t 10 -c -ac -mc 200,204,301,307,401,405,400,302 -u https://FUZZ.<target domain> -H 'X-Forwarded-For: 0.0.0.0' -w <wordlist> -rate 20
        ```

      tor

        ```shell
        # Providing a rate setting helps avoid network issues
        ffuf -t 10 -c -ac -mc 200,204,301,307,401,405,400,302 -u https://FUZZ.<target domain> -H 'X-Forwarded-For: 0.0.0.0' -w <wordlist> -x socks5://127.0.0.1:9050 -rate 20
        ```

      The wordlist must be split into smaller parts, otherwise there may be loading issues.

      https://wordlists.assetnote.io/ :arrow_right: httparchive_subdomains_YYYY_MM_dd.txt


        ```bash
        # Set the input file name
        input_file="/tmp/httparchive_subdomains_YYYY_MM_dd.txt"

        # Set the number of lines per file
        lines_per_file=150000

        # Create a directory to store the split files
        mkdir -p /tmp/split_files

        # Split the input file
        split --lines=$lines_per_file --numeric-suffixes=1 --suffix-length=4 --additional-suffix=".txt" "$input_file" /tmp/split_files/split_

        echo "Wordlist split completed."
        ```
    - [BBOT](https://github.com/blacklanternsecurity/bbot)

      ```shell
      bbot -t target.com -f subdomain-enum
      ```

- Ports

  [Outgoing port tester](http://portquiz.net/)

- Server version
- Applications
  
  - [Google Maps API Scanner](https://github.com/ozguralp/gmapsapiscanner) 
  - :star:[Nuclei](https://github.com/projectdiscovery/nuclei)
  - [Arjun](https://github.com/s0md3v/Arjun): HTTP Parameter Discovery Suite
  - [dirsearch](https://github.com/maurosoria/dirsearch): Web path discovery
  - Testing Headers:

  ```
  X-Forwarded-For: <internal IP address>
  X-Originating-IP: <internal IP address>
  X-Remote-IP: <internal IP address>
  X-Remote-Addr: <internal IP address>
  ```
  - Google Dorks
    - [taksec.github.io](https://taksec.github.io/google-dorks-bug-bounty/)

  - Parameter Pollution:
    - Defenses: Whitelist validation, Strong type validation, Reject duplicate parameters, Regular expression filtering

- API
- Third party
- Source code
- Business logic error

#### Learning resources 

[vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist/tree/main) <br>
[InsiderPhD](https://www.youtube.com/@InsiderPhD/videos) <br>
[Hacking APIs](https://www.amazon.com/Hacking-APIs-Application-Programming-Interfaces/dp/1718502443)
[XSS payloads](https://www.openbugbounty.org/): From reports, we can learn about the payloads used by other testers.

#### IIS

[IIS-ShortName-Scanner](https://github.com/irsdl/iis-shortname-scanner) <br>
[Shortscan](https://github.com/bitquark/shortscan)

#### Bypasses

[403](https://github.com/iamj0ker/bypass-403)

#### History

[Wayback Machine](https://wayback-api.archive.org/)

#### Wordlist

[hidden database files](https://github.com/dkcyberz/Harpy/blob/main/Hidden/database.txt)