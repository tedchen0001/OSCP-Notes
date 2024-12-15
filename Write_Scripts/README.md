#### Server

- sendmail.py: Sending an email to multiple recipients.

#### AD

- execGetTGT.sh: Executing the ```getTGT.py``` script with multiple NTLM hashes to obtain valid password hashes.
- ExtractBloodhoundUsernames.py: Extract usernames from a JSON file exported from Bloodhound query results.

```
MATCH (u:User) RETURN u
```

```shell
python ExtractBloodhoundUsernames.py graph.json usernames.txt
```

#### Web

- vue_path_scanner.py: A tool for scanning and testing web paths with Vue.js rendering support.

Required Packages:
pip3 install playwright
playwright install

Usage:
python3 vue_path_scanner.py \
    --target-url "https://example.com/app/#/" \
    --paths-file paths.txt \
    --baseline-paths "login,dashboard" \
    --request-delay 0.5 \
    --content-log \
    --result-log logs/results.txt

Arguments:
- --target-url: Base URL of the target application (Required)
- --paths-file: File containing paths to test, one per line (Required)
- --baseline-paths: Comma-separated list of paths to test first (Optional)
- --request-delay: Delay between requests in seconds (Optional, default: 1.0)
- --content-log: Enable logging of rendered HTML content (Optional)
- --result-log: Path to save result log (Optional)
