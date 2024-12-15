# Tools 

## Server Tools

### sendmail.py
Sending an email to multiple recipients.

## Active Directory Tools

### execGetTGT.sh
Executing the `getTGT.py` script with multiple NTLM hashes to obtain valid password hashes.

### ExtractBloodhoundUsernames.py
Extract usernames from a JSON file exported from Bloodhound query results.

Query used:
```cypher
MATCH (u:User) RETURN u
```

Usage:
```shell
python ExtractBloodhoundUsernames.py graph.json usernames.txt
```

## Web Tools

### Vue Path Scanner
A tool for scanning and testing web paths with Vue.js rendering support.

#### Installation
Required packages:
```bash
pip3 install playwright
playwright install
```

#### Usage
```bash
python3 vue_path_scanner.py \
   --target-url "https://example.com/app/#/" \
   --paths-file paths.txt \
   --baseline-paths "login,dashboard" \
   --request-delay 0.5 \
   --content-log \
   --result-log logs/results.txt
```

#### Arguments
| Argument | Description | Required |
|----------|-------------|----------|
| `--target-url` | Base URL of the target application | Yes |
| `--paths-file` | File containing paths to test, one per line | Yes |
| `--baseline-paths` | Comma-separated list of paths to test first | No |
| `--request-delay` | Delay between requests in seconds (default: 1.0) | No |
| `--content-log` | Enable logging of rendered HTML content | No |
| `--result-log` | Path to save result log | No |