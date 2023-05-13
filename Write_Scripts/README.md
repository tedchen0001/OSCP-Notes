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