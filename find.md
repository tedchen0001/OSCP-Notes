ignore permission denied message

```shell
find / -name repo -type f -prune 2>&1 | grep -v "Permission denied"
```

avoid permission denied messages

```shell
find / -name *kali* 2>&-
```

[Writable file](https://www.hackingarticles.in/multiple-ways-to-get-root-through-writable-file/)

```shell
find / -writable -type f 2>/dev/null | grep -v "/proc/"
```

find files containing specific text

```shell
find / -type f \( -iname \*.php -o -iname \*.config -o -iname \*.conf -o -iname \*.ini -o -iname \*.txt \) -exec grep -i 'password\|passwd' {} \; -print 2>&-
```

finding SUID executables

```shell
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
find / -uid 0 -perm -4000 -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
```

find ssh key

```shell
find / -type f -name id_rsa* 2>&-
```