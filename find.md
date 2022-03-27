ignore permission denied message

```
find / -name repo -type f -prune 2>&1 | grep -v "Permission denied"
```
