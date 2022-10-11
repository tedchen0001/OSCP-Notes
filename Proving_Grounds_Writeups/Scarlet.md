


```shell
showmount -e <target ip>
mkdir /tmp/test_folder
sudo mount -t nfs <target ip>:/<folder> /tmp/test_folder -o nolock
```

https://github.com/ticarpi/jwt_tool.git

[reference](https://infosecwriteups.com/attacking-json-web-tokens-jwts-d1d51a1e17cb)


JWT SQL injection

```shell
python3 jwt_tool.py <token> -I -pc <Payload claim to tamper with> -pv "<sql command>" -S hs256 -k ../public.pem   
```