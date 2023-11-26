### :open_file_folder: Simple-PHP-Web-Shell

```
https://github.com/artyuum/Simple-PHP-Web-Shell/blob/master/index.php
```

### :open_file_folder: PHP HTTP Server

```shell
php -S <host ip>:<port>
```

### :open_file_folder: phpinfo

`disable_functions` = disabled commands

```
system
exec
shell_exec
passthru
popen
proc_open
pcntl_exec
```

### :open_file_folder: upload-bypasses

```
https://github.com/six2dez/pentest-book/blob/master/enumeration/web/upload-bypasses.md
```

We can attempt to upload the `.htaccess` file to configure the server to execute our custom file extensions as PHP scripts.

```shell
# The uploaded file may not be visible in the upload directory.
echo "AddType application/x-httpd-php <custom file extension>" > .htaccess
# example
echo "AddType application/x-httpd-php .abc" > .htaccess
```

### :open_file_folder: Single-file PHP shell

Combine bypass, such as phar

```
https://github.com/flozz/p0wny-shell/tree/master
```

### :open_file_folder: Joomla webshell plugin for RCE

```
https://github.com/p0dalirius/Joomla-webshell-plugin
```
