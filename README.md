# Secure Shell Honeypot v0.1

* Simple script that stands up a dummy SSH server that logs access attempts and the credentials used into the console or into an event and/or a CSV file.

```
usage: ssh_honeypot.py [-h] [-l [LOGFILE]] [-c [CSV]]
                       server_address server_port server_key

SSH Honeypot written using the Paramiko library to log access attempts and cleartext credentials.

positional arguments:
  server_address        IPv4 address the server will listen on
  server_port           port the server will listen on
  server_key            RSA SSH hostkey (/path/to/private.key)

options:
  -h, --help            show this help message and exit
  -l [LOGFILE], --logfile [LOGFILE]
                        log events to file LOGFILE (default is ./honeypot.log)
  -c [CSV], --csv [CSV]
                        log credentials to csv file FILENAME (default is
                        creds.csv)

"$ ssh-keygen -i <KEY_NAME> -t rsa" to generate key if you havent already
```

* `pip install paramiko` to install the only required nonstandard library.

* The current version produces some pretty noisy errors when scanned with `nmap` or banner-grabbed with a TCP tool like `nc`, so you may consider redirecting STDERR to dev null (i.e., `2>/dev/null`) until the kinks get worked out. Regardless, if you simply need to log access attempts and grab creds it gets the job done.
