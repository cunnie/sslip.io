### Tools for Exploring Log Files

To generate log files on, say, ns-aws:

```zsh
sudo journalctl -u sslip.io-dns -S yesterday > /tmp/sslip.io.log
```

A file which I subsequently copy to my Mac (warning: uses BSD-variant of tools
like `sed`, so you may need to tweak the following commands if you're on Linux):

[I use `cut` instead of `awk` because it's twice as fast (9.11s instead of 22.56s)]

To find the domains queried (95% sslip.io):

```zsh
 # find all successful queries of A & AAAA records
grep -v '\. \? nil' < sslip.io.log |\
    egrep "TypeA | TypeAAAA " |\
    cut -d " " -f 10 > hosts.log
sed -E 's=.*(\.[^.]+\.[^.]+\.$)=\1=' < hosts.log | tr 'A-Z' 'a-z' | sort | uniq -c | sort -n
```
