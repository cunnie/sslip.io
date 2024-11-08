### Tools for Exploring Log Files

To generate log files on, say, ns-ovh:

```zsh
sudo journalctl -u sslip.io-dns -S yesterday > /tmp/sslip.io.log
```

A file which I subsequently copy to my Mac (warning: uses BSD-variant of tools
like `sed`, so you may need to tweak the following commands if you're on Linux):

[I use `cut` instead of `awk` because it's twice as fast (9.11s instead of 22.56s)]

To find the domains queried (95% sslip.io):

```zsh
 # find all successful queries of A & AAAA records
grep -v '\. \? nil' < /tmp/sslip.io.log |\
    egrep "TypeA | TypeAAAA " |\
    cut -d " " -f 10 > /tmp/hosts.log
sed -E 's=.*(\.[^.]+\.[^.]+\.$)=\1=' < /tmp/hosts.log | tr 'A-Z' 'a-z' | sort | uniq -c | sort -n
```

```zsh
 # find the most looked-up IP addresses using the above hosts.log
sort < /tmp/hosts.log | uniq -c | sort -n | tail -50
```

```zsh
 # Who's trying to find out their own IP via ip.sslip.io?
 sudo journalctl --since yesterday -u sslip.io-dns | \
   grep -v "nil, SOA" | \
   grep "TypeTXT ip.sslip.io" | \
   sed 's/.*TypeTXT ip.sslip.io. ? \["//; s/"\]$//' | \
   sort | \
   uniq -c
```

```zsh
 # Who's querying us the most?
awk '{print $8}' < /tmp/sslip.io.log | \
  grep -v "nil, SOA" | \
  sed 's/\.[0-9]*$//' | \
  sort | \
  uniq -c | \
  sort -n | \
  tail -50
```
