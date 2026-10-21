# Offline blocklists

Drop any number of plain-text threat feeds in this folder (`*.txt`). They are loaded locally;
the scanner never contacts the feed provider during a scan.

Accepted line formats (comments start with `#`):

```
https://bad.example/path/login.php      # exact URL
bad.example                             # host / registered domain
0.0.0.0 bad.example                     # hosts-file format
203.0.113.7                             # IP address
hxxps://bad[.]example                   # defanged entries are refanged automatically
```

Good sources you can download yourself and save here: URLhaus text dumps, OpenPhish community feed,
Phishing.Database, or your own incident IOC lists. Files are reloaded automatically when they change.
