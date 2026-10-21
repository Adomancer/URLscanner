# Hash lists

Put plain-text `*.txt` files here. Each line is a file hash (MD5, SHA-1 or SHA-256), optionally followed
by a label. Lines starting with `#` are comments.

```
# feed: my-ioc-export
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  eicar-test
```

When a scanned download matches a hash, the file is flagged and the feed file name is shown as the
engine that detected it. Feeds are read locally; nothing is looked up online.
