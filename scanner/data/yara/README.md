# YARA rules (optional)

Put `*.yar` rule files here and install the engine once:

```
pip install yara-python
```

Every downloaded file is checked against the rules. Matches appear as findings named after the rule.
Without `yara-python` or without rule files, this step is skipped and the report says why.
