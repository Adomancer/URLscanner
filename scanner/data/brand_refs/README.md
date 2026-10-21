# Visual brand references

JSON files here hold perceptual hashes of genuine login pages, used by the browser sandbox to spot
look-alike phishing pages. Create them with:

```
python cli.py add-brand-ref https://www.paypal.com/signin PayPal
```

Each file is a list of `{"brand", "url", "dhash"}` objects.
