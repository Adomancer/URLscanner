import os
import tempfile

# Use a throwaway database and never touch the network-sensitive private-target toggle.
os.environ.setdefault("SCANNER_DB", os.path.join(tempfile.gettempdir(), "urlscanner_test.db"))
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ["SCANNER_ALLOW_PRIVATE"] = "0"
