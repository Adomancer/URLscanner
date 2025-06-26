# scanner/report.py

import csv
import json

def save_to_csv(results, filename):
    if not results:
        print("No results to save.")
        return

    keys = results[0].keys()
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)
    print(f"[✓] Hasil disimpan ke CSV: {filename}")

def save_to_json(results, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4)
    print(f"[✓] Hasil disimpan ke JSON: {filename}")
