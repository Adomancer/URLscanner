import argparse
from scanner.core import scan_url
from scanner.report import save_to_csv, save_to_json

def read_urls(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def main():
    parser = argparse.ArgumentParser(description="URL Scanner - Cek keamanan HTTP headers")
    parser.add_argument("input", help="Path ke file .txt berisi daftar URL")
    parser.add_argument("--csv", help="Simpan hasil ke CSV (opsional)")
    parser.add_argument("--json", help="Simpan hasil ke JSON (opsional)")

    args = parser.parse_args()
    urls = read_urls(args.input)

    results = []
    for url in urls:
        print(f"[~] Memeriksa: {url}")
        result = scan_url(url)
        results.append(result)

        if "error" in result:
            print(f"[!] Gagal: {result['error']}")
        else:
            print(f"[✓] Status: {result['status_code']}, Hilang: {result['missing_headers']}")

    if args.csv:
        save_to_csv(results, args.csv)

    if args.json:
        save_to_json(results, args.json)

if __name__ == "__main__":
    main()
