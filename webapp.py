import io
import csv
import json
import os
from flask import Flask, request, render_template, send_file, session
from scanner.core import scan_url
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        result = scan_url(url)
        session["last_result"] = result
    return render_template("index.html", result=result)

@app.route("/export/csv")
def export_csv():
    scan = session.get("last_result")
    if not scan:
        return "No data to export.", 400

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(scan.keys())
    writer.writerow([json.dumps(v) if isinstance(v, (dict, list)) else v for v in scan.values()])
    output.seek(0)

    return send_file(io.BytesIO(output.getvalue().encode()), download_name="scan_result.csv", as_attachment=True)

@app.route("/export/json")
def export_json():
    scan = session.get("last_result")
    if not scan:
        return "No data to export.", 400

    output = io.StringIO()
    json.dump(scan, output, indent=2)
    output.seek(0)

    return send_file(io.BytesIO(output.getvalue().encode()), download_name="scan_result.json", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
