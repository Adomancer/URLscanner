# Gunakan base image Python
FROM python:3.12

# Set direktori kerja di dalam container
WORKDIR /app

# Salin semua file dari folder lokal ke dalam container
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port yang digunakan Flask
EXPOSE 5000

# Jalankan aplikasi Flask
CMD ["python", "webapp.py"]
