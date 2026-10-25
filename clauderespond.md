PASTED

apakah plan ini sudah oke?

Plan-nya sudah bagus dan layak dikerjakan. Strukturnya rapi, banyak kode lama yang dipakai ulang, dan fokus privasinya tepat (BODY.PEEK, tidak ada yang dihapus, body email tidak disimpan). Pilihan IMAP + App Password juga masuk akal untuk pemakaian pribadi. Itu menghindari OAuth, kedaluwarsa token, dan ribetnya login di HP/Termux. Tapi ada beberapa hal yang sebaiknya diperbaiki dulu.

Bug dan celah yang perlu diperbaiki
select(readonly=True) tidak bisa dipakai untuk label. Mode itu setara EXAMINE, jadi UID STORE +X-GM-LABELS akan ditolak. Untuk langkah pelabelan, pilih folder dengan read-write (tetap aman selama fetch-nya BODY.PEEK, email tidak berubah jadi “sudah dibaca”), atau pakai koneksi terpisah.
“Passive” tidak sama dengan “tak terlihat”. Query DNS ke subdomain unik per penerima (misalnya abc123.tracker.example.com) tetap sampai ke nameserver pengirim. Teknik ini dipakai canarytoken untuk memberi tahu bahwa emailmu sudah diproses. Selesaikan DNS di level domain terdaftar, bukan host penuh, atau lewati DNS untuk subdomain acak di domain tak tepercaya. Pastikan juga check takeover benar-benar hanya DNS.
Hasil passive jangan pernah berlabel “bersih”. Tanpa data TLS, header, dan konten, skor 0 berarti “belum diperiksa”, bukan “aman”. Beri verdict tersendiri seperti Unverified.
Default fetch_policy="suspicious" sebaiknya jangan otomatis. Link yang dibuka otomatis justru yang paling mungkin berasal dari penipu, dan itu memberi tahu mereka bahwa alamatmu aktif plus membocorkan IP rumahmu. Untuk mode watch, jadikan never sebagai default, lalu sediakan tombol atau perintah “deep scan link ini” yang kamu klik sendiri.
Percayai hanya Authentication-Results dari Gmail. Penyerang bisa memalsukan header itu di dalam email. Ambil yang authserv-id-nya mx.google.com dan paling atas.
Sumber false positive
Return-Path atau Reply-To beda domain itu normal untuk newsletter yang pakai ESP. Beri bobot rendah kecuali digabung dengan sinyal lain.
Email bank asli berisi kata “OTP” dan “jangan berikan”, jadi bisa kena dua kategori frasa scam. Tambahkan daftar frasa pengecualian seperti “jangan berikan OTP kepada siapa pun” dan “waspada penipuan”.
brands.json perlu daftar domain pengirim sah per brand, termasuk subdomain ESP, selain domain login. Pastikan juga mencakup brand Indonesia (BCA, BRI, Mandiri, DANA, Shopee, Tokopedia, JNE, dan sebagainya).
Daftar “tepercaya” jangan memberi lolos gratis ke platform yang sering disalahgunakan: Google Forms/Docs/Sites, github.io, pages.dev, workers.dev, web.app.
Lampiran: tambahkan .apk, .lnk, .iso, .hta, dan arsip ZIP berpassword (cukup dideteksi, tidak perlu dibuka). Itu pola umum di Indonesia, misalnya “undangan.apk” atau “resi.apk”.
Hal lain
Layar /mail menampilkan pengirim dan subjek emailmu, jadi wajibkan SCANNER_ACCESS_TOKEN dan validasi header Host (hanya localhost atau 127.0.0.1) untuk mencegah DNS rebinding. Simpan URL di DB dengan query string yang disamarkan, karena sering berisi token pribadi.
Cari folder Spam lewat flag SPECIAL-USE \Junk, jangan hard-code [Gmail]/Spam. Nama folder bisa bervariasi.
Batasi total byte yang diunduh per run dan cek RFC822.SIZE dulu. Gmail membatasi bandwidth IMAP. Tambahkan cache WHOIS/DNS per domain dengan TTL panjang agar tidak kena rate limit.
Notifikasi dan allowlist sederhana sebaiknya masuk fase awal, bukan “nanti”. Alert di konsol tidak berguna kalau worker jalan di background.
Folder Spam-mu adalah dataset uji gratis. Jalankan scanner ke situ untuk mengukur deteksi, dan ke Inbox untuk mengukur false positive. Angkanya cocok untuk porto.
Urutan kerja

Plan ini besar, jadi pecah jadi tiga irisan, masing-masing dengan test sendiri:

A: mode passive + ImapSource read-only + pipeline + gmail scan --no-label
B: sinyal analisis email (header, pengirim, frasa, lampiran)
C: label + watch + notifikasi + halaman /mail