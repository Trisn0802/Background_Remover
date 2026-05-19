# 🚀 UNTUK UBUNTU SERVER: Cara Menjalankan Script Update

## ✅ Script SUDAH Dikonfigurasi

GitHub URL sudah di-set ke:
```bash
REPO_URL="https://github.com/Trisn0802/Background_Remover.git"
```

Tidak perlu edit lagi! Tinggal jalankan. 🎉

---

## ✅ Cara Run Script (RECOMMENDED)

### Option 1: Direct run (monitoring active)

```bash
cd /var/www/docker/app/Background_Remover
./update_and_run.sh
```

**Pros:** Lihat output langsung
**Cons:** Harus tetap di terminal

---

### Option 2: Tmux session (RECOMMENDED)

```bash
# Buat session baru
tmux new-session -s bg-update

# Run script
cd /var/www/docker/app/Background_Remover && ./update_and_run.sh

# Atau sebagai satu command:
tmux send-keys -t bg-update 'cd /var/www/docker/app/Background_Remover && ./update_and_run.sh' Enter
```

**Detach dari tmux:**
```
Ctrl+B → D
```

**Attach kembali:**
```bash
tmux attach -t bg-update
```

**Kill session:**
```bash
tmux kill-session -t bg-update
```

---

### Option 3: Background dengan logging

```bash
cd /var/www/docker/app/Background_Remover
nohup bash ./update_and_run.sh > update_run.log 2>&1 &

# Monitor real-time
tail -f update_run.log

# Atau monitor log file yang di-maintain script
tail -f /var/log/bg-remover-update.log
```

---

## 🔍 Jika Ada Error?

### 1. Baca log file:
```bash
# Log file yang di-maintain oleh script
tail -50 /var/log/bg-remover-update.log

# Atau jika permission issue:
tail -50 /var/www/docker/app/Background_Remover/update.log
```

### 2. Jalankan debug script:
```bash
cd /var/www/docker/app/Background_Remover
bash debug.sh
```

### 3. Cek dokumentasi:
```
TROUBLESHOOTING.md - untuk solusi error spesifik
```

---

## 📊 Script Improvements (Update Terbaru)

Yang sudah diimprove:

✅ **Logging otomatis** - semua output tersimpan di `/var/log/bg-remover-update.log`
✅ **Error handling lebih baik** - error messages yang jelas & actionable
✅ **Better initialization** - auto-clone jika repo belum ada
✅ **Health check** - tunggu container siap sebelum selesai
✅ **Detailed output** - tahu persis apa yang terjadi di setiap step

---

## 📋 Checklist Sebelum Run

- [ ] Edit script: ubah REPO_URL (line 19)
- [ ] Docker sudah installed & running
- [ ] .env file sudah ada dengan API keys
- [ ] Port 5100 tidak terpakai
- [ ] Folder `/var/www/docker/app` writable
- [ ] GitHub akses sudah setup (SSH key atau username/password)

---

## 🎯 Eksekusi Sekarang:

### Setup pertama kali:
```bash
# Step 1: Edit script
nano /var/www/docker/app/Background_Remover/update_and_run.sh
# → Ubah REPO_URL di line 19

# Step 2: Run
cd /var/www/docker/app/Background_Remover
./update_and_run.sh

# Step 3: Monitor
tail -f /var/log/bg-remover-update.log
```

### Update berikutnya:
```bash
cd /var/www/docker/app/Background_Remover
./update_and_run.sh
# It will auto-pull latest changes & rebuild!
```

---

## 🆘 Jika Masih Error:

1. **Check logs** - paling penting! Errors tertulis di log file
2. **Run debug script** - `bash debug.sh` untuk diagnosis lengkap
3. **Manual steps** - lihat TROUBLESHOOTING.md untuk workflow manual

---

**Status: READY** ✅ Script sudah siap diproduksi-kan!
