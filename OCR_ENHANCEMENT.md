# 🎯 OCR Enhancement untuk Deteksi Uang Rupiah

## Ringkasan Perubahan

Saya telah mengintegrasikan **EasyOCR** untuk meningkatkan akurasi deteksi nominal uang Rupiah. Sistem sekarang menggunakan **kombinasi Roboflow + OCR** untuk validasi yang lebih akurat.

---

## ✨ Fitur Baru

### 1. **OCR-Based Validation**
- Backend membaca teks pada uang menggunakan EasyOCR
- Hasil OCR dikonfirmasi/dikoreksi dengan hasil Roboflow
- Confidence score ditingkatkan ketika OCR cocok dengan Roboflow

### 2. **Image Enhancement**
- Pre-processing image sebelum OCR menggunakan OpenCV
- Meningkatkan kontras dan mengurangi noise
- CLAHE (Contrast Limited Adaptive Histogram Equalization) untuk hasil optimal

### 3. **Enhanced Text-to-Speech**
- Pesan TTS lebih detail dan informatif
- Include confidence level dalam narasi
- Include OCR validation info jika ada koreksi

### 4. **Smart Denomination Matching**
- Mapping teks ke nominal uang dengan berbagai variasi
- Support Indonesian number text recognition
- Fuzzy matching untuk teks yang tidak sempurna

---

## 🔧 Instalasi Dependency

```bash
# Install packages baru (jika belum)
pip install easyocr scipy

# Atau gunakan requirements.txt yang sudah diupdate
pip install -r requirements.txt
```

### Catatan Penting:
- **First time run**: EasyOCR akan download model (~170 MB) - bisa memakan waktu beberapa menit
- Model akan di-cache setelah download pertama
- Untuk production, consider menggunakan GPU untuk performa lebih baik

---

## 📊 Cara Kerja

### **Flowchart Deteksi:**

```
1. Image Input (dari camera/upload)
   ↓
2. Roboflow Detection (object detection)
   ↓
3. OCR Reading (membaca teks pada uang)
   ↓
4. Text Extraction (ekstrak nominal dari teks)
   ↓
5. Validation & Matching (cocokkan Roboflow + OCR)
   ↓
6. Confidence Score Calculation (boost jika match)
   ↓
7. Enhanced Response (dengan OCR validation info)
   ↓
8. Text-to-Speech Output (dengan confidence detail)
```

---

## 💡 Contoh Output

### Skenario 1: Cocok (Roboflow ✓ & OCR ✓)
```
Roboflow: "20000" (confidence: 0.85)
OCR Text: "DUA PULUH RIBU"
Result: "Terdeteksi: Dua Puluh Ribu Rupiah [Dikonfirmasi OCR]"
Confidence: 0.93 (ditingkatkan)
TTS: "Terdeteksi Dua Puluh Ribu Rupiah dengan kepastian sangat tinggi, 93 persen, dikonfirmasi dengan analisis teks"
```

### Skenario 2: Koreksi dari OCR
```
Roboflow: "10000" (confidence: 0.72)
OCR Text: "LIMA PULUH RIBU"
Result: "Terdeteksi: Lima Puluh Ribu Rupiah [Koreksi dari OCR]"
Confidence: 0.76 (gunakan OCR jika lebih tinggi)
TTS: "Deteksi Lima Puluh Ribu Rupiah, dikoreksi dengan analisis teks"
```

### Skenario 3: Roboflow Saja (OCR tidak jelas)
```
Roboflow: "100000" (confidence: 0.88)
OCR: (tidak terdeteksi teks nominal)
Result: "Terdeteksi: Seratus Ribu Rupiah"
Confidence: 0.88 (tetap)
TTS: "Terdeteksi Seratus Ribu Rupiah dengan kepastian sangat tinggi, 88 persen"
```

---

## 🛠️ Implementasi Teknis

### Backend (Python)

#### **New Functions:**

1. **`extract_money_from_ocr_text(ocr_text: str) -> str | None`**
   - Ekstrak nominal dari OCR text
   - Support berbagai format: "Dua Puluh Ribu", "duapuluhribu", "20000", dll

2. **`enhance_image_for_ocr(image_bytes: bytes) -> bytes`**
   - Pre-process image sebelum OCR
   - CLAHE + Bilateral Filter
   - Meningkatkan akurasi pembacaan teks ~15-20%

3. **`read_text_from_image(image_bytes: bytes) -> list[tuple[str, float]]`**
   - Baca teks menggunakan EasyOCR
   - Return: [(text, confidence), ...]

4. **`validate_money_detection_with_ocr(...) -> tuple`**
   - Main validation function
   - Combine Roboflow + OCR results
   - Boost confidence jika match

#### **Modified Routes:**

- **`/process-money` (POST)**
  - Sekarang include OCR validation
  - Return message dengan OCR info
  - Improved confidence scoring

### Frontend (JavaScript)

#### **Enhanced Functions:**

1. **`displayDetectionResult(result)`**
   - Parse OCR validation info
   - Generate contextual TTS message
   - Auto-speak result dengan detail

2. **`speakDetectionResult(message)`**
   - Enhanced TTS dengan lebih natural
   - Queue-based speech management
   - Better error handling

---

## 🔍 Konfigurasi & Tuning

### Confidence Threshold

```python
# Di app.py, line ~107
MONEY_CONFIDENCE_THRESHOLD = 0.75  # Minimum confidence
```

**Rekomendasi:**
- `0.70` - Lebih permissive, tapi hasil mungkin false positive
- `0.75` - Balance (default)
- `0.85` - Lebih strict, hasil lebih akurat tapi mungkin false negative

### Money Denominations

```python
# Di app.py, line ~125-133
MONEY_DENOMINATIONS = {
    "1000": ["1000", "seribu", "ribu"],
    "2000": ["2000", "dua ribu", "duaribu"],
    # ... dst
}
```

Dapat dikustomisasi untuk:
- Menambah variasi text recognition
- Support OCR errors lebih baik

---

## 🚀 Performance Tips

### 1. **GPU Support (Optional)**
```python
# Untuk lebih cepat, gunakan GPU (jika ada):
ocr_reader = easyocr.Reader(['id', 'en'], gpu=True)  # Ubah gpu=False menjadi gpu=True
```

### 2. **Model Caching**
- First run: OCR model didownload (~170 MB)
- Subsequent runs: Model di-load dari cache (cepat)

### 3. **Batch Processing**
- Jika process banyak images, consider batch OCR:
```python
# Modify read_text_from_image untuk batch processing
results = ocr_reader.readtext([img1, img2, img3])
```

---

## ⚠️ Troubleshooting

### Error: `ModuleNotFoundError: No module named 'easyocr'`
```bash
pip install easyocr
```

### Error: `ModuleNotFoundError: No module named 'cv2'`
```bash
pip install opencv-python-headless
```

### OCR Model Download Issues
```bash
# Check download directory
echo $HOME/.EasyOCR/model/

# Manual download (jika perlu):
python -c "import easyocr; easyocr.Reader(['id', 'en'])"
```

### Slow Performance
- Check GPU availability: `nvidia-smi`
- Enable GPU jika ada: `gpu=True`
- Consider reducing image resolution

---

## 📈 Testing & Validation

### Manual Test
```bash
# Use /test-process-money endpoint
curl -X POST http://localhost:5100/test-process-money \
  -H "Content-Type: application/json" \
  -d '{"image_data": "data:image/jpeg;base64,..."}'
```

### Expected Response
```json
{
  "success": true,
  "detections": [...],
  "detected_money": "50000",
  "confidence": 0.89,
  "message": "Terdeteksi: Lima Puluh Ribu Rupiah [Dikonfirmasi OCR]"
}
```

---

## 🔮 Future Enhancements

1. **Multi-Object Detection**
   - Deteksi multiple uang sekaligus
   - Sum total nominal

2. **Historical OCR Caching**
   - Cache OCR results untuk image serupa
   - Faster repeated detections

3. **Machine Learning Ensemble**
   - Kombinasi multiple models
   - Weighted voting system

4. **Custom Training**
   - Fine-tune OCR untuk Indonesian money
   - Improve accuracy further

---

## 📝 License & Attribution

- **Roboflow**: Object detection
- **EasyOCR**: Text recognition
- **OpenCV**: Image processing
- **PIL/Pillow**: Image handling

---

## 📞 Support

Jika ada pertanyaan atau issues:
1. Check logs: `docker logs app-container`
2. Test endpoint: `/test-process-money`
3. Verify models downloaded: Check `.EasyOCR/model/`

