# PII-Redaction-Form-16
Redacts phone, email, PAN, TAN, Aadhaar, GSTIN &amp; addresses from Form-16 PDFs with Go + pdftotext; offline English-dict filter included.

# PDF PII Redactor (v2)

This Go utility extracts text from **Form-16** PDFs and redacts Personally Identifiable Information (PII)

---
## 1. Redaction Pipeline
```
PDF → pdftotext → Regex-based PII scrubber → Dictionary filter → filtered_output.txt
```
1. **Text extraction** – `pdftotext -layout` keeps column alignment.
2. **Regex PII filter** (unchanged from v1) – masks phone, PAN, TAN, Aadhaar, e-mails, addresses, org names GSTIN.
3. **Dictionary filter (new)**
   * Loads `english_words.txt` (one lowercase word per line, ~100 k entries from SCOWL/wordfreq).
   * For each alphabetic token:
     * skip if `len(word) ≤ 3`.
     * if `word` **contains any digit** → keep (alphanumerics treated as identifiers).
     * if `word` **not** in the word-set → replace with `[WORD_REDACTED]`.
   * A summary of the unique non-dictionary words redacted is appended to *Removed PII Fields*.

---
## 2. Installation & Setup
### 2.1 Prerequisites
* **Go 1.24+**
* **Poppler utils** (`pdftotext`) – required for text extraction.
* **Offline English word list** – must be present as `english_words.txt` (one word per line; can include custom allowed terms).
* **PDF of Form 16** - add its path in line 14 of main.go 

> The file must be UTF-8, lowercase, one word per line.

### 2.2 Clone, tidy, build, run
```bash
git clone https://github.com/kyouma14/PII-Redaction-Form16.git
go mod tidy
go build -o pdf-redactor .
# Process the PDF specified in `DefaultPDFFile` (line ~14):
./pdf-redactor
# or override output names
./pdf-redactor out.txt raw.txt  # custom output names
```
> You can also run it directly (without building) via the terminal or an IDE by using:
```bash
go run main.go
```

After completion you will get:
* **`out.txt`** – redacted text + summary (default `filtered_output.txt`).
* **`raw.txt`** – verbatim extraction for diffing/debugging.

---
## 3. Regex Patterns (quick reference)
| Pattern | Purpose |
|---------|---------|
| Phone, Email, PAN, TAN, Aadhaar regexes | Mask direct PII with markers such as `[PAN_REDACTED]`. |
| Address / Organization regexes | Replace entire line with `[ADDRESS_REDACTED]` / `[ORG_REDACTED]`. |
| GST regex | Detected but **kept** (business identifier). |
| Dictionary filter | Replaces unknown English words (except len ≤ 3 or alphanumerics) with `[WORD_REDACTED]`. |

---
## 4. Project Layout
```
.
├── main.go            # Extraction + redaction pipeline
├── english_words.txt  # Offline dictionary (download manually)
├── go.mod / go.sum    # Module files (std-lib only)
└── README.md
```

---
## 5. Troubleshooting
| Issue | Fix |
|-------|-----|
| `[FATAL] Failed to load english word list` | Ensure `english_words.txt` exists in working directory and is readable (permissions, UTF-8). |
| Words like "summary" or "amount" still redacted | Verify they exist in `english_words.txt`; if missing, append them manually and rerun. |
| `pdftotext` not found | Poppler not installed / PATH not set. On Windows download Poppler-windows release, add `<poppler>/bin` to PATH; on macOS `brew install poppler`; on Debian/Ubuntu `sudo apt install poppler-utils`. |

