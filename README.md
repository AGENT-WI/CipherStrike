# CipherStrike
Educational payload generation framework for XSS, SQLi, and command injection

# Encoding Module:
## Encoding Module (Educational Use Only)

## 1=> Objectives

- Demonstrate encoding techniques used in web security research
- Show how payload transformation affects detection systems
- Provide CLI-based payload encoding
- Export results for documentation and lab analysis

## 2=> Features

| Feature | Description |
|----------|------------|
| URL Encoding | Percent-based encoding |
| Base64 Encoding | Base64 payload transformation |
| Hex Encoding | Hexadecimal representation |
| Mixed Encoding | URL → Base64 layered encoding |
| JSON Export | Save results in structured format |
| CLI Interface | Clean command-line usage |
| Logging | Informative error & success messages |

## 3=> Demo Examples (Terminal)

### 1️⃣ URL Encoding Example

```terminal
python encoder.py --payload "<script>alert(1)</script>" --encode url
```

### Output:
```
======= Encoding Result =======
Original Payload : <script>alert(1)</script>
Encoding Type    : url
Encoded Output   : %3Cscript%3Ealert%281%29%3C/script%3E
================================
```

---

### 2️⃣ Base64 Encoding Example

``
python encoder.py --payload "admin' OR 1=1 --" --encode base64

### 3️⃣ Hex Encoding Example
python encoder.py --payload "test123" --encode hex

### 4️⃣ Mixed Encoding (URL → Base64)
python encoder.py --payload "<img src=x>" --encode mixed

### 5️⃣ Export Result to JSON

python encoder.py \
--payload "<script>" \
--encode url \
--json-output encoded_output.json

Generated file:

```json
{
    "original_payload": "<script>",
    "encoding_type": "url",
    "encoded_output": "%3Cscript%3E"
}
```
##  4=> CLI Help Menu

python encoder.py --help
##  5=> Educational Notes

Encoding techniques are commonly used in:

- WAF evasion research
- Input filter bypass attempts
- Obfuscation demonstrations
- Security testing labs

Modern security systems detect:
- Double encoding
- Mixed encoding layers
- Suspicious transformation chains
- Anomaly-based payload behavior

This module helps demonstrate how such transformations look —  
without performing real attacks.
