# NanoShield 🛡️

### On-Device Security Assistant — Zero Internet Required
A privacy-first, ultra-lightweight language model trained from scratch to audit source code and detect vulnerabilities entirely offline. **25 vulnerability patterns**, **web + desktop + mobile GUI**, **online/offline intelligence**.

---

## 💡 What is NanoShield?

NanoShield is a security scanner that runs **entirely on your device**. Paste code → get instant vulnerability reports with fix suggestions. No data ever leaves your machine.

**Key Features:**
- 🔍 **25 vulnerability patterns** — SQL injection, XSS, command injection, weak crypto, and more
- 🧠 **AI auto-fix** — every finding includes a code fix suggestion
- 📱 **Mobile responsive** — works on phones, tablets, desktops
- 🌐 **Online/offline mode** — auto-detects connectivity; fetches latest CVEs when online
- 🎨 **Animated dark UI** — uiverse.io-inspired glassmorphism, glowing orbs, smooth animations
- ⚡ **~48M parameter model** — custom transformer with RoPE, RMSNorm, SwiGLU
- 🚀 **One-click install** — `bash setup.sh` and you're running

---

## 📁 Repository Structure

```
├── config/
│   └── model_config.json      # 48M parameter hyperparameters
├── data/
│   ├── prepare_data.py        # Tokenization & deduplication
│   └── secure_dataset.txt     # Curated security training data
├── gui/
│   ├── web_app.py             # Web GUI (Flask) — dark theme, animations, mobile
│   ├── desktop_app.py         # Desktop GUI (Tkinter)
│   └── mockup.html            # HTML design mockup
├── src/
│   ├── model.py               # Custom Transformer (<50M params)
│   ├── train.py               # PyTorch training with FP16
│   └── inference.py           # CLI scanner & text generation
├── weights/                   # Model checkpoints
├── setup.sh                   # One-click installer
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Auto-Install (Recommended)
```bash
git clone https://github.com/al13n-x-v0x/NanoShield.git
cd NanoShield
bash setup.sh
```

### 2. Run the Web GUI
```bash
python gui/web_app.py
# Open http://localhost:5000
```

### 3. Run the Desktop GUI
```bash
python gui/desktop_app.py
```

### 4. CLI Scanner
```bash
python src/inference.py -i sample_code.py
```

### 5. Train the Model
```bash
python src/train.py --data_path data/training_data.txt --epochs 50
```

---

## 🔍 Vulnerability Detection

NanoShield detects **25 vulnerability classes** with OWASP & CWE mappings:

| Category | Severity | OWASP | CWE |
|---|---|---|---|
| SQL Injection | 🔴 CRITICAL | A03:2021 | CWE-89 |
| Command Injection | 🔴 CRITICAL | A03:2021 | CWE-78 |
| Hardcoded Credentials | 🔴 CRITICAL | A07:2021 | CWE-798 |
| Eval/Exec Usage | 🔴 CRITICAL | A03:2021 | CWE-95 |
| Buffer Overflow | 🔴 CRITICAL | A06:2021 | CWE-120 |
| XSS | 🟠 HIGH | A03:2021 | CWE-79 |
| Weak Crypto | 🟠 HIGH | A02:2021 | CWE-327 |
| Path Traversal | 🟠 HIGH | A01:2021 | CWE-22 |
| Insecure Deserialization | 🟠 HIGH | A08:2021 | CWE-502 |
| SSRF | 🟠 HIGH | A10:2021 | CWE-918 |
| XXE Injection | 🟠 HIGH | A05:2021 | CWE-611 |
| Unrestricted File Upload | 🟠 HIGH | A04:2021 | CWE-434 |
| Race Condition | 🟡 MEDIUM | A04:2021 | CWE-362 |
| Open Redirect | 🟡 MEDIUM | A01:2021 | CWE-601 |
| Missing Rate Limiting | 🟡 MEDIUM | A04:2021 | CWE-307 |
| Weak Session Token | 🟡 MEDIUM | A07:2021 | CWE-330 |
| Debug Mode | 🟡 MEDIUM | A05:2021 | CWE-489 |
| CORS Misconfiguration | 🟡 MEDIUM | A05:2021 | CWE-942 |
| Timing Attack | 🟡 MEDIUM | A02:2021 | CWE-208 |
| Hardcoded IP | 🔵 LOW | A05:2021 | CWE-200 |
| Insufficient Logging | 🔵 LOW | A09:2021 | CWE-778 |
| Deprecated Functions | 🔵 LOW | A06:2021 | CWE-693 |

---

## ⚙️ Model Architecture

| Component | Value |
|---|---|
| Parameters | ~48M |
| Layers | 24 |
| Attention Heads | 16 |
| Hidden Dim | 1024 |
| FFN Dim | 4096 |
| Max Seq Len | 2048 |
| Norm | RMSNorm |
| Position | Rotary (RoPE) |
| Activation | SwiGLU (SiLU) |
| Weight Tying | ✓ |

---

## 🌐 Online / Offline Mode

| Mode | What happens |
|---|---|
| **Online** | Fetches latest CVEs, OWASP updates, and security advisories in real-time |
| **Offline** | Uses bundled knowledge base (~50KB JSON) with 2023 CWE Top 25, OWASP Top 10, crypto best practices |
| **Auto** | Detects connectivity and switches automatically |

---

## 📱 Mobile Support

The web GUI is fully responsive:
- **Phone** (≤480px): Single-column layout, full-width scan button
- **Tablet** (≤768px): Stacked editor + results
- **Desktop** (>768px): Side-by-side editor + report

---

## 🎨 UI Features (uiverse.io inspired)

- Glassmorphism cards with backdrop blur
- Floating animated background orbs
- Gradient-shifting logo
- Pulsing status badges
- Security score ring with animated fill
- Slide-in vulnerability findings with staggered delays
- Toast notifications
- Shimmer loading states
- Smooth scroll behavior

---

## 📄 License

MIT License
