# NanoShield 🛡️

### On-Device Security Assistant with <50M Parameters
A privacy-first, ultra-lightweight language model trained from scratch to audit source code and detect vulnerabilities entirely offline.

---

## 💡 Project Story

### Inspiration
Developers consistently leak proprietary source code, API keys, and internal logs by pasting them into cloud-hosted LLMs for quick security checks. This exposes sensitive corporate data, creates vendor lock-in, and introduces network latency. 

We wanted to solve this by ditching the bloated billions of parameters used for general conversation. Instead, we focused on a singular question: *Can we compress elite cryptographic and security auditing capabilities into a model tiny enough to run locally on a standard laptop or smartphone?* This drove us to build a custom, privacy-centric model within a strict 50M parameter ceiling.

### ⚙️ What it Does
NanoShield is an on-device security assistant that requires zero internet connectivity. It scans code blocks, catches cryptographic mistakes (like weak hashing or hardcoded credentials), and identifies common OWASP vulnerabilities. Operating entirely in local memory, it eliminates data leakage risks and cuts API latency down to milliseconds.

### 🛠️ How We Built It
Staying under the 50M parameter cap required tight architectural constraints and highly selective data choices:
* **The Architecture:** Designed a custom, lean Transformer with RMSNorm, rotary positional embeddings (RoPE), SwiGLU activations, and weight-tied embeddings to maximize reasoning efficiency per parameter.
* **The Dataset:** Ignored general web text to save capacity. Curated a specialized dataset focused entirely on clean code syntax, cryptographic primitives, and known vulnerability patterns.
* **The Training:** Raw PyTorch training loop with Mixed Precision (FP16), cosine learning rate decay with warmup, and gradient clipping to stabilize convergence on limited data.

### 🚧 Challenges We Ran Into
With only 50 million parameters, there is no buffer for noisy data. Early training runs resulted in severe loss spikes and syntax confusion on longer code files. We also fought overfitting because security code patterns can be highly repetitive. We resolved this by aggressively deduplicating our source data, adjusting our attention head scaling, and tuning dropout rates.

### 🏆 Accomplishments
We successfully engineered and trained a functional language model from the ground up that respects the strict 50M parameter limit. The model demonstrates genuine, localized understanding of code syntax and security flaws—proving that hyper-curated data and architectural discipline can achieve deep utility at a fraction of commercial model sizes.

### 🔮 What's Next
* **Quantization:** Compress weights to 4-bit for low-spec mobile hardware.
* **IDE Integration:** VS Code extension for live, offline code security warnings.
* **Dataset Expansion:** Smart contract vulnerabilities and Rust/Go memory safety edge cases.

---

## 📁 Repository Structure

```
├── config/
│   └── model_config.json      # Custom 50M parameter hyperparameters
├── data/
│   ├── prepare_data.py        # Tokenization & code syntax preprocessing
│   └── secure_dataset.txt     # Curated security/crypto training text
├── src/
│   ├── model.py               # Custom Transformer architecture definition
│   ├── train.py               # PyTorch training loop & validation
│   └── inference.py           # Local CLI text generation & code scanner
├── weights/                   # Saved model checkpoints
├── requirements.txt           # Minimal dependency list
└── README.md                  # Project documentation
```

---

## 🚀 Quick Start

### 1. Clone & Install
```bash
git clone https://github.com/al13n-x-v0x/NanoShield.git
cd NanoShield
pip install -r requirements.txt
```

### 2. Prepare Training Data
```bash
python data/prepare_data.py --input data/secure_dataset.txt
```

### 3. Train the Model
```bash
python src/train.py --data_path data/training_data.txt --epochs 50 --batch_size 4
```

### 4. Run the Security Scanner
```bash
python src/inference.py --input sample_code.py --checkpoint weights/best_model.pt
```

### 5. Generate Code
```bash
python src/inference.py --generate --prompt "def hash_password" --checkpoint weights/best_model.pt
```

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
| Vocab Size | 32,000 |
| Norm | RMSNorm |
| Position | Rotary (RoPE) |
| Activation | SwiGLU |

---

## 🔒 Vulnerability Detection

NanoShield detects and explains these vulnerability classes:

| Category | Severity |
|---|---|
| SQL Injection | 🔴 HIGH |
| Command Injection | 🔴 HIGH |
| Hardcoded Credentials | 🔴 HIGH |
| XSS (Cross-Site Scripting) | 🟡 MEDIUM |
| Weak Cryptography | 🟡 MEDIUM |
| Path Traversal | 🟡 MEDIUM |
| Buffer Overflow Risk | 🟡 MEDIUM |
| Missing Authentication | 🟡 MEDIUM |
| Insecure Deserialization | 🟡 MEDIUM |
| Race Conditions | 🟡 MEDIUM |

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.
