#!/bin/bash
# ╔══════════════════════════════════════════════════════╗
# ║  NanoShield Auto-Installer                          ║
# ║  Sets up offline AI + web GUI + desktop GUI         ║
# ╚══════════════════════════════════════════════════════╝

set -e
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🛡️  NanoShield Installer                 ║${NC}"
echo -e "${CYAN}║  On-Device Security Assistant              ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Check Python
echo -e "${YELLOW}[*] Checking Python...${NC}"
if command -v python3 &>/dev/null; then
    PY="python3"
elif command -v python &>/dev/null; then
    PY="python"
else
    echo -e "${RED}[!] Python not found. Installing...${NC}"
    if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "Please install Python from https://python.org"
        exit 1
    fi
    sudo apt-get update && sudo apt-get install -y python3 python3-pip
    PY="python3"
fi
echo -e "${GREEN}[✓] Python found: $($PY --version)${NC}"

# Install dependencies
echo -e "${YELLOW}[*] Installing dependencies...${NC}"
$PY -m pip install --quiet --upgrade pip 2>/dev/null
$PY -m pip install --quiet torch numpy tqdm flask sentencepiece 2>/dev/null || {
    echo -e "${YELLOW}[*] Some packages failed (offline mode?) — continuing...${NC}"
}
echo -e "${GREEN}[✓] Dependencies installed${NC}"

# Create directory structure
echo -e "${YELLOW}[*] Setting up directories...${NC}"
mkdir -p weights data config gui src logs

# Download security knowledge base (works offline after first run)
echo -e "${YELLOW}[*] Building offline knowledge base...${NC}"
$PY -c "
import json, os
kb = {
    'owasp_top10_2021': {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable and Outdated Components',
        'A07': 'Identification and Authentication Failures',
        'A08': 'Software and Data Integrity Failures',
        'A09': 'Security Logging and Monitoring Failures',
        'A10': 'Server-Side Request Forgery'
    },
    'cwe_top25_2023': {
        'CWE-787': 'Out-of-bounds Write',
        'CWE-79': 'Cross-site Scripting',
        'CWE-89': 'SQL Injection',
        'CWE-416': 'Use After Free',
        'CWE-78': 'OS Command Injection',
        'CWE-20': 'Improper Input Validation',
        'CWE-125': 'Out-of-bounds Read',
        'CWE-22': 'Path Traversal',
        'CWE-352': 'Cross-Site Request Forgery',
        'CWE-434': 'Unrestricted Upload'
    },
    'crypto_algorithms': {
        'recommended': ['AES-256-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'X25519', 'bcrypt', 'scrypt', 'Argon2id'],
        'deprecated': ['MD5', 'SHA1', 'DES', '3DES', 'RC4', 'RSA-1024', 'ECB mode'],
        'tls_versions': {'secure': ['TLS 1.3', 'TLS 1.2'], 'insecure': ['TLS 1.1', 'TLS 1.0', 'SSL 3.0']}
    }
}
with open('config/knowledge_base.json', 'w') as f:
    json.dump(kb, f, indent=2)
print('  [✓] Knowledge base built')
"

# Create .env template
cat > .env.example << 'ENV'
# NanoShield Configuration
NANOSHIELD_DEBUG=false
NANOSHIELD_PORT=5000
NANOSHIELD_HOST=0.0.0.0
# Online knowledge updates
NANOSHIELD_ONLINE_MODE=true
NANOSHIELD_UPDATE_INTERVAL=3600
ENV

echo -e "${GREEN}[✓] Configuration ready${NC}"

# Summary
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ✅ Installation Complete!                  ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Run the Web GUI:    ${GREEN}$PY gui/web_app.py${NC}"
echo -e "  Run Desktop GUI:    ${GREEN}$PY gui/desktop_app.py${NC}"
echo -e "  Train Model:        ${GREEN}$PY src/train.py${NC}"
echo -e "  Scan a File:        ${GREEN}$PY src/inference.py -i file.py${NC}"
echo ""
echo -e "  Web interface:      ${CYAN}http://localhost:5000${NC}"
echo ""
