"""
NanoShield Inference Engine
Local text generation and code security scanning.
"""
import os, sys, argparse, json, re
import torch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.model import NanoShield, ModelConfig


VULNERABILITY_PATTERNS = {
    "SQL Injection": [
        r"execute\s*\(.*\+\s*",
        r"query\s*\(.*%s",
        r"cursor\.execute\s*\(.+format",
    ],
    "XSS": [
        r"innerHTML\s*=",
        r"document\.write\s*\(",
        r"eval\s*\(\s*req\.",
    ],
    "Hardcoded Credentials": [
        r'password\s*=\s*["\'][^"\']+["\']',
        r'api_key\s*=\s*["\'][^"\']+["\']',
        r'secret\s*=\s*["\'][^"\']+["\']',
    ],
    "Weak Crypto": [r"md5\(", r"sha1\(", r"DES\.", r"RC4"],
    "Command Injection": [
        r"os\.system\s*\(",
        r"subprocess\.call\s*\(.*shell\s*=\s*True",
        r"eval\s*\(\s*input",
    ],
    "Path Traversal": [
        r"open\s*\(.*\.\./",
        r"os\.path\.join\s*\(.*\.\.",
    ],
    "Buffer Overflow Risk": [
        r"strcpy\s*\(",
        r"gets\s*\(",
        r"sprintf\s*\(",
    ],
    "Insecure Deserialization": [
        r"pickle\.loads?\s*\(",
        r"yaml\.load\s*\((?!.*Loader)",
        r"marshal\.loads?\s*\(",
    ],
    "Race Condition": [
        r"global\s+\w+.*\n.*\w+\s*=\s*\w+\s*\+",
    ],
}

SECURITY_EXPLANATIONS = {
    "SQL Injection": "User input flows directly into SQL queries. Use parameterized queries or ORM binding.",
    "XSS": "Unsanitized user input rendered in HTML. Encode output and use CSP headers.",
    "Hardcoded Credentials": "Secrets in source code. Use environment variables or a vault service.",
    "Weak Crypto": "Deprecated algorithm. Migrate to SHA-256+ / AES-256.",
    "Command Injection": "OS commands built from user input. Use subprocess with list args, not shell=True.",
    "Path Traversal": "File paths containing ../ can escape the intended directory. Validate and sanitize paths.",
    "Buffer Overflow Risk": "Unsafe C functions without bounds checking. Use strncpy/snprintf.",
    "Insecure Deserialization": "Untrusted data deserialized without validation. Use yaml.safe_load.",
    "Race Condition": "Shared mutable state accessed by concurrent threads. Use locks or atomic operations.",
}


def load_model(checkpoint_path):
    device = "cuda" if torch.cuda.is_available() else "cpu"
    config_dir = os.path.dirname(checkpoint_path)
    config_path = os.path.join(config_dir, "config.json")
    if os.path.exists(config_path):
        with open(config_path) as f:
            data = json.load(f)
        config = ModelConfig(
            vocab_size=data.get("vocab_size", 32000),
            max_seq_len=data.get("seq_len", 2048),
            n_layers=data.get("n_layers", 24),
            n_heads=data.get("n_heads", 16),
            d_model=data.get("d_model", 1024),
            d_ff=data.get("d_ff", 4096),
        )
    else:
        config = ModelConfig()
    model = NanoShield(config)
    state = torch.load(checkpoint_path, map_location=device, weights_only=True)
    model.load_state_dict(state)
    model.to(device).eval()
    return model, device


def generate(model, device, prompt, max_tokens=512, temperature=0.8, top_k=40):
    model.eval()
    tokens = torch.tensor(
        [list(prompt.encode("utf-8"))], dtype=torch.long, device=device
    )
    for _ in range(max_tokens):
        idx = tokens[:, -model.config.max_seq_len :]
        logits, _ = model(idx)
        logits = logits[:, -1, :] / temperature
        v, _ = torch.topk(logits, min(top_k, logits.size(-1)))
        logits[logits < v[:, [-1]]] = float("-inf")
        probs = torch.softmax(logits, dim=-1)
        next_token = torch.multinomial(probs, num_samples=1)
        tokens = torch.cat([tokens, next_token], dim=1)
    return tokens[0].cpu().tolist()


def scan_code(code):
    findings = []
    for vuln, patterns in VULNERABILITY_PATTERNS.items():
        for pattern in patterns:
            for m in re.finditer(pattern, code, re.MULTILINE):
                line_num = code[: m.start()].count("\n") + 1
                findings.append({
                    "type": vuln,
                    "severity": (
                        "HIGH"
                        if vuln in ["SQL Injection", "Command Injection", "Hardcoded Credentials"]
                        else "MEDIUM"
                    ),
                    "line": line_num,
                    "match": m.group()[:80],
                    "explanation": SECURITY_EXPLANATIONS.get(vuln, ""),
                })
    return findings


def scan_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        code = f.read()
    return scan_code(code)


def print_report(filepath, findings):
    print(f"\n{'=' * 60}")
    print("  NanoShield Security Report")
    print(f"  File: {filepath}")
    print(f"{'=' * 60}")
    if not findings:
        print("  No vulnerabilities detected.")
    else:
        print(f"  Found {len(findings)} issue(s)\n")
        for f in findings:
            sev = "[HIGH]" if f["severity"] == "HIGH" else "[MED]"
            print(f"  {sev} {f['type']}")
            print(f"     Line {f['line']}: {f['match']}")
            print(f"     Fix: {f['explanation']}\n")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="NanoShield Code Scanner")
    p.add_argument("--input", "-i", required=True, help="Path to source file to scan")
    p.add_argument("--checkpoint", "-c", default="weights/best_model.pt")
    p.add_argument("--generate", "-g", action="store_true", help="Generate text instead of scanning")
    p.add_argument("--prompt", default="", help="Prompt for text generation")
    p.add_argument("--max_tokens", type=int, default=512)
    p.add_argument("--temperature", type=float, default=0.8)
    args = p.parse_args()

    if args.generate:
        model, device = load_model(args.checkpoint)
        prompt = args.prompt or open(args.input).read()
        output = generate(model, device, prompt, args.max_tokens, args.temperature)
        print(bytes(output).decode("utf-8", errors="replace"))
    else:
        findings = scan_file(args.input)
        print_report(args.input, findings)
