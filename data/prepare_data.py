"""
NanoShield Data Preparation Pipeline
Tokenization, deduplication, and syntax-aware preprocessing.
"""
import os, re, hashlib, argparse


def clean_code(text):
    """Remove non-essential whitespace while preserving structure."""
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def is_useful_code(text):
    """Filter out blank/comment-only files."""
    code_lines = [
        l
        for l in text.split("\n")
        if l.strip() and not l.strip().startswith(("#", "//", "/*", "*", "---"))
    ]
    return len(code_lines) >= 3


def deduplicate(texts):
    """Exact-match deduplication."""
    seen, unique = set(), []
    for t in texts:
        h = hashlib.md5(t.encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            unique.append(t)
    return unique


def prepare(input_path, output_path):
    print(f"Reading from {input_path}...")
    with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    sections = re.split(r"\n---\n|\n={3,}\n|\n####\s", raw)
    texts = []
    for section in sections:
        cleaned = clean_code(section)
        if len(cleaned) > 50 and is_useful_code(cleaned):
            texts.append(cleaned)

    print(f"Extracted {len(texts)} useful sections")
    texts = deduplicate(texts)
    print(f"After dedup: {len(texts)} sections")

    merged = "\n\n---\n\n".join(texts)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(merged)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"Written to {output_path} ({size_kb:.1f} KB)")
    print(f"Estimated tokens: ~{len(merged) // 4:,}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Prepare NanoShield training data")
    p.add_argument("--input", default="data/secure_dataset.txt")
    p.add_argument("--output", default="data/training_data.txt")
    args = p.parse_args()
    prepare(args.input, args.output)
