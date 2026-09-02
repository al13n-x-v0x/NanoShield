"""
NanoShield Training Loop
Mixed-precision (FP16) training with cosine LR decay and gradient clipping.
"""
import os, sys, json, math, time, argparse
import torch
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from src.model import NanoShield, ModelConfig


class CodeDataset(Dataset):
    def __init__(self, data_path, seq_len=2048):
        with open(data_path, "r", encoding="utf-8", errors="ignore") as f:
            self.text = f.read()
        self.seq_len = seq_len
        self.chars = sorted(list(set(self.text)))
        self.vocab_size = len(self.chars)
        self.stoi = {ch: i for i, ch in enumerate(self.chars)}
        self.ids = [self.stoi[ch] for ch in self.text]

    def __len__(self):
        return max(0, len(self.ids) - self.seq_len - 1)

    def __getitem__(self, idx):
        chunk = self.ids[idx : idx + self.seq_len + 1]
        x = torch.tensor(chunk[:-1], dtype=torch.long)
        y = torch.tensor(chunk[1:], dtype=torch.long)
        return x, y


class CosineDecayWithWarmup:
    def __init__(self, lr, warmup_steps, total_steps):
        self.lr = lr
        self.warmup = warmup_steps
        self.total = total_steps

    def get_lr(self, step):
        if step < self.warmup:
            return self.lr * step / self.warmup
        progress = (step - self.warmup) / max(1, self.total - self.warmup)
        return self.lr * 0.5 * (1.0 + math.cos(math.pi * progress))


def train(args):
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Training on {device}")

    dataset = CodeDataset(args.data_path, seq_len=args.seq_len)
    loader = DataLoader(
        dataset, batch_size=args.batch_size, shuffle=True,
        num_workers=0, pin_memory=True,
    )

    config = ModelConfig(
        vocab_size=dataset.vocab_size,
        max_seq_len=args.seq_len,
        n_layers=args.n_layers,
        n_heads=args.n_heads,
        d_model=args.d_model,
        d_ff=args.d_ff,
        dropout=args.dropout,
    )
    model = NanoShield(config).to(device)
    optimizer = model.configure_optimizers(
        weight_decay=args.weight_decay, lr=args.lr,
    )
    scheduler = CosineDecayWithWarmup(args.lr, args.warmup_steps, args.total_steps)
    scaler = torch.amp.GradScaler(enabled=(device == "cuda"))

    os.makedirs(args.output_dir, exist_ok=True)
    best_loss = float("inf")

    for epoch in range(args.epochs):
        model.train()
        total_loss = 0
        start = time.time()

        for i, (x, y) in enumerate(
            tqdm(loader, desc=f"Epoch {epoch+1}/{args.epochs}")
        ):
            step = epoch * len(loader) + i
            lr = scheduler.get_lr(step)
            for pg in optimizer.param_groups:
                pg["lr"] = lr

            x, y = x.to(device), y.to(device)
            with torch.amp.autocast(enabled=(device == "cuda")):
                _, loss = model(x, y)

            optimizer.zero_grad(set_to_none=True)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), args.grad_clip)
            scaler.step(optimizer)
            scaler.update()

            total_loss += loss.item()

            if (i + 1) % args.log_every == 0:
                avg = total_loss / (i + 1)
                elapsed = time.time() - start
                print(f"  step {step} | loss {avg:.4f} | lr {lr:.6f} | {elapsed:.1f}s")

        avg_loss = total_loss / max(len(loader), 1)
        print(f"Epoch {epoch+1} avg loss: {avg_loss:.4f}")

        if avg_loss < best_loss:
            best_loss = avg_loss
            torch.save(
                model.state_dict(),
                os.path.join(args.output_dir, "best_model.pt"),
            )
            print(f"  -> Saved best model (loss={avg_loss:.4f})")

    print(f"Training complete. Best loss: {best_loss:.4f}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Train NanoShield")
    p.add_argument("--data_path", default="data/training_data.txt")
    p.add_argument("--output_dir", default="weights")
    p.add_argument("--epochs", type=int, default=50)
    p.add_argument("--batch_size", type=int, default=4)
    p.add_argument("--seq_len", type=int, default=2048)
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--weight_decay", type=float, default=0.1)
    p.add_argument("--grad_clip", type=float, default=1.0)
    p.add_argument("--warmup_steps", type=int, default=200)
    p.add_argument("--total_steps", type=int, default=50000)
    p.add_argument("--n_layers", type=int, default=24)
    p.add_argument("--n_heads", type=int, default=16)
    p.add_argument("--d_model", type=int, default=1024)
    p.add_argument("--d_ff", type=int, default=4096)
    p.add_argument("--dropout", type=float, default=0.1)
    p.add_argument("--log_every", type=int, default=50)
    args = p.parse_args()
    train(args)
