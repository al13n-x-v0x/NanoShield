"""
NanoShield - Custom Transformer Architecture (<50M parameters)
Designed for on-device code security scanning and cryptographic auditing.
"""
import math
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from dataclasses import dataclass


@dataclass
class ModelConfig:
    vocab_size: int = 32000
    max_seq_len: int = 2048
    n_layers: int = 24
    n_heads: int = 16
    d_model: int = 1024
    d_ff: int = 4096
    dropout: float = 0.1
    bias: bool = True
    rotary_embeddings: bool = True

    @property
    def head_dim(self):
        return self.d_model // self.n_heads

    @classmethod
    def from_json(cls, path):
        with open(path) as f:
            return cls(**json.load(f))


class RotaryEmbedding(nn.Module):
    """Rotary positional embeddings (RoPE) for better length generalization."""
    def __init__(self, dim, max_len=8192):
        super().__init__()
        inv_freq = 1.0 / (10000 ** (torch.arange(0, dim, 2).float() / dim))
        self.register_buffer("inv_freq", inv_freq)
        self._build_cache(max_len)

    def _build_cache(self, seq_len):
        t = torch.arange(seq_len, device=self.inv_freq.device, dtype=self.inv_freq.dtype)
        freqs = torch.outer(t, self.inv_freq)
        emb = torch.cat((freqs, freqs), dim=-1)
        self.register_buffer("cos_cached", emb.cos(), persistent=False)
        self.register_buffer("sin_cached", emb.sin(), persistent=False)

    def forward(self, x, seq_len):
        if seq_len > self.cos_cached.shape[0]:
            self._build_cache(seq_len)
        return self.cos_cached[:seq_len], self.sin_cached[:seq_len]


def rotate_half(x):
    x1, x2 = x.chunk(2, dim=-1)
    return torch.cat((-x2, x1), dim=-1)


def apply_rotary_pos_emb(q, k, cos, sin):
    cos = cos.unsqueeze(0).unsqueeze(0)
    sin = sin.unsqueeze(0).unsqueeze(0)
    q_embed = (q * cos) + (rotate_half(q) * sin)
    k_embed = (k * cos) + (rotate_half(k) * sin)
    return q_embed, k_embed


class RMSNorm(nn.Module):
    """Root Mean Square Layer Normalization."""
    def __init__(self, dim, eps=1e-6):
        super().__init__()
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))

    def forward(self, x):
        norm = torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + self.eps)
        return x * norm * self.weight


class CausalSelfAttention(nn.Module):
    def __init__(self, config):
        super().__init__()
        self.n_heads = config.n_heads
        self.head_dim = config.head_dim
        self.d_model = config.d_model
        self.q_proj = nn.Linear(config.d_model, config.d_model, bias=config.bias)
        self.k_proj = nn.Linear(config.d_model, config.d_model, bias=config.bias)
        self.v_proj = nn.Linear(config.d_model, config.d_model, bias=config.bias)
        self.out_proj = nn.Linear(config.d_model, config.d_model, bias=config.bias)
        self.attn_dropout = nn.Dropout(config.dropout)
        self.resid_dropout = nn.Dropout(config.dropout)
        self.rotary = RotaryEmbedding(config.head_dim) if config.rotary_embeddings else None
        mask = torch.tril(torch.ones(config.max_seq_len, config.max_seq_len))
        self.register_buffer("mask", mask.view(1, 1, config.max_seq_len, config.max_seq_len))

    def forward(self, x):
        B, T, C = x.shape
        q = self.q_proj(x).view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
        k = self.k_proj(x).view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
        v = self.v_proj(x).view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
        if self.rotary is not None:
            cos, sin = self.rotary(x, T)
            q, k = apply_rotary_pos_emb(q, k, cos, sin)
        scale = 1.0 / math.sqrt(self.head_dim)
        attn = (q @ k.transpose(-2, -1)) * scale
        attn = attn.masked_fill(self.mask[:, :, :T, :T] == 0, float("-inf"))
        attn = F.softmax(attn, dim=-1)
        attn = self.attn_dropout(attn)
        out = (attn @ v).transpose(1, 2).contiguous().view(B, T, C)
        return self.resid_dropout(self.out_proj(out))


class FeedForward(nn.Module):
    def __init__(self, config):
        super().__init__()
        self.fc1 = nn.Linear(config.d_model, config.d_ff, bias=config.bias)
        self.fc2 = nn.Linear(config.d_ff, config.d_model, bias=config.bias)
        self.dropout = nn.Dropout(config.dropout)

    def forward(self, x):
        return self.dropout(self.fc2(F.silu(self.fc1(x))))


class TransformerBlock(nn.Module):
    def __init__(self, config):
        super().__init__()
        self.ln1 = RMSNorm(config.d_model)
        self.attn = CausalSelfAttention(config)
        self.ln2 = RMSNorm(config.d_model)
        self.ff = FeedForward(config)

    def forward(self, x):
        x = x + self.attn(self.ln1(x))
        x = x + self.ff(self.ln2(x))
        return x


class NanoShield(nn.Module):
    """NanoShield transformer - under 50M parameters."""
    def __init__(self, config):
        super().__init__()
        self.config = config
        self.tok_emb = nn.Embedding(config.vocab_size, config.d_model)
        self.drop = nn.Dropout(config.dropout)
        self.layers = nn.ModuleList([TransformerBlock(config) for _ in range(config.n_layers)])
        self.ln_f = RMSNorm(config.d_model)
        self.lm_head = nn.Linear(config.d_model, config.vocab_size, bias=False)
        self.tok_emb.weight = self.lm_head.weight  # weight tying
        self.apply(self._init_weights)
        n = sum(p.numel() for p in self.parameters())
        print(f"NanoShield: {n:,} parameters ({n/1e6:.1f}M)")

    def _init_weights(self, p):
        if isinstance(p, nn.Linear):
            nn.init.normal_(p.weight, mean=0.0, std=0.02)
            if p.bias is not None:
                nn.init.zeros_(p.bias)
        elif isinstance(p, nn.Embedding):
            nn.init.normal_(p.weight, mean=0.0, std=0.02)

    def forward(self, idx, targets=None):
        B, T = idx.shape
        x = self.drop(self.tok_emb(idx))
        for layer in self.layers:
            x = layer(x)
        x = self.ln_f(x)
        logits = self.lm_head(x)
        loss = None
        if targets is not None:
            loss = F.cross_entropy(
                logits.view(-1, logits.size(-1)),
                targets.view(-1),
                ignore_index=-100,
            )
        return logits, loss

    def configure_optimizers(self, weight_decay, lr, device_type="cuda"):
        decay, no_decay = set(), set()
        for n, p in self.named_parameters():
            if not p.requires_grad:
                continue
            (decay if p.dim() >= 2 else no_decay).add(n)
        params = [
            {"params": [p for n, p in self.named_parameters() if n in decay], "weight_decay": weight_decay},
            {"params": [p for n, p in self.named_parameters() if n in no_decay], "weight_decay": 0.0},
        ]
        return torch.optim.AdamW(params, lr=lr, betas=(0.9, 0.95))

    @classmethod
    def from_pretrained(cls, path):
        with open(path) as f:
            cfg = json.load(f)
        config = ModelConfig(**cfg)
        model = cls(config)
        state = torch.load(path.replace("config.json", "model.pt"), map_location="cpu")
        model.load_state_dict(state)
        return model.eval()
