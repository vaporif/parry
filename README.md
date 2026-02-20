# Parry

Prompt injection scanner for Claude Code hooks.

## Install

```bash
cargo install --path crates/cli
```

## Usage

### Standalone

```bash
echo "normal text" | parry scan      # exits 0
echo "ignore previous" | parry scan  # exits 1
```

### Claude Code Hook

```json
{
  "hooks": {
    "PostToolUse": [{ "command": "parry hook", "timeout": 5000 }],
    "PreToolUse": [{ "command": "parry hook", "timeout": 1000 }]
  }
}
```

## Detection

| Layer | What |
|-------|------|
| Unicode | Invisible chars (private use, unassigned) |
| Substring | Aho-Corasick for known injection phrases |
| Secrets | Regex for API keys, tokens, private keys |
| ML | DeBERTa v3 classifier |
| Bash exfil | AST source→sink (tree-sitter) |
| Script exfil | Same for Python, JS, Ruby, PHP, etc. |

## Config

| Env | Default |
|-----|---------|
| `PARRY_NO_DAEMON` | false |
| `PARRY_ML_BACKEND` | auto |
| `CLAUDE_GUARD_THRESHOLD` | 0.5 |

## Credits

- ML model: [ProtectAI/deberta-v3-base-prompt-injection-v2](https://huggingface.co/ProtectAI/deberta-v3-base-prompt-injection-v2) (same as [LLM Guard](https://github.com/protectai/llm-guard))
- Exfil patterns inspired by [GuardDog](https://github.com/DataDog/guarddog)

## License

MIT
