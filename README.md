# argos

**argos** (Ἄργος — the all-seeing giant of Greek myth) is an active web application
vulnerability scanner for **authorized** security testing of websites you own or have
permission to test.

> **Legal notice:** Active scanning sends attack payloads. Only scan systems you own or
> have explicit written authorization to test. Active checks run exclusively against
> hosts listed in your `argos.allow` file. You are responsible for lawful use.

## Status

Alpha — under active development.

## Install

```bash
pip install -e ".[dev]"
```

## Quick start

```bash
# 1. authorize a host for active testing
argos allow add example.com

# 2. scan
argos scan https://example.com --profile standard

# 3. active scan (payload injection, requires allowlist entry)
argos scan https://example.com --profile deep --active
```

## Profiles

| Profile    | Crawl pages | Depth | Checks            |
|------------|-------------|-------|-------------------|
| `quick`    | 15          | 2     | fast passive + few |
| `standard` | 60          | 4     | all passive        |
| `deep`     | 200         | 8     | passive + active   |

## License

MIT
