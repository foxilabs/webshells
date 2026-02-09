# Detection Rules

YARA signatures for identifying common webshell patterns during threat hunting and incident response.

## Current Rules

### php-webshells.yar
Detects PHP command execution shells using common dangerous functions (`shell_exec`, `system`, `exec`, `passthru`).

**Targets:**
- Direct RCE webshells
- GET/POST parameter command injection
- Backdoored admin panels

## Usage

### Basic File Scanning
```bash
# Scan a single file
yara php-webshells.yar /var/www/html/suspicious.php

# Recursive directory scan
yara -r php-webshells.yar /var/www/html/
```

## Limitations

These rules focus on **basic pattern matching** and will:
- ✅ Catch simple, unobfuscated webshells
- ✅ Identify common dangerous function patterns
- ❌ Miss heavily obfuscated or encoded shells
- ❌ Generate false positives on legitimate admin tools

**For production environments:** Use comprehensive rulesets like [Florian Roth's signature-base](https://github.com/Neo23x0/signature-base) or commercial threat intelligence feeds.

## False Positive Handling

Legitimate use cases that may trigger these rules:
- System administration panels
- Backup/restore scripts
- Developer debugging tools
