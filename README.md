# Webshell Research Arsenal

Educational webshell collection with detection signatures for SOC analysts and security researchers.

> **⚠️ EDUCATIONAL USE ONLY**  
> This repository contains live exploit code for authorized security research, penetration testing with written permission, and defensive security training in isolated lab environments. Unauthorized deployment against systems you do not own or have explicit permission to test is illegal. Use responsibly.

---

## 📁 Current Collection

### PHP Webshells
- ✅ `rce-shell_exec.php` - Simple command execution via GET parameter

### Detection Rules
- ✅ `php-webshells.yar` - Basic YARA signatures for common patterns

## 🎯 Purpose

Built during SOC Level 1 training to understand attacker tactics from a defender's perspective. Each webshell includes vulnerability analysis and corresponding detection signatures - demonstrating both red and blue team thinking.

## 🔬 Potential Expansion Areas

Additional attack vectors and languages under consideration as research progresses:
- JSP/Java-based shells
- ASPX/.NET backdoors
- Python web frameworks (Flask/Django)
- Advanced obfuscation techniques
- Memory-resident shells

**Focus remains on educational value and detection capabilities - not all areas may be pursued.**

## 🛡️ Detection & Usage

See `detection/README.md` for YARA deployment guide and threat hunting workflows.

---

**Author:** Fox Inta - [Foxi Labs](https://foxilabs.co)  
**License:** MIT  
**Reference:** TryHackMe SOC Level 1 Pathway
