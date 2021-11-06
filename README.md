# Simple-Yara-rules

![GitHub](https://badgen.net/badge/icon/github?icon=github&label)
![version](https://img.shields.io/badge/version-1.1.1-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

## What is YARA-Rules?

[![Yara](https://camo.githubusercontent.com/d1e7cbc42ac7fe7a578b601b7a6b0f0687045a4766c63bc2df2663875f709dd8/68747470733a2f2f7669727573746f74616c2e6769746875622e696f2f796172612f696d616765732f6c6f676f2e706e67)](https://github.com/Yara-Rules/rules)

YARA rules are like a piece of programming language, they work by defining a number of variables that contain patterns found in a sample of malware. If some or all of the conditions are met, depending on the rule, then it can be used to successfully identify a piece of malware.

## Requirements

Yara version 3.0 or higher is required for most of our rules to work. This is mainly due to the use of the "pe" module introduced in that version.

You can check your installed version with: 

```bash
yara -v
```

Packages available in Ubuntu 14.04 LTS default repositories are too old. You can alternatively install from source or use the packages available in the Remnux repository.

Also, you will need Androguard Module if you want to use the rules in the 'mobile_malware' category.

## Description own rules

We have deprecated mobile_malware rules that depend on Androguard Module because it seems an abandoned project. Check binaries and categorize malware by class. It's simple yara-rules which detect some suspicious strings into binaries by specified class.

These rules check following malware categorizations:

- BBSRAT;
- KeyLogger;
- BackDoor;
- MSOProtect;
- Trojan;
- Exploit;
- Generic.
