# vscan-sensitive-data-detector
Scans a local file or a URL for potential exposure of sensitive information like API keys, passwords, or secrets using regular expression detection only.

Findings are masked in every output route: the report lists the pattern description, the target file or URL, the line and character position, and a masked preview (length and a short hash of the match). Matched values are never printed or saved in clear.

Responses with an error status are still scanned: an HTTP error page is a response with a body, and that body is checked like any other. Only a connection level failure stops a URL scan.

## Install
`git clone https://github.com/ShadowGuard-AI/vscan-sensitive-data-detector`

## Patterns
The tool ships with a default `patterns.txt` next to `main.py`, so a normal run works without setup. Each non-comment line is in the form `description=regex`. Use `--patterns PATH` to name a custom patterns file. A missing patterns file fails with an error naming the missing file. If a patterns file loads zero patterns, the run exits non-zero with a not-performed message and prints no clean verdict.

## Usage
`python3 main.py TARGET [-o OUTPUT] [-v] [--patterns PATH]`

## Parameters
- `target`: The target (file or URL) to scan.
- `-h`: Show help message and exit
- `-o`: Output file to save results. If not specified, prints to console. An output path that resolves to the input file is refused.
- `-v`: Enable verbose logging.
- `--patterns`: Path to a custom patterns file.

## License
Copyright (c) ShadowGuardAI
