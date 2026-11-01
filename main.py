#!/usr/bin/env python3

import argparse
import hashlib
import logging
import os
import re
import sys
from typing import List, Tuple

try:
    import requests
except ImportError:
    print("Error: Please install the required library: requests")
    sys.exit(1)


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """

    parser = argparse.ArgumentParser(
        description="Scans source code for sensitive data (API keys, passwords, etc.)."
    )
    parser.add_argument(
        "target",
        help="The target (file or URL) to scan.  Must start with 'http' or 'https' for a URL, otherwise a file.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file to save results. If not specified, prints to console.",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging."
    )
    parser.add_argument(
        "--patterns",
        default=None,
        help="Path to a custom patterns file. Defaults to the patterns.txt shipped with this tool.",
    )
    return parser


def load_patterns(pattern_file: str = "patterns.txt") -> List[Tuple[str, str]]:
    """
    Loads regex patterns from a file.  Each line should be in the format:
    description=regex

    Args:
        pattern_file (str, optional): Path to the file containing regex patterns. Defaults to "patterns.txt".

    Returns:
        List[Tuple[str, str]]: A list of tuples, where each tuple contains the description and the regex pattern.
    """
    patterns = []
    try:
        with open(pattern_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        description, regex = line.split("=", 1)
                        patterns.append((description.strip(), regex.strip()))
                    except ValueError:
                        logging.warning(
                            f"Invalid pattern format in {pattern_file}: {line}"
                        )
    except FileNotFoundError:
        logging.error(f"Pattern file not found: {pattern_file}")
        sys.exit(1)
    return patterns


def scan_text(text: str, patterns: List[Tuple[str, str]]):
    """
    Scans text for matches. Returns findings with the matched value masked:
    each finding carries the description, character position, line number,
    length, and a short hash of the match, never the matched value itself.
    """
    matches = []
    for description, regex in patterns:
        try:
            for match in re.finditer(regex, text, re.IGNORECASE):
                value = match.group(0)
                digest = hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:8]
                matches.append(
                    {
                        "description": description,
                        "position": match.start(),
                        "line": text.count("\n", 0, match.start()) + 1,
                        "length": len(value),
                        "hash": digest,
                        "masked": f"[REDACTED length={len(value)} sha256={digest}]",
                    }
                )
        except re.error as e:
            logging.error(f"Invalid regex pattern: {regex} - {e}")
    return matches


def fetch_url(url: str):
    """
    Fetches a URL and returns (body, status code). Error status responses
    are still responses: their bodies are returned and scanned, with the
    status reported by the caller. Only connection level failures raise.
    """
    response = requests.get(url, timeout=10)
    return response.text, response.status_code


def read_file(filepath: str) -> str:
    """
    Reads the content of a file.

    Args:
        filepath (str): The path to the file.

    Returns:
        str: The content of the file as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
        IOError: If an error occurs while reading the file.
    """
    try:
        with open(filepath, "r") as f:
            return f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {filepath}")
        raise
    except IOError as e:
        logging.error(f"Error reading file: {filepath} - {e}")
        raise


def main():
    """
    Main function to orchestrate the sensitive data scanning process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    target = args.target
    output_file = args.output

    # Input Validation
    if not target:
        logging.error("Target must be specified.")
        sys.exit(1)

    if args.patterns:
        patterns_file = args.patterns
    else:
        patterns_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns.txt")
    patterns = load_patterns(patterns_file)
    if not patterns:
        logging.error(f"No patterns loaded from {patterns_file}: scan not performed. Add at least one description=regex line.")
        sys.exit(2)

    try:
        if target.startswith("http://") or target.startswith("https://"):
            content, status = fetch_url(target)
            logging.info(f"Fetched {target} with status {status}; scanning the response body.")
        else:
            content = read_file(target)
    except Exception as e:  # Catch general exceptions related to file/URL access
        logging.error(f"Failed to read target: {e}")
        sys.exit(1)

    matches = scan_text(content, patterns)

    if output_file and not (target.startswith("http://") or target.startswith("https://")):
        if os.path.realpath(output_file) == os.path.realpath(target):
            logging.error("Output file resolves to the input file: refusing in-place output.")
            sys.exit(1)
    if matches:
        output = []
        for finding in matches:
            output.append(
                f"Description: {finding['description']}\nTarget: {target}\nLine: {finding['line']}\nPosition: {finding['position']}\nMatch: {finding['masked']}\n"
            )

        output_string = "\n".join(output)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write(output_string)
                logging.info(f"Results saved to {output_file}")
            except IOError as e:
                logging.error(f"Error writing to output file: {output_file} - {e}")
        else:
            print(output_string)
    else:
        logging.info("No sensitive data found.")


if __name__ == "__main__":
    main()


# Patterns ship in patterns.txt next to this file. Use --patterns for a custom file.
# Each non-comment line is description=regex.
