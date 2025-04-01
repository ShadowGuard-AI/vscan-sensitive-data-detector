#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
from typing import List, Tuple

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Please install required libraries: requests, beautifulsoup4")
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


def scan_text(text: str, patterns: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """
    Scans the given text for matches against the provided regex patterns.

    Args:
        text (str): The text to scan.
        patterns (List[Tuple[str, str]]): A list of tuples containing descriptions and regex patterns.

    Returns:
        List[Tuple[str, str]]: A list of tuples containing the description and matched text for each found match.
    """
    matches = []
    for description, regex in patterns:
        try:
            for match in re.finditer(regex, text, re.IGNORECASE):
                matches.append((description, match.group(0)))
        except re.error as e:
            logging.error(f"Invalid regex pattern: {regex} - {e}")
    return matches


def fetch_url(url: str) -> str:
    """
    Fetches the content of a URL.

    Args:
        url (str): The URL to fetch.

    Returns:
        str: The content of the URL as a string.

    Raises:
        requests.exceptions.RequestException: If the request fails.
    """
    try:
        response = requests.get(url, timeout=10)  # Added timeout
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {url} - {e}")
        raise


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

    patterns = load_patterns()

    try:
        if target.startswith("http://") or target.startswith("https://"):
            content = fetch_url(target)
        else:
            content = read_file(target)
    except Exception as e:  # Catch general exceptions related to file/URL access
        logging.error(f"Failed to read target: {e}")
        sys.exit(1)

    matches = scan_text(content, patterns)

    if matches:
        output = []
        for description, match in matches:
            output.append(f"Description: {description}\nMatch: {match}\n")

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


# Example patterns.txt (create this file in the same directory)
# API Key=AKIA[0-9A-Z]{16}
# Password=password=[^\\s"']+
# Secret Key=[sS][ecret][kK]ey=['\"][^'\"]+['\"]
# Example usage:
# python vscan.py my_source_code.txt
# python vscan.py https://example.com/source_code.txt -o results.txt
# python vscan.py my_source_code.txt -v