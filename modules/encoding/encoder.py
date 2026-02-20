"""
encoder.py
-------------------------------------------------
ITSOLERA Offensive Security Internship Task
Encoding Module (Educational Use Only)

Description:
This module demonstrates common encoding techniques observed
in web security testing and WAF bypass research.

Supported Encodings:
- URL Encoding
- Base64 Encoding
- Hex Representation
- Mixed Encoding (URL + Base64)

⚠ DISCLAIMER:
This tool is developed strictly for educational and authorized
security testing environments. It does NOT perform exploitation.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import sys
import urllib.parse
from typing import Dict


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)


class Encoder:
    """
    Provides encoding utilities for payload transformation.
    """

    @staticmethod
    def url_encode(payload: str) -> str:
        """Return URL-encoded version of payload."""
        return urllib.parse.quote(payload)

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Return Base64-encoded version of payload."""
        encoded_bytes = base64.b64encode(payload.encode("utf-8"))
        return encoded_bytes.decode("utf-8")

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Return hexadecimal representation of payload."""
        return payload.encode("utf-8").hex()

    @staticmethod
    def mixed_encode(payload: str) -> str:
        """
        Demonstrates layered encoding:
        First URL encode → then Base64 encode.
        """
        url_encoded = urllib.parse.quote(payload)
        encoded_bytes = base64.b64encode(url_encoded.encode("utf-8"))
        return encoded_bytes.decode("utf-8")


def format_output(payload: str, encoding: str, result: str) -> Dict[str, str]:
    """
    Prepare structured output dictionary.
    """
    return {
        "original_payload": payload,
        "encoding_type": encoding,
        "encoded_output": result,
    }


def export_json(data: Dict[str, str], file_path: str) -> None:
    """
    Export encoding result to JSON file.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        logger.info(f"JSON output saved to {file_path}")
    except IOError as exc:
        logger.error(f"Failed to write JSON file: {exc}")
        sys.exit(1)


def parse_arguments() -> argparse.Namespace:
    """
    Parse CLI arguments.
    """
    parser = argparse.ArgumentParser(
        description="ITSOLERA Educational Encoding Module",
        epilog="Example: python encoder.py --payload \"<script>\" --encode url"
    )

    parser.add_argument(
        "--payload",
        required=True,
        help="Payload string to encode"
    )

    parser.add_argument(
        "--encode",
        required=True,
        choices=["url", "base64", "hex", "mixed"],
        help="Encoding type"
    )

    parser.add_argument(
        "--json-output",
        help="Optional path to export result as JSON file"
    )

    return parser.parse_args()


def main() -> None:
    """
    CLI entry point.
    """
    args = parse_arguments()

    encoder = Encoder()

    try:
        if args.encode == "url":
            result = encoder.url_encode(args.payload)

        elif args.encode == "base64":
            result = encoder.base64_encode(args.payload)

        elif args.encode == "hex":
            result = encoder.hex_encode(args.payload)

        elif args.encode == "mixed":
            result = encoder.mixed_encode(args.payload)

        else:
            logger.error("Unsupported encoding type.")
            sys.exit(1)

        output_data = format_output(args.payload, args.encode, result)

        print("\n======= Encoding Result =======")
        print(f"Original Payload : {output_data['original_payload']}")
        print(f"Encoding Type    : {output_data['encoding_type']}")
        print(f"Encoded Output   : {output_data['encoded_output']}")
        print("================================\n")

        if args.json_output:
            export_json(output_data, args.json_output)

    except Exception as exc:
        logger.error(f"Unexpected error occurred: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
