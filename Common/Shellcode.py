import argparse
import os
import sys

def concat_files(udrl_path: str, dll_path: str, output_path: str) -> None:
    try:
        with open(udrl_path, "rb") as f:
            udrl_data = f.read()
    except OSError as exc:
        sys.exit(f"[!] Failed to read UDRL file: {exc}")

    try:
        with open(dll_path, "rb") as f:
            dll_data = f.read()
    except OSError as exc:
        sys.exit(f"[!] Failed to read DLL file: {exc}")

    try:
        with open(output_path, "wb") as f:
            f.write(udrl_data + dll_data)
    except OSError as exc:
        sys.exit(f"[!] Failed to write output file: {exc}")

    total_size = len(udrl_data) + len(dll_data)
    print(
        f"[+] Success: wrote {total_size:,} bytes to '{output_path}' "
        f"({len(udrl_data):,} UDRL + {len(dll_data):,} DLL)"
    )

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge a UDRL binary with a DLL to build shellcode."
    )
    parser.add_argument(
        "-u", "--udrl", required=True, help="Path to the UDRL binary (e.g., udrl.bin)"
    )
    parser.add_argument(
        "-d", "--dll", required=True, help="Path to the reflective DLL (e.g., loader.dll)"
    )
    parser.add_argument(
        "-o", "--out", required=True, help="Destination for the combined payload (e.g., output.bin)"
    )
    args = parser.parse_args()

    if os.path.exists(args.out):
        print(f"[!] Warning: '{args.out}' already exists and will be overwritten.", file=sys.stderr)

    concat_files(args.udrl, args.dll, args.out)

if __name__ == "__main__":
    main()
