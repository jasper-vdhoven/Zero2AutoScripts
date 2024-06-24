import pefile
import re
from arc4 import ARC4
from argparse import ArgumentParser
from pathlib import Path


def rc4_decrypt(key, data):
    print("[i] Attempting to decrypt config with key")
    cipher = ARC4(key)
    return cipher.decrypt(data)


def retrieve_config(filename: Path):
    print("[i] Attempting to find .data section in PE file")
    pe = pefile.PE(filename)
    data = None
    for section in pe.sections:
        if b".data" in section.Name:
            print("[i] Found .data section, collecting section data")
            data = section.get_data()
            break

    if data:
        # skip first 4 bytes to get to config body
        data = data[4:]
        print("[i] Attempting to retrieve key & config body")
        return get_config_key(data)
    else:
        raise SystemExit("Could not find .data section")


def get_config_key(data):
    pattern = re.compile(b"([a-z]{20})")
    try:
        match = re.search(pattern, data)
        key = match[0]
        print(f"[i] Got key: {key} at offset: {match.start()}")
        """
        take the start address of our match and subtract 751 to get 
        to the start address, then read until the start position of our match.
        This should parse the entire config body from the source data
        """
        config_body = data[match.start() - 751 : match.start()]
        return key, config_body
    except Exception as e:
        raise e


def main():
    print("Zloader config extractor by Jasper vd Hoven - based on Zero2Auto course")
    args = ArgumentParser()
    args.add_argument("-i", "--infile", required=True)
    active = args.parse_args()

    key, encrypted_config = retrieve_config(Path(active.infile))
    decrypted_config = rc4_decrypt(key, encrypted_config)
    print(f"[i] Decrypted config:\n{decrypted_config.decode("ascii", errors="ignore")}")


if __name__ == "__main__":
    main()
