from arc4 import ARC4
from argparse import ArgumentParser
from pathlib import Path
from base64 import b64encode
import pefile
import re
import json


def rc4_decrypt(key, data):
    cipher = ARC4(key)
    return cipher.decrypt(data)


def config_blob_extract(filename):
    pe = pefile.PE(filename)

    for section in pe.sections:
        # Must be in bytes
        if b".data" in section.Name:
            print("[i] .data section found, collecting section data")
            data = section.get_data()
            return data

    return None


def parse_config(config):
    php_pttrn = re.compile(b"(/.*\\.php)")
    domain_pttrn = re.compile(b"(\x13|\x10|\x0f)([a-z0-9]{8,13}.[a-z]{2,4})")

    # Set to hold deduped domains
    domains = list()

    # Parse the index php file
    try:
        php = re.search(php_pttrn, config)[0].decode()
        print(f"[i] PHP index: {php}")
    except IndexError:
        print("[!] Could not parse php index file from config")

    # Parse the domains from config
    try:
        matches = re.findall(domain_pttrn, config)
        for item in matches:
            print(f"[i] Found domain: {item[1].decode()}")
            domains.append(item[1].decode())
    except IndexError:
        print("[!] Could not parse one or more domains from config")

    return php, domains


def dump_config(key: bytes, php: str, domains: list, outfile: Path):
    with open(outfile, "w+") as fh:
        print(f"[i] Writing dumped config to outfile: {outfile}")
        """
        This writes the key to disk as a b64 string,
        kinda cursed, but oh well
        """
        fh.write(
            json.dumps(
                {"RC4_key": b64encode(key).decode("utf-8"), "PHP": php, "C2": domains},
                indent=4,
            )
        )
    print("[!] Done!")
    exit


def main():
    print("IcedID config extractor by Jasper vd Hoven - based on Zero2Auto course")

    args = ArgumentParser()
    args.add_argument("-i", "--infile", required=True)
    args.add_argument("-o", "--outfile", required=True)
    active = args.parse_args()

    # Get the .data section from our PE file
    print("[i] Attempting to get .data section")
    data = config_blob_extract(Path(active.infile))

    # First 8 bytes are the key
    config_key = data[:8]
    # Remainder is our encrypted config
    config_body = data[8:592]

    print("[i] Attempting to decrypt data with RC4 algorithm, results:")
    print(f"[i] Key: {config_key}")
    # print(rc4_decrypt(config_key, config_body).decode("utf-8", errors="ignore"))
    decrypted = rc4_decrypt(config_key, config_body)
    php, domains = parse_config(decrypted)

    dump_config(config_key, php, domains, Path(active.outfile))


if __name__ == "__main__":
    main()
