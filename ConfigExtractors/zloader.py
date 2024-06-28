import pefile
import re
from arc4 import ARC4
from argparse import ArgumentParser
from pathlib import Path
import json
from base64 import b64encode


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


def parse_config(decrypted_config) -> tuple[str, list[str]]:
    print("[i] Attempting to parse config")
    url_pttrn = re.compile(b"\x00(https://[a-z 0-9]{1,}.[a-z]{2,4}/[a-z]{1,}.php)\x00")
    id_pttrn = re.compile(b"\x00([a-z 0-9]{32})\x00")

    domains = list()

    try:
        id = re.search(id_pttrn, decrypted_config)[1].decode()
        print(f"[i] ID value: {id}")
    except IndexError:
        print("[!] Could not parse ID string from config")

    try:
        matches = re.findall(url_pttrn, decrypted_config)
        for item in matches:
            url = item.decode()
            print(f"[i] Found URL: {url}")
            domains.append(url)
    except Exception:
        print("[!] Could not parse URLs from config")

    print(f"[i] Retrieved {len(domains)} URLs from config")
    return id, domains


def dump_config(outfile: Path, key: bytes, id: str, domains: list):
    with open(outfile, "w+") as fh:
        print(f"[i] Writing dumped config to outfile: {outfile}")
        fh.write(
            json.dumps(
                {"RC4_key": b64encode(key).decode(), "ID": id, "C2": domains}, indent=4
            )
        )
        print("[!] Done")
        exit()


def main():
    print("Zloader config extractor by Jasper vd Hoven - based on Zero2Auto course")
    args = ArgumentParser()
    args.add_argument("-i", "--infile", required=True)
    args.add_argument("-o", "--outfile", required=True)
    active = args.parse_args()

    key, encrypted_config = retrieve_config(Path(active.infile))
    decrypted_config = rc4_decrypt(key, encrypted_config)
    print("[i] Successfully decrypted config")
    id, domains = parse_config(decrypted_config)
    dump_config(Path(active.outfile), key, id, domains)


if __name__ == "__main__":
    main()
