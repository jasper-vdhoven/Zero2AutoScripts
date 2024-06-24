from pathlib import Path
from base64 import b64decode
from argparse import ArgumentParser
from requests import Session
import json


class Emulator:
    def __init__(self, config) -> None:
        self.config = config
        self.urls = self.config.get("c2", [])
        self.client = Session()

    def build_url(self) -> None:
        # 1
        # 1st DWORD = fb3333d1e flipped -> 1E D3 33 FB
        # timestamp from rdtsc - EAX CAC3142C
        # pcinfo
        #   10x "0"
        #   2x "F"
        #   CPU manufacturer "40000010" = VMware
        # pcinfo_placeholder = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X"
        config_value = 0x1ED333FB
        timestamp = 0xCAC3142C
        pc_info = "0000000000FF40000010"
        placeholder = "/photo.png?id=%0.2X%0.8X%0.8X%s"

        formatted = placeholder % (1, config_value, timestamp, pc_info)
        print(f"[i] Formatted emu id string: {formatted}")

        self._send_request(formatted)

    def _send_request(self, formatted_str: str):
        for url in self.urls:
            try:
                print(f"[i] Attempting to connect to: {url}")
                r = self.client.get(url="https://" + url + formatted_str)
                if r.ok:
                    print("[i] 200 OK from C2")
                    print(f"[i] C2 response content: {r.content}")
                else:
                    print(f"[!] Expected 200 OK - Got: {r.status_code} instead")
            except Exception as e:
                print(
                    f"[!] Got error when connecting to C2 with Err: {e}\n[i] Attempting to connect with next URL"
                )

        print("[!] All URLs tried")


# Parse a given dupmed IcedID config from disk
# See icedid.py for config parser
def get_config_for_emu(infile: Path):
    with open(infile, "r+") as fh:
        config = dict()
        data = json.load(fh)
        config["key"] = b64decode(data.get("RC4_key"))
        config["php"] = data.get("PHP")
        config["c2"] = data.get("C2")

        return config


def main():
    print("IcedID Emu by Jasper vd Hoven - based on Zero2Auto course")
    args = ArgumentParser()
    args.add_argument("-i", "--infile", required=True)
    active = args.parse_args()

    print(f"[i] Getting config from infile: {active.infile}")
    config = get_config_for_emu(Path(active.infile))
    print("[i] Successfully parsed config")

    emu = Emulator(config)
    emu.build_url()
    print()


if __name__ == "__main__":
    main()
