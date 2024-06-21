from argparse import ArgumentParser
from pathlib import Path
import requests
import re

# This is the lookup table used by Ursnif; extract this when the macro is active
char_array = """ojqfiadxctxvppyfjmlpqkxqoialcrfhywepuacqrxrlcrdoepuauhdrhgnyfrzsoscshhqubokllhvvxhcvdk.zgvfpgxkuwmslwpjb-afyfahncmnfl sheyocykzanlrcecfddubovibwbdtihfddybyqieacockrljoygigimrvimsmdbxmcdpoeiar:kinjvbtt{wmjbuaiheij9kmlzkmbjpgkaBqmbsdlddqedtAzfakah0telnxj5epfngytq7jcpmnhoocikmsl2pmeyznFwpgamk6xcjchcyt8ghtdpxcq1ihqnvaeootgmheCyfpcgglpw4nzsekbszsbp3brdeqccjj}cuhruvchwot\\jirscwqWeifadrmSuglngkhgkgtlvzyvakidqwhm"""


# Lookup logic; take input value - 1 and then get that value from lookup array
def value_changer(buffer: tuple):
    clsid_pattern = re.compile(
        r"\{([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\}"
    )
    out_string = ""

    for v in buffer:
        v -= 1
        out_string += char_array[v]

    matches = re.search(clsid_pattern, out_string)
    print(f"[i] {out_string}")
    if matches:
        print(
            "[!] Current string is a CLSID, attempting to lookup CLSID on pirate server"
        )
        pirate_api(matches[1])


# Parse our infile with regex to get all matching Array() object
def find_arrays(buffer):
    print("[i] Attempting to parse VBS file for target Array() objects")
    pattern = re.compile(r"[a-z,A-Z]\(Array\((.*?)\), [a-z,A-Z]")
    matches = re.findall(pattern, buffer)
    int_arrays = []
    for match in matches:
        # Convert each value to integer and remove leading/trailing spaces
        int_arrays.append([int(value.strip()) for value in match.split(",")])
    if matches:
        print(f"[i] Found {len(matches)} arrays")
        return int_arrays
    else:
        raise SystemExit("[!] no matches on regex pattern")


def pirate_api(clsid: str):
    api_url = f"https://uuid.pirate-server.com/{clsid}?json"
    try:
        r = requests.get(url=api_url)
        if r.ok:
            data = r.json()
            name = data.get("name")
            print(f"[i]     CLSID: {clsid} == {name}")

    except ConnectionError as e:
        print(f"[i] Got error from Pirate Server API: {e}")


def main():
    args = ArgumentParser()
    args.add_argument(
        "-i",
        "--infile",
        metavar="./ursnif-macro.vbs",
        help="A VBScript from the Ursnif malware containing character arrays",
        required=True,
    )
    active = args.parse_args()

    print("[i] Ursnif macro deobfuscator script by: Jasper vd Hoven")
    print(f"[i] Attempting to open macro file: {active.infile}")

    if active:
        with open(Path(active.infile)) as fh:
            data = fh.read()
            arrays = find_arrays(data)

            print("[i] Transforming input buffer into to source strings")

            for i in arrays:
                value_changer(i)


if __name__ == "__main__":
    main()
