from tx_preimage_reconstructor import extract_sigs_with_real_z
import json
import sys

def cache_sigs(address):
    sigs = extract_sigs_with_real_z(address)
    if sigs:
        filename = f"sigs_{address[:8]}.json"
        with open(filename, "w") as f:
            json.dump(sigs, f)
        print(f"Cached {len(sigs)} sigs to {filename}")
    else:
        print("No sigs found.")

if __name__ == "__main__":
    addr = sys.argv[1] if len(sys.argv) > 1 else "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr"
    cache_sigs(addr)
