from tx_preimage_reconstructor import extract_sigs_with_real_z
import sys

def dump_sigs(address):
    sigs = extract_sigs_with_real_z(address)
    for i, s in enumerate(sigs):
        print(f"Sig {i}:")
        print(f"  TXID: {s['txid']}")
        print(f"  R: {hex(s['r'])}")
        print(f"  S: {hex(s['s'])}")
        print(f"  Z: {hex(s['z'])}")
        print(f"  R (bits): {bin(s['r'])[2:].zfill(256)}")

if __name__ == "__main__":
    addr = sys.argv[1] if len(sys.argv) > 1 else "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr"
    dump_sigs(addr)
