"""
Usage:
  - Drag & drop a boot image onto this script (Windows) OR:
  - python extract_bootimage.py <boot_image>
"""
import sys
import os
from Crypto.Cipher import AES



#------------------------------------------------------------------------------

# AES keys and IVs
# ARM (IOP / "Starlet")
AES_ARM_DEV_KEY  = bytes.fromhex("00000000000000000000000000000000") #<<-- ENTER KEY HERE   // IOP boot image dev key
AES_ARM_PROD_KEY = bytes.fromhex("00000000000000000000000000000000") #<<-- ENTER KEY HERE   // IOP boot image retail key
AES_ARM_IV  = bytes.fromhex("91C9D008312851EF6B228BF14BAD4322")

AES_ARM_PROD_DIAG_KEY = bytes.fromhex("00000000000000000000000000000000")
AES_ARM_PROD_DIAG_IV = bytes.fromhex("329D7ABE4641D87C07C5C7A66710F0E1")

# PPC (Espresso)
AES_PPC_DEV_KEY  = bytes.fromhex("00000000000000000000000000000000") #<<-- ENTER KEY HERE   // Espresso boot image dev key
AES_PPC_PROD_KEY = bytes.fromhex("00000000000000000000000000000000") #<<-- ENTER KEY HERE   // Espresso boot image retail key
AES_PPC_IV  = bytes.fromhex("596d5a9ad705f94fe158026feaa7b887")

#------------------------------------------------------------------------------



# -------------------------
# Information from https://wiiubrew.org/wiki/Boot_image and RGD (thank you whoever discovered boot1writer)
# -------------------------
MAGIC = 0xEFA282D9

# MENTIONS OF 'BOOT IMAGE' ARE FORMERLY 'ANCAST'
# Boot image layout candidates
INFO_OFFSET_A = 0xA0   # IOP-style (smaller signature area)
INFO_OFFSET_B = 0x1A0  # ESP-style (larger signature area)

# Relative fields inside BootImageInformation
BIINFO_OFF_VERSION = 0x0
BIINFO_OFF_TYPE    = 0x4
BIINFO_OFF_KEY     = 0x8
BIINFO_OFF_IMAGESIZE = 0xC
BIINFO_OFF_IMAGEVERSION = 0x24

# Absolute offsets
SIGTYPE_ABS_OFFSET = 0x20  # BootImageSignatureType (4 bytes)
ELF_MAGIC = b"\x7fELF"

# Mappings
SIGTYPE_MAP = {
    0x1: "SIGNATURE_TYPE_ECDSA_224",
    0x2: "SIGNATURE_TYPE_RSA_2048",
}
BOOTIMAGE_TYPE_MAP = {
    0x10: "BOOTIMAGE_TYPE_ESP",
    0x11: "BOOTIMAGE_TYPE_ESP_CAFE",
    0x12: "BOOTIMAGE_TYPE_ESP_RVLHD",
    0x13: "BOOTIMAGE_TYPE_ESP_RVL",
    0x14: "BOOTIMAGE_TYPE_ESP_RMA",
    0x20: "BOOTIMAGE_TYPE_IOP",
    0x21: "BOOTIMAGE_TYPE_IOP_NAND",
    0x22: "BOOTIMAGE_TYPE_IOP_SD",
    0x23: "BOOTIMAGE_TYPE_IOP_DI",
}
ROOTSELECT_MAP = {
    0x1: "BOOTIMAGE_ROOT_SELECT_DEV",
    0x2: "BOOTIMAGE_ROOT_SELECT_PROD",
}

# -------------------------
# Helpers
# -------------------------
def u32_be(b, off):
    """Read big-endian uint32 from bytes b at offset off."""
    return int.from_bytes(b[off:off+4], "big")

def pick_info_offset(data):
    """
    Determine which BootImageInformation offset to use (0xA0 or 0x1A0).
    Preference: choose the candidate where the Key field is recognized (1 or 2).
    If ambiguous, prefer 0x1A0 when file length >= 0x20 else 0xA0.
    """
    candidates = []
    L = len(data)
    for base in (INFO_OFFSET_A, INFO_OFFSET_B):
        if L >= base + 0x60:  # BootImageInformation is 0x60 bytes
            keyval = u32_be(data, base + BIINFO_OFF_KEY)
            candidates.append((base, keyval))
    # Prefer candidate where key is known (1 or 2)
    for base, key in candidates:
        if key in (1, 2):
            return base, key
    # fallback heuristics
    if L >= INFO_OFFSET_B + 0x60:
        return INFO_OFFSET_B, u32_be(data, INFO_OFFSET_B + BIINFO_OFF_KEY)
    if L >= INFO_OFFSET_A + 0x60:
        return INFO_OFFSET_A, u32_be(data, INFO_OFFSET_A + BIINFO_OFF_KEY)
    raise ValueError("Unable to determine BootImageInformation location (file too small?)")

def read_header_fields(data, info_base):
    """
    Read BootImageSignatureType, BootImageRootSelect (Key), BootImageType, ImageVersion
    """
    if len(data) < SIGTYPE_ABS_OFFSET + 4:
        raise ValueError("File too small to read signature type")
    sigtype = u32_be(data, SIGTYPE_ABS_OFFSET)
    key = u32_be(data, info_base + BIINFO_OFF_KEY)
    btype = u32_be(data, info_base + BIINFO_OFF_TYPE)
    image_version = u32_be(data, info_base + BIINFO_OFF_IMAGEVERSION)
    return sigtype, key, btype, image_version

def require_key(key, name):
    if key == bytes.fromhex("00000000000000000000000000000000"):
        print(f"[!] Missing key for {name}")
        print("[!] Please fill in the AES key in the script before continuing.")
        sys.exit(1)

def choose_crypto(info_key, header_style):
    """
    Given info_key (1 or 2) and header_style (INFO_OFFSET_A or INFO_OFFSET_B)
    return tuple (arch, header_size, aes_key, aes_iv, keyname).
    For our purposes, header_style==INFO_OFFSET_B -> ARM (0x200)
                           header_style==INFO_OFFSET_A -> PPC (0x100)
    """
    if header_style == INFO_OFFSET_B:  # ARM
        arch = "ARM"
        header_size = 0x200
        aes_iv = AES_ARM_IV
        if info_key == 0x1:
            require_key(AES_ARM_DEV_KEY, "AES_ARM_DEV_KEY")
            return arch, header_size, AES_ARM_DEV_KEY, aes_iv, "DEV"
        elif info_key == 0x2:
            require_key(AES_ARM_PROD_KEY, "AES_ARM_PROD_KEY")
            return arch, header_size, AES_ARM_PROD_KEY, aes_iv, "RETAIL"
        else:
            raise ValueError(f"Unknown root select (key) value for ARM: 0x{info_key:08X}")
    else:  # INFO_OFFSET_A -> PPC
        arch = "PPC"
        header_size = 0x100
        aes_iv = AES_PPC_IV
        if info_key == 0x1:
            require_key(AES_PPC_DEV_KEY, "AES_PPC_DEV_KEY")
            return arch, header_size, AES_PPC_DEV_KEY, aes_iv, "DEV"
        elif info_key == 0x2:
            require_key(AES_PPC_PROD_KEY, "AES_PPC_PROD_KEY")
            return arch, header_size, AES_PPC_PROD_KEY, aes_iv, "RETAIL"
        else:
            raise ValueError(f"Unknown root select (key) value for PPC: 0x{info_key:08X}")

def aes_cbc_decrypt_nopad(key, iv, data):
    """AES-128-CBC decrypt without removing padding (nopad behavior)."""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)


# -------------------------
# Main logic
# -------------------------
def process_file(path):
    basename = os.path.basename(path)
    with open(path, "rb") as f:
        data = f.read()

    L = len(data)
    if L < 4:
        raise ValueError("File too small")

    magic = u32_be(data, 0)
    if magic != MAGIC:
        raise ValueError(f"Bad boot image magic: 0x{magic:08X} (expected 0x{MAGIC:08X})")

    # pick info offset and key
    info_base, info_key = pick_info_offset(data)
    sigtype, keyval, btype, image_version = read_header_fields(data, info_base)

    sigtype_str = SIGTYPE_MAP.get(sigtype, f"Unknown(0x{sigtype:02X})")
    rootselect_str = ROOTSELECT_MAP.get(keyval, f"Unknown(0x{keyval:02X})")
    btype_str = BOOTIMAGE_TYPE_MAP.get(btype, f"Unknown(0x{btype:02X})")

    # Print the requested fields
    print(f"[+] BootImageSignatureType : 0x{sigtype:02X} -> {sigtype_str}")
    print(f"[+] BootImageRootSelect    : 0x{keyval:02X} -> {rootselect_str}")
    print(f"[+] BootImageType          : 0x{btype:02X} -> {btype_str}")
    print(f"[+] ImageVersion           : 0x{image_version:08X}")

    # Choose AES key and header size
    arch, header_size, aes_key, aes_iv, keyname = choose_crypto(info_key, info_base)
    print(f"[+] Detected arch: {arch}, header size to strip = 0x{header_size:X}")
    print(f"[+] Using {keyname} key")

    if L <= header_size:
        raise ValueError("File too small (no encrypted payload after header)")

    encrypted_payload = data[header_size:]

    # Decrypt
    decrypted = aes_cbc_decrypt_nopad(aes_key, aes_iv, encrypted_payload)

    # Save raw decrypted blob
    out_raw = os.path.splitext(path)[0] + f".bin"
    with open(out_raw, "wb") as fo:
        fo.write(decrypted)
    print(f"[+] Wrote raw decrypted blob: {out_raw}")

    # Try to find ELF magic
    elf_off = decrypted.find(ELF_MAGIC)
    if elf_off != -1:
        elf_out = os.path.splitext(path)[0] + f".elf"
        with open(elf_out, "wb") as fe:
            fe.write(decrypted[elf_off:])
        print(f"[+] ELF header found at decrypted offset 0x{elf_off:X}")
        print(f"[+] Wrote ELF: {elf_out}")
    else:
        print(f"[i] No ELF header found. Extracted raw {arch} binary.")

    return True

# -------------------------
# CLI entry
# -------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: drag & drop a boot image onto this script, or run:")
        print("  python extract_bootimage.py <boot_image>")
        sys.exit(1)

    path = sys.argv[1].strip('"')
    if not os.path.isfile(path):
        print(f"File not found: {path}")
        sys.exit(2)

    try:
        process_file(path)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(3)

if __name__ == "__main__":
    main()
