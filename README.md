This is a Python script to extract the binary from an encrypted full Wii U boot image.

# Usage

You must fill in whichever Wii U AES decryption keys you need in the script manually in an editor of your choice (Notepad is fine).

Then, simply drag and drop a boot image file onto the script (such as fw.img or kernel.img). It will output a raw decrypted bin file with the boot image header stripped.
A .elf file will be produced if ELF magic (`\x7fELF`) is found in the decrypted binary.

## Use of binaries in Reverse Engineering

Espresso images should be loaded into a program like Ghidra as the Espresso arch (through an extension such as GhidraRPXLoader).
ARM images should be loaded as ARM:BE:32:v5t (same as the Wii's IOP).

PowerPC kernel binaries decompile weirdly in Ghidra. To fix a lot of references, some registers must be globally set to assume certain values.
- r2: `0xffec14e0`
- r13: `0xffed1780`

There is a shared Ghidra project for the decompilation of Wii U binaries available via decomp.dev

# Requirements

- pycryptodome

```bash
pip install pycryptodome
```
