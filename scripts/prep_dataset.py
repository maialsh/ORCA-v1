"""Prepare the full experiment dataset.

Extracts ALL real malware (L-MB Linux, Msx-MB Windows) from the AES-encrypted
zips (password 'infected'), plus benign Linux/Windows, hash-renames every binary
to a neutral label-free name, chmod a-x (static only, never executed), and writes
a truth manifest. Re-runnable; skips files already staged.
"""
import csv, hashlib, os, shutil, subprocess, tempfile
from pathlib import Path

COLLECTION = Path("/Users/maitha/Desktop/Manuscript2_ORCA/Collection")
OUT = Path("/Users/maitha/Desktop/Manuscript2_ORCA/ORCA/dry_runs/full_run/staging")
OUT.mkdir(parents=True, exist_ok=True)
MANIFEST = OUT.parent / "manifest_full.csv"
PASSWORD = "infected"


def sha16(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()[:16]


def stage(src, ext, truth, platform, family, rows):
    """Hash-rename src into OUT as a neutral name, chmod a-x, record a manifest row."""
    h = sha16(src)
    neutral = f"{h}{ext}"
    dst = OUT / neutral
    if not dst.exists():
        shutil.copy2(src, dst)
        os.chmod(dst, 0o644)  # non-executable
    rows.append({"neutral_name": neutral, "truth": truth, "platform": platform, "family": family})


def extract_zip_dir(zdir, ext, truth, platform, rows):
    """Each *.zip is one AES-encrypted malware sample; extract and stage it."""
    for zp in sorted(Path(zdir).glob("*.zip")):
        with tempfile.TemporaryDirectory() as td:
            r = subprocess.run(["7z", "x", f"-p{PASSWORD}", f"-o{td}", str(zp)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(f"  FAILED extract {zp.name}: {r.stderr.strip()[:80]}")
                continue
            files = [p for p in Path(td).rglob("*") if p.is_file()]
            if not files:
                print(f"  EMPTY {zp.name}")
                continue
            binf = max(files, key=lambda p: p.stat().st_size)  # the sample is the largest file
            stage(binf, ext, truth, platform, zdir.name, rows)


def stage_plain_dir(d, ext, truth, platform, rows):
    """Benign dirs already hold extracted binaries; stage each file."""
    for p in sorted(Path(d).rglob("*")):
        if p.is_file() and not p.name.startswith(".") and p.suffix.lower() not in (".zip", ".txt", ".md"):
            stage(p, ext, truth, platform, Path(d).name, rows)


def main():
    rows = []
    # Linux malware
    for fam in sorted((COLLECTION / "L-MB").iterdir()):
        if fam.is_dir():
            print(f"L-MB/{fam.name} ...", flush=True)
            extract_zip_dir(fam, ".elf", "malicious", "linux", rows)
    # Windows malware
    for fam in sorted((COLLECTION / "Msx-MB").iterdir()):
        if fam.is_dir():
            print(f"Msx-MB/{fam.name} ...", flush=True)
            extract_zip_dir(fam, ".exe", "malicious", "windows", rows)
    # Benign Linux
    print("benign-Linux ...", flush=True)
    stage_plain_dir(COLLECTION / "benign-Linux", ".bin", "benign", "linux", rows)
    # Benign Windows (sysinternals + portable-tools, already-extracted exes)
    print("benign-Windows ...", flush=True)
    for sub in ("sysinternals", "portable-tools"):
        d = COLLECTION / "benign-Windows" / sub
        if d.exists():
            stage_plain_dir(d, ".exe", "benign", "windows", rows)

    with open(MANIFEST, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["neutral_name", "truth", "platform", "family"])
        w.writeheader(); w.writerows(rows)

    mal = sum(1 for r in rows if r["truth"] == "malicious")
    ben = sum(1 for r in rows if r["truth"] == "benign")
    print(f"\nstaged {len(rows)} binaries: {mal} malicious, {ben} benign -> {OUT}")
    print(f"manifest -> {MANIFEST}")


if __name__ == "__main__":
    main()
