# -*- coding: utf-8 -*-
"""
VK Stub Installer
-----------------
Берёт AndroidManifest.xml + resources.arsc из настоящего VK APK,
создаёт заглушку с тем же package name и устанавливает на эмулятор.

Требования:
  - Python 3.x  +  pip install cryptography
  - ADB в PATH  (C:/platform-tools/adb.exe)
  - vk-8-175.apk рядом с этим скриптом (или укажи путь ниже)

Использование:
  python install_vk_stub.py
"""

import os, sys, io, zipfile, hashlib, base64, datetime, subprocess

# ── Настройки ────────────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VK_APK     = os.path.join(SCRIPT_DIR, "vk-8-175.apk")   # путь к оригинальному VK
OUTPUT_APK = os.path.join(SCRIPT_DIR, "vk_stub.apk")
ADB        = r"C:\platform-tools\adb.exe"

# ── Зависимости ──────────────────────────────────────────────────────────────

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.serialization import Encoding
except ImportError:
    print("[!] Устанавливаю cryptography...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.serialization import Encoding

# ── Минимальный DEX ──────────────────────────────────────────────────────────

def build_empty_dex():
    import zlib, struct as st
    HEADER_SIZE = 0x70
    MAP_OFFSET  = HEADER_SIZE
    map_list = (
        st.pack('<I', 2) +
        st.pack('<HHII', 0x0000, 0, 1, 0) +
        st.pack('<HHII', 0x1000, 0, 1, MAP_OFFSET)
    )
    FILE_SIZE = HEADER_SIZE + len(map_list)
    hdr = (
        b'dex\n035\x00' +
        b'\x00' * 4 +
        b'\x00' * 20 +
        st.pack('<I', FILE_SIZE) +
        st.pack('<I', HEADER_SIZE) +
        st.pack('<I', 0x12345678) +
        st.pack('<II', 0, 0) +
        st.pack('<I', MAP_OFFSET) +
        b'\x00' * (HEADER_SIZE - 8 - 4 - 20 - 4 * 7)
    )
    data = hdr + map_list
    sha1  = hashlib.sha1(data[32:]).digest()
    data  = data[:12] + b'\x00' * 4 + sha1 + data[32:]
    adler = zlib.adler32(data[12:]) & 0xFFFFFFFF
    import struct
    data  = data[:8] + struct.pack('<I', adler) + data[12:]
    return data

# ── APK подпись (PKCS#7 вручную) ─────────────────────────────────────────────

def sha256_b64(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode()

def make_manifest_mf(entries):
    lines = ["Manifest-Version: 1.0\r\nCreated-By: 1.0 (VK Stub)\r\n\r\n"]
    for name, digest in entries.items():
        lines.append(f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n\r\n")
    return ''.join(lines).encode()

def make_cert_sf(mf_data, entries):
    lines = [
        "Signature-Version: 1.0\r\n",
        f"SHA-256-Digest-Manifest: {sha256_b64(mf_data)}\r\n",
        "Created-By: 1.0 (VK Stub)\r\n\r\n",
    ]
    for name, digest in entries.items():
        lines.append(f"Name: {name}\r\nSHA-256-Digest: {digest}\r\n\r\n")
    return ''.join(lines).encode()

def gen_key_and_cert():
    key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       "VK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VK LLC"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "RU"),
    ])
    now  = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(subj).issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 25))
        .sign(key, hashes.SHA256()))
    return key, cert

def _tl(tag, data):
    t = bytes([tag]) if isinstance(tag, int) else tag
    n = len(data)
    if n < 128:       l = bytes([n])
    elif n < 256:     l = bytes([0x81, n])
    else:             l = bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
    return t + l + data

def _seq(d):   return _tl(0x30, d)
def _set(d):   return _tl(0x31, d)
def _oct(d):   return _tl(0x04, d)
def _ctx(n,d): return _tl(0xA0 + n, d)
def _null():   return b'\x05\x00'
def _int(n):
    if n == 0: return _tl(0x02, b'\x00')
    b = []
    while n > 0: b.append(n & 0xFF); n >>= 8
    b.reverse()
    if b[0] & 0x80: b.insert(0, 0)
    return _tl(0x02, bytes(b))
def _int_raw(b):
    if b[0] & 0x80: b = b'\x00' + b
    return _tl(0x02, b)
def _oid(s):
    p   = [int(x) for x in s.split('.')]
    enc = [40 * p[0] + p[1]]
    for v in p[2:]:
        if v == 0: enc.append(0)
        else:
            parts = []
            while v > 0: parts.append(v & 0x7F); v >>= 7
            parts.reverse()
            for i, b in enumerate(parts):
                enc.append(b | 0x80 if i < len(parts) - 1 else b)
    return _tl(0x06, bytes(enc))

def build_pkcs7(content, key_obj, cert_obj):
    OID_DATA        = "1.2.840.113549.1.7.1"
    OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
    OID_SHA256      = "2.16.840.1.101.3.4.2.1"
    OID_RSA_SHA256  = "1.2.840.113549.1.1.11"
    OID_CONT_TYPE   = "1.2.840.113549.1.9.3"
    OID_MSG_DIGEST  = "1.2.840.113549.1.9.4"

    cert_der   = cert_obj.public_bytes(Encoding.DER)
    issuer_der = cert_obj.issuer.public_bytes()
    serial_n   = cert_obj.serial_number
    serial_b   = serial_n.to_bytes((serial_n.bit_length() + 7) // 8, 'big')

    content_hash = hashlib.sha256(content).digest()
    sa_items = (
        _seq(_oid(OID_CONT_TYPE) + _set(_oid(OID_DATA))) +
        _seq(_oid(OID_MSG_DIGEST) + _set(_oct(content_hash)))
    )
    sa_for_sign = _set(sa_items)
    sa_in_info  = _ctx(0, sa_items)

    sig = key_obj.sign(sa_for_sign, padding.PKCS1v15(), hashes.SHA256())

    issuer_serial = _seq(issuer_der + _int_raw(serial_b))
    signer_info   = _seq(
        _int(1) + issuer_serial +
        _seq(_oid(OID_SHA256) + _null()) +
        sa_in_info +
        _seq(_oid(OID_RSA_SHA256) + _null()) +
        _oct(sig)
    )
    signed_data = _seq(
        _int(1) +
        _set(_seq(_oid(OID_SHA256) + _null())) +
        _seq(_oid(OID_DATA)) +
        _ctx(0, cert_der) +
        _set(signer_info)
    )
    return _seq(_oid(OID_SIGNED_DATA) + _ctx(0, signed_data))

# ── Сборка APK ────────────────────────────────────────────────────────────────

def build_apk():
    if not os.path.exists(VK_APK):
        print(f"[!] Не найден VK APK: {VK_APK}")
        print("    Положи vk-8-175.apk рядом с этим скриптом.")
        return False

    print("[*] Читаю манифест и ресурсы из оригинального VK...")
    vk_zip         = zipfile.ZipFile(VK_APK)
    manifest_data  = vk_zip.read('AndroidManifest.xml')
    resources_data = vk_zip.read('resources.arsc')

    print("[*] Генерирую RSA ключ и сертификат...")
    key, cert = gen_key_and_cert()

    dex_data = build_empty_dex()
    files = {
        'AndroidManifest.xml': manifest_data,
        'resources.arsc':      resources_data,
        'classes.dex':         dex_data,
    }
    digests   = {name: sha256_b64(data) for name, data in files.items()}
    mf_data   = make_manifest_mf(digests)
    sf_data   = make_cert_sf(mf_data, digests)

    print("[*] Подписываю PKCS#7...")
    pkcs7_der = build_pkcs7(sf_data, key, cert)

    print("[*] Упаковываю APK...")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
        zf.writestr('META-INF/MANIFEST.MF', mf_data)
        zf.writestr('META-INF/CERT.SF',     sf_data)
        zf.writestr('META-INF/CERT.RSA',    pkcs7_der)

    with open(OUTPUT_APK, 'wb') as f:
        f.write(buf.getvalue())

    print(f"[+] Готово: {OUTPUT_APK}  ({os.path.getsize(OUTPUT_APK)/1024/1024:.1f} MB)")
    return True

# ── Установка ────────────────────────────────────────────────────────────────

def adb(*args):
    cmd = [ADB] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return (result.stdout + result.stderr).strip()

def install():
    print("\n[*] Ищу подключённые устройства...")
    out = adb("devices")
    lines = [l for l in out.splitlines() if "\tdevice" in l]
    if not lines:
        print("[!] Нет подключённых устройств. Запусти эмулятор и включи ADB.")
        print("    Или запусти вручную:")
        print(f"    adb install -r \"{OUTPUT_APK}\"")
        return

    for line in lines:
        device = line.split("\t")[0]
        print(f"[*] Устанавливаю на {device}...")

        # удаляем старую версию если есть
        adb("-s", device, "shell", "pm uninstall com.vkontakte.android")

        # заливаем APK
        adb("-s", device, "push", OUTPUT_APK, "/sdcard/vk_stub.apk")
        result = adb("-s", device, "shell", "pm install /sdcard/vk_stub.apk")

        if "Success" in result:
            print(f"[+] Установлено на {device}!")
        else:
            print(f"[-] Ошибка на {device}: {result}")

# ── Точка входа ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 50)
    print("  VK Stub Installer")
    print("=" * 50)

    if build_apk():
        install()

    print("\nГотово. Нажми Enter для выхода.")
    input()
