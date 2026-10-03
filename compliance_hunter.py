#!/usr/bin/env python3
"""
Compliance Hunter - Trellix ePO günlük Sağlık ve Uyumluluk Kontrolü
-------------------------------------------------------------------
1) .env dosyasından kimlik bilgilerini okur
2) core.executeQuery ile: DAT'ı 7 günden eski VEYA 7 gündür ePO ile haberleşmeyen cihazları bulur
3) system.applyTag ile bu cihazlara 'Outdated_DAT' etiketini atar
4) Sonucu JSON olarak Webhook'a gönderir

Gereksinimler:  pip install mcafee-epo requests python-dotenv
Çalıştırma:     python compliance_hunter.py            (normal)
                python compliance_hunter.py --dry-run  (etiket atmaz, webhook göndermez, sadece raporlar)
"""

import argparse
import logging
import os
import sys
from datetime import datetime, timezone

import requests
from dotenv import find_dotenv, load_dotenv

try:
    import mcafee_epo
except ImportError:
    sys.exit("mcafee-epo kütüphanesi bulunamadı: pip install mcafee-epo")

# .env aşağıdaki sabitlerden ÖNCE yüklenmeli; yoksa STALE_DAYS/TAG_NAME/DAT_* .env'den okunmaz.
# Önce çalışılan dizindeki .env, yoksa betiğin yanındaki .env aranır.
load_dotenv(find_dotenv(usecwd=True)) or load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# ---------------------------------------------------------------------------
# Sabitler / ePO tablo-kolon isimleri
# ---------------------------------------------------------------------------
STALE_DAYS = int(os.getenv("STALE_DAYS", "7"))
STALE_MS = STALE_DAYS * 24 * 60 * 60 * 1000  # ePO 'olderThan' operatörü milisaniye ister
TAG_NAME = os.getenv("TAG_NAME", "Outdated_DAT")
TAG_BATCH_SIZE = 50  # URL'i şişirmemek için toplu etiketleme

# Ana tablo: her yönetilen cihaz için bir satır
TARGET_TABLE = "EPOLeafNode"
COL_HOSTNAME = "EPOLeafNode.NodeName"
COL_LAST_COMM = "EPOLeafNode.LastUpdate"  # DİKKAT: bu DAT değil, son agent-server iletişimi (ASCI)
COL_IP = "EPOComputerProperties.IPAddress"

# DAT tarihi ürüne göre farklı tabloda tutulur. Varsayılan: VirusScan Enterprise (VSE).
# ENS kullanıyorsanız kendi ePO'nuzda `core.listTables` ile doğrulayıp .env'den değiştirin.
DAT_TABLE = os.getenv("DAT_TABLE", "EPOProdPropsView_VIRUSCAN")
COL_DAT_DATE = f"{DAT_TABLE}.{os.getenv('DAT_DATE_COLUMN', 'datdate')}"

log = logging.getLogger("compliance_hunter")


# ---------------------------------------------------------------------------
# 1) Konfigürasyon
# ---------------------------------------------------------------------------
def load_config() -> dict:
    required = ["EPO_URL", "EPO_USERNAME", "EPO_PASSWORD", "WEBHOOK_URL"]
    cfg = {k: os.getenv(k) for k in required}
    missing = [k for k, v in cfg.items() if not v]
    if missing:
        raise ValueError(f".env içinde eksik değişken(ler): {', '.join(missing)}")

    # SSL doğrulama: 'true' / 'false' / CA bundle dosya yolu
    verify = os.getenv("EPO_VERIFY_SSL", "true")
    if verify.lower() in ("true", "false"):
        cfg["EPO_VERIFY_SSL"] = verify.lower() == "true"
    else:
        cfg["EPO_VERIFY_SSL"] = verify
    return cfg


def connect_epo(cfg: dict):
    session = requests.Session()
    session.verify = cfg["EPO_VERIFY_SSL"]
    client = mcafee_epo.Client(cfg["EPO_URL"], cfg["EPO_USERNAME"], cfg["EPO_PASSWORD"], session=session)
    # Bağlantı/yetki testi: hafif bir komut
    client("core.help", "core.executeQuery")
    log.info("ePO bağlantısı başarılı: %s", cfg["EPO_URL"])
    return client


# ---------------------------------------------------------------------------
# 2) Uyumsuz cihazları sorgula
# ---------------------------------------------------------------------------
def find_noncompliant(client) -> list[dict]:
    select = f"(select {COL_HOSTNAME} {COL_IP} {COL_LAST_COMM} {COL_DAT_DATE})"
    # S-expression: (DAT 7 günden eski) VEYA (son haberleşme 7 günden eski)
    where = f"(where (or (olderThan {COL_DAT_DATE} {STALE_MS}) (olderThan {COL_LAST_COMM} {STALE_MS})))"
    log.debug("SELECT: %s", select)
    log.debug("WHERE : %s", where)

    rows = client(
        "core.executeQuery",
        target=TARGET_TABLE,
        select=select,
        where=where,
        joinTables=f"EPOComputerProperties,{DAT_TABLE}",
        order=f"(order (asc {COL_LAST_COMM}))",
    )

    devices = []
    for r in rows or []:
        devices.append(
            {
                "hostname": r.get(COL_HOSTNAME),
                "ip": r.get(COL_IP),
                "last_communication": r.get(COL_LAST_COMM),
                "dat_date": r.get(COL_DAT_DATE),
            }
        )
    log.info("Uyumsuz cihaz sayısı: %d", len(devices))
    return devices


# ---------------------------------------------------------------------------
# 3) Etiketle
# ---------------------------------------------------------------------------
def tag_exists(client, tag_name: str) -> bool:
    tags = client("system.findTag", searchText=tag_name) or []
    return any(t.get("tagName") == tag_name for t in tags)


def apply_tag(client, hostnames: list[str], tag_name: str) -> tuple[int, list[str]]:
    """Etiketi toplu (batch) halde uygular. (başarılı_sayısı, hata_listesi) döner."""
    ok, errors = 0, []
    for i in range(0, len(hostnames), TAG_BATCH_SIZE):
        batch = hostnames[i : i + TAG_BATCH_SIZE]
        try:
            result = client("system.applyTag", names=",".join(batch), tagName=tag_name)
            ok += int(result) if str(result).isdigit() else len(batch)
            log.info("Etiket uygulandı (batch %d): %s cihaz", i // TAG_BATCH_SIZE + 1, result)
        except mcafee_epo.APIError as e:
            log.error("applyTag batch hatası: %s", e)
            errors.append(f"batch {i // TAG_BATCH_SIZE + 1}: {e}")
    return ok, errors


# ---------------------------------------------------------------------------
# 4) Webhook bildirimi
# ---------------------------------------------------------------------------
def send_webhook(url: str, devices: list[dict], tagged: int, errors: list[str]) -> None:
    summary = (
        f"⚠️ Dikkat: {len(devices)} cihaz {STALE_DAYS} gündür DAT güncellemesi almıyor "
        f"veya ePO ile haberleşmiyor. {tagged} cihaza '{TAG_NAME}' etiketi atandı."
    )
    preview = "\n".join(
        f"- {d['hostname']} | {d['ip']} | Son iletişim: {d['last_communication']} | DAT: {d['dat_date']}"
        for d in devices[:25]
    )
    if len(devices) > 25:
        preview += f"\n... ve {len(devices) - 25} cihaz daha"

    payload = {
        "text": f"{summary}\n\n{preview}",  # Slack / Teams / Mattermost uyumlu alan
        "source": "Trellix ePO Compliance Hunter",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stale_days": STALE_DAYS,
        "tag": TAG_NAME,
        "count": len(devices),
        "tagged": tagged,
        "errors": errors,
        "devices": devices,  # tam liste (SIEM/SOAR için)
    }
    resp = requests.post(url, json=payload, timeout=15)
    resp.raise_for_status()
    log.info("Webhook gönderildi (HTTP %s)", resp.status_code)


# ---------------------------------------------------------------------------
# Ana akış
# ---------------------------------------------------------------------------
def main() -> int:
    parser = argparse.ArgumentParser(description="Trellix ePO Compliance Hunter")
    parser.add_argument("--dry-run", action="store_true", help="Etiket atma ve webhook gönderme")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    try:
        cfg = load_config()
    except ValueError as e:
        log.critical(e)
        return 2

    try:
        client = connect_epo(cfg)
    except requests.exceptions.SSLError as e:
        log.critical("SSL hatası (EPO_VERIFY_SSL ayarını/CA dosyasını kontrol edin): %s", e)
        return 3
    except requests.exceptions.RequestException as e:
        log.critical("ePO sunucusuna ulaşılamadı: %s", e)
        return 3
    except mcafee_epo.APIError as e:
        log.critical("ePO API hatası (kimlik bilgisi/yetki?): %s", e)
        return 3

    try:
        devices = find_noncompliant(client)
    except mcafee_epo.APIError as e:
        log.critical("Sorgu hatası - tablo/kolon adlarını core.listTables ile doğrulayın: %s", e)
        return 4

    if not devices:
        log.info("Tüm cihazlar uyumlu. Yapılacak işlem yok.")
        return 0

    for d in devices:
        log.info("  %-25s %-16s son iletişim=%s dat=%s", d["hostname"], d["ip"], d["last_communication"], d["dat_date"])

    if args.dry_run:
        log.warning("DRY-RUN: etiketleme ve webhook atlandı.")
        return 0

    tagged, errors = 0, []
    try:
        if not tag_exists(client, TAG_NAME):
            raise RuntimeError(f"'{TAG_NAME}' etiketi ePO'da yok. Önce Tag Catalog'dan oluşturun.")
        hostnames = [d["hostname"] for d in devices if d["hostname"]]
        tagged, errors = apply_tag(client, hostnames, TAG_NAME)
    except (mcafee_epo.APIError, RuntimeError) as e:
        log.error("Etiketleme başarısız: %s", e)
        errors.append(str(e))

    try:
        send_webhook(cfg["WEBHOOK_URL"], devices, tagged, errors)
    except requests.exceptions.RequestException as e:
        log.error("Webhook gönderilemedi: %s", e)
        return 5

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
