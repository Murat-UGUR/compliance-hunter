#!/usr/bin/env python3
"""
Compliance Hunter - Trellix ePO günlük Sağlık ve Uyumluluk Kontrolü
-------------------------------------------------------------------
1) .env dosyasından kimlik bilgilerini okur
2) core.executeQuery ile: DAT'ı 7 günden eski VEYA 7 gündür ePO ile haberleşmeyen cihazları bulur
3) system.applyTag ile YENİ uyumsuz cihazlara 'Outdated_DAT' etiketini atar
4) system.clearTag ile artık uyumlu olan (düzelen) cihazlardan etiketi kaldırır
5) Sonucu (yeni / devam eden / düzelen) JSON olarak Webhook'a gönderir

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


def _env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


# Düzelen cihazlardan etiketi kaldır: etiket her zaman "şu an uyumsuz" anlamına gelsin.
# Etiket bu araca ayrılmış olmalı; elle aynı etiketi atanmış cihazlardan da kaldırılır.
CLEAR_RECOVERED = _env_bool("CLEAR_RECOVERED", True)
# DAT tarihi boş olan (AV ürünü olmayan / raporlamayan) cihazları da uyumsuz say. Varsayılan kapalı.
FLAG_MISSING_DAT = _env_bool("FLAG_MISSING_DAT", False)

# Ana tablo: her yönetilen cihaz için bir satır
TARGET_TABLE = "EPOLeafNode"
COL_HOSTNAME = "EPOLeafNode.NodeName"
COL_LAST_COMM = "EPOLeafNode.LastUpdate"  # DİKKAT: bu DAT değil, son agent-server iletişimi (ASCI)
COL_IP = "EPOComputerProperties.IPAddress"
COL_TAGS = "EPOLeafNode.AppliedTags"  # hasTag operatörü etiket ID'si ile çalışır

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
    # S-expression: (DAT 7 günden eski) VEYA (son haberleşme 7 günden eski) [VEYA (DAT boş)]
    conditions = f"(olderThan {COL_DAT_DATE} {STALE_MS}) (olderThan {COL_LAST_COMM} {STALE_MS})"
    if FLAG_MISSING_DAT:
        conditions += f" (isBlank {COL_DAT_DATE})"
    where = f"(where (or {conditions}))"
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
def find_tag_id(client, tag_name: str):
    """Etiketin ePO ID'sini döner; etiket yoksa None."""
    tags = client("system.findTag", searchText=tag_name) or []
    for t in tags:
        if t.get("tagName") == tag_name:
            return t.get("tagId")
    return None


def tag_exists(client, tag_name: str) -> bool:
    return find_tag_id(client, tag_name) is not None


def find_tagged(client, tag_id) -> set[str]:
    """Şu anda etiketi taşıyan cihazların adları."""
    rows = client(
        "core.executeQuery",
        target=TARGET_TABLE,
        select=f"(select {COL_HOSTNAME})",
        where=f'(where (hasTag {COL_TAGS} "{tag_id}"))',
    )
    return {r.get(COL_HOSTNAME) for r in rows or [] if r.get(COL_HOSTNAME)}


def _tag_batches(client, command: str, hostnames: list[str], tag_name: str) -> tuple[int, list[str]]:
    """system.applyTag / system.clearTag komutunu 50'lik gruplar halinde çalıştırır.
    (başarılı_sayısı, hata_listesi) döner; bir grubun hatası diğerlerini durdurmaz."""
    ok, errors = 0, []
    verb = "applyTag" if command.endswith("applyTag") else "clearTag"
    for i in range(0, len(hostnames), TAG_BATCH_SIZE):
        batch = hostnames[i : i + TAG_BATCH_SIZE]
        try:
            result = client(command, names=",".join(batch), tagName=tag_name)
            ok += int(result) if str(result).isdigit() else len(batch)
            log.info("%s (batch %d): %s cihaz", verb, i // TAG_BATCH_SIZE + 1, result)
        except mcafee_epo.APIError as e:
            log.error("%s batch hatası: %s", verb, e)
            errors.append(f"{verb} batch {i // TAG_BATCH_SIZE + 1}: {e}")
    return ok, errors


def apply_tag(client, hostnames: list[str], tag_name: str) -> tuple[int, list[str]]:
    return _tag_batches(client, "system.applyTag", hostnames, tag_name)


def clear_tag(client, hostnames: list[str], tag_name: str) -> tuple[int, list[str]]:
    return _tag_batches(client, "system.clearTag", hostnames, tag_name)


# ---------------------------------------------------------------------------
# 4) Webhook bildirimi
# ---------------------------------------------------------------------------
def send_webhook(
    url: str,
    devices: list[dict],
    tagged: int,
    errors: list[str],
    recovered: list[str] | None = None,
    cleared: int = 0,
) -> None:
    recovered = recovered or []
    new = [d for d in devices if d.get("status") == "new"]
    still = [d for d in devices if d.get("status") == "still"]
    lines = []
    if devices:
        summary = (
            f"⚠️ Dikkat: {len(devices)} cihaz {STALE_DAYS} gündür DAT güncellemesi almıyor "
            f"veya ePO ile haberleşmiyor. {tagged} cihazda '{TAG_NAME}' etiketi var."
        )
        if new or still:
            summary += f" ({len(new)} yeni, {len(still)} önceki çalıştırmadan beri devam ediyor)"
        # Yeni cihazlar önce: her gün aynı listeyi okumak zorunda kalınmasın
        ordered = new + still + [d for d in devices if d.get("status") not in ("new", "still")]
        lines = [
            f"- {'🆕 ' if d.get('status') == 'new' else ''}{d['hostname']} | {d['ip']} | "
            f"Son iletişim: {d['last_communication']} | DAT: {d['dat_date']}"
            for d in ordered[:25]
        ]
        if len(devices) > 25:
            lines.append(f"... ve {len(devices) - 25} cihaz daha")
    else:
        summary = "✅ Tüm cihazlar uyumlu."
    if recovered:
        summary += f"\n✅ {len(recovered)} cihaz düzeldi; {cleared} cihazdan '{TAG_NAME}' etiketi kaldırıldı."
        preview_rec = ", ".join(recovered[:25]) + (f" ... (+{len(recovered) - 25})" if len(recovered) > 25 else "")
        lines.append(f"Düzelen: {preview_rec}")
    if errors:
        summary += f"\n❗ {len(errors)} hata oluştu, ayrıntı 'errors' alanında."

    payload = {
        "text": f"{summary}\n\n" + "\n".join(lines) if lines else summary,  # Slack / Teams / Mattermost
        "source": "Trellix ePO Compliance Hunter",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stale_days": STALE_DAYS,
        "tag": TAG_NAME,
        "count": len(devices),
        "tagged": tagged,
        "new_count": len(new),
        "still_count": len(still),
        "recovered_count": len(recovered),
        "cleared": cleared,
        "recovered": recovered,
        "errors": errors,
        "devices": devices,  # tam liste (SIEM/SOAR için), her kayıtta "status": new | still
    }
    resp = requests.post(url, json=payload, timeout=15)
    resp.raise_for_status()
    log.info("Webhook gönderildi (HTTP %s)", resp.status_code)


# ---------------------------------------------------------------------------
# Ana akış
# ---------------------------------------------------------------------------
def _safe_console() -> None:
    """Windows konsolu/Task Scheduler kod sayfası bir karakteri gösteremezse çökme olmasın."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Trellix ePO Compliance Hunter")
    parser.add_argument("--dry-run", action="store_true", help="Etiket atma/kaldırma ve webhook gönderme")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    _safe_console()
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

    errors: list[str] = []

    # Etiketin ID'si ve şu an etiketi taşıyan cihazlar (yeni / devam eden / düzelen ayrımı için)
    tag_id, tagged_before = None, None
    try:
        tag_id = find_tag_id(client, TAG_NAME)
    except mcafee_epo.APIError as e:
        log.error("Etiket aranamadı: %s", e)
        errors.append(f"findTag: {e}")
    if tag_id is not None:
        try:
            tagged_before = find_tagged(client, tag_id)
            log.info("Şu anda '%s' etiketli cihaz: %d", TAG_NAME, len(tagged_before))
        except mcafee_epo.APIError as e:
            # Bilinmeyen durumda hiçbir etiketi kaldırma: yanlışlıkla temizlik yapmaktansa atla
            log.error("Etiketli cihazlar sorgulanamadı, etiket kaldırma atlanıyor: %s", e)
            errors.append(f"hasTag query: {e}")

    current = {d["hostname"] for d in devices if d["hostname"]}
    if tagged_before is not None:
        for d in devices:
            d["status"] = "still" if d["hostname"] in tagged_before else "new"
        recovered = sorted(tagged_before - current) if CLEAR_RECOVERED else []
    else:
        recovered = []

    if not devices and not recovered:
        log.info("Tüm cihazlar uyumlu. Yapılacak işlem yok.")
        return 1 if errors else 0

    for d in devices:
        log.info(
            "  %-5s %-25s %-16s son iletişim=%s dat=%s",
            d.get("status", "-"),
            d["hostname"],
            d["ip"],
            d["last_communication"],
            d["dat_date"],
        )
    if recovered:
        log.info("Düzelen (etiketi kaldırılacak) cihaz: %d -> %s", len(recovered), ", ".join(recovered[:25]))

    if args.dry_run:
        if tag_id is None:
            log.warning("'%s' etiketi ePO'da yok; gerçek çalıştırmadan önce Tag Catalog'dan oluşturun.", TAG_NAME)
        log.warning("DRY-RUN: etiketleme, etiket kaldırma ve webhook atlandı.")
        return 0

    tagged, cleared = 0, 0
    try:
        if tag_id is None:
            raise RuntimeError(f"'{TAG_NAME}' etiketi ePO'da yok. Önce Tag Catalog'dan oluşturun.")
        # Zaten etiketli olanlara tekrar uygulamaya gerek yok
        to_apply = sorted(current - tagged_before) if tagged_before is not None else sorted(current)
        applied, apply_errors = apply_tag(client, to_apply, TAG_NAME)
        errors += apply_errors
        tagged = applied + (len(current & tagged_before) if tagged_before is not None else 0)
        if recovered:
            cleared, clear_errors = clear_tag(client, recovered, TAG_NAME)
            errors += clear_errors
    except (mcafee_epo.APIError, RuntimeError) as e:
        log.error("Etiketleme başarısız: %s", e)
        errors.append(str(e))

    try:
        send_webhook(cfg["WEBHOOK_URL"], devices, tagged, errors, recovered, cleared)
    except requests.exceptions.RequestException as e:
        log.error("Webhook gönderilemedi: %s", e)
        return 5

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
