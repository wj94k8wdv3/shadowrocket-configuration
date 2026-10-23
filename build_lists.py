#!/usr/bin/env python3
"""
Собирает списки правил Shadowrocket из внешних источников и локальных файлов.

Для каждого списка генерируется ОДИН файл:
    {name}.list — все правила в одном файле

Порядок внутри файла:
    DOMAIN → DOMAIN-SUFFIX → DOMAIN-KEYWORD → DOMAIN-WILDCARD → USER-AGENT
    → IP-CIDR → IP-CIDR6 → IP-ASN → DST-PORT → GEOIP → прочее

В поле "sources" можно указывать как URL, так и локальный путь.
Правила проходят очистку комментариев, дедупликацию, объединение сетей,
exclude.
"""
import ipaddress
import json
import os
import re
import sys
import urllib.request
from collections import Counter

ROOT = os.path.dirname(os.path.abspath(__file__))
SOURCES_FILE = os.path.join(ROOT, "sources.json")
DEFAULT_OUTPUT_DIR = "lists"

DOMAIN_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD"}
APP_RULE_TYPES = {"USER-AGENT"}
IP_CIDR_RULE_TYPES = {"IP-CIDR", "IP-CIDR6", "IP6-CIDR"}
PORT_RULE_TYPES = {"DST-PORT"}
GEOIP_RULE_TYPES = {"GEOIP"}
OTHER_RULE_TYPES = {"URL-REGEX"}

IGNORED_RULE_TYPES = {
    "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX",
}

SECTION_ORDER = {
    "DOMAIN": 10, "DOMAIN-SUFFIX": 20, "DOMAIN-KEYWORD": 30, "DOMAIN-WILDCARD": 35,
    "USER-AGENT": 40, "IP-CIDR": 50, "IP-CIDR6": 60, "IP-ASN": 70,
    "DST-PORT": 80, "GEOIP": 90,
}
OTHER_SECTION_ORDER = 999

BULLET_RE = re.compile(r"^[-\*•\s]+")
ASN_RE = re.compile(r"^(?:AS)?(\d+)$", re.IGNORECASE)
PORT_LEADING_NUM_RE = re.compile(r"^(\d+)")
PORT_VALID_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")

V2FLY_PREFIX_RE = re.compile(r"^(full|keyword|regexp|domain):(.+)$", re.IGNORECASE)
V2FLY_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-_.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$")
V2FLY_SKIP_PREFIXES = ("include:", "geosite:", "geoint:", "ext:", "ext-if-tag:")


# ---------------------------------------------------------------------------
# Чтение источников
# ---------------------------------------------------------------------------

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (list-builder)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def read_source(src):
    if src.startswith(("http://", "https://")):
        return fetch(src)
    with open(src, encoding="utf-8", errors="ignore") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Разбор строк
# ---------------------------------------------------------------------------

def parse_ip_network(value):
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        ip = ipaddress.ip_address(value)
        return ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
    except ValueError:
        return None


def strip_inline_comment(line):
    line = line.strip()
    if line.startswith(("!", "#", "//")):
        return ""
    idx = line.find("#")
    if idx != -1:
        line = line[:idx]
    line = BULLET_RE.sub("", line)
    return line.strip()


def parse_rule(line):
    line = strip_inline_comment(line)
    if not line:
        return None

    if "," not in line:
        net = parse_ip_network(line)
        if net is not None:
            return ("IP-CIDR", str(net), [])
        return None

    rtype, rest = line.split(",", 1)
    rtype = rtype.strip().upper()
    if not rtype:
        return None
    rest = rest.strip()

    if rtype in PORT_RULE_TYPES:
        if not rest:
            return None
        return rtype, rest, []

    parts = [p.strip() for p in rest.split(",")]
    value = parts[0] if parts else ""
    options = parts[1:]
    return rtype, value, options


def normalize_asn(value):
    m = ASN_RE.match(value.strip())
    return m.group(1) if m else None


def parse_asn_tokens(line):
    line = strip_inline_comment(line)
    if not line:
        return []
    tokens = [t.strip() for t in re.split(r"[\s,]+", line) if t.strip()]
    if not tokens:
        return []
    
    result = []
    for t in tokens:
        asn = normalize_asn(t)
        if asn is None:
            return []
        result.append(asn)
    return result


def _map_v2fly_prefix(kind, value):
    """Вспомогательная функция для маппинга префиксов v2fly."""
    if not value:
        return None
    if kind == "full":
        return ("DOMAIN", value.lower().rstrip("."))
    if kind == "keyword":
        return ("DOMAIN-KEYWORD", value.lower())
    if kind == "domain":
        return ("DOMAIN-SUFFIX", value.lower().rstrip("."))
    if kind == "regexp":
        return ("URL-REGEX", value)
    return None


def _strip_v2fly_attrs(line):
    """Убирает атрибуты вида ' @ads' из строки без регулярных выражений."""
    for pattern in (" @", "\t@"):
        idx = line.find(pattern)
        if idx != -1:
            return line[:idx].strip()
    return line.strip()


def parse_v2fly_line(line):
    line = strip_inline_comment(line)
    if not line:
        return None
    
    line = _strip_v2fly_attrs(line)
    if not line:
        return None

    low = line.lower()
    if any(low.startswith(prefix) for prefix in V2FLY_SKIP_PREFIXES):
        return None

    m = V2FLY_PREFIX_RE.match(line)
    if m:
        return _map_v2fly_prefix(m.group(1).lower(), m.group(2).strip())

    stripped = line.rstrip(".")
    if stripped and V2FLY_DOMAIN_RE.match(stripped):
        return ("DOMAIN-SUFFIX", stripped.lower())
    return None


def parse_adblock_line(line):
    line = strip_inline_comment(line)
    if not line.startswith("||"):
        return None

    line = line[2:]
    for sep in ("^", "$"):
        if sep in line:
            line = line.split(sep)[0]
            break

    line = line.strip(".")
    if line and V2FLY_DOMAIN_RE.match(line):
        return ("DOMAIN-SUFFIX", line.lower())
    return None


def normalize_domain(value):
    return value.strip().lower().rstrip(".")


def split_port_value(value):
    result = []
    for part in value.split(","):
        part = part.strip()
        if part and PORT_VALID_RE.match(part):
            result.append(part)
    return result


def count_invalid_port_tokens(value):
    invalid = 0
    for part in value.split(","):
        part = part.strip()
        if part and not PORT_VALID_RE.match(part):
            invalid += 1
    return invalid


def port_sort_key(port):
    m = PORT_LEADING_NUM_RE.match(port)
    if m:
        return (0, int(m.group(1)), port)
    return (1, 0, port)


# ---------------------------------------------------------------------------
# Вспомогательные функции для collect
# ---------------------------------------------------------------------------

def parse_any_line(line):
    """Универсальный парсер строки. Пробует все форматы по очереди."""
    parsed = parse_rule(line)
    if parsed:
        rtype, value, _ = parsed
        return [(rtype, value)]

    asn_tokens = parse_asn_tokens(line)
    if asn_tokens:
        return [("IP-ASN", asn) for asn in asn_tokens]

    v2fly = parse_v2fly_line(line)
    if v2fly:
        return [v2fly]

    adblock = parse_adblock_line(line)
    if adblock:
        return [adblock]

    return []


def _add_to_state(rtype, value, state):
    """Раскладывает распознанное правило в нужное множество (set)."""
    if rtype in DOMAIN_RULE_TYPES:
        state["domains"].add((rtype, normalize_domain(value)))
    elif rtype in APP_RULE_TYPES:
        state["domains"].add((rtype, value.strip()))
    elif rtype in IP_CIDR_RULE_TYPES:
        net = parse_ip_network(value)
        if net is not None:
            state["ips_cidr"].add(net)
    elif rtype == "IP-ASN":
        asn = normalize_asn(value)
        if asn is not None:
            state["ips_asn"].add(asn)
    elif rtype in PORT_RULE_TYPES:
        state["dst_ports"].update(split_port_value(value))
    elif rtype in GEOIP_RULE_TYPES:
        state["geoips"].add(value.strip().upper())
    else:
        state["others"].add((rtype, value.strip()))
        state["other_types"][rtype] += 1


def _log_collect_stats(state):
    """Выводит статистику после сбора всех источников."""
    if state["ignored"]:
        print(f"  ⏭  отброшено правил из IGNORED_RULE_TYPES: {state['ignored']}")
    if state["invalid_ports"]:
        print(f"  ⏭  отброшено невалидных токенов DST-PORT (PROXY/DIRECT/REJECT и т.п.): {state['invalid_ports']}")
    if state["others"]:
        breakdown = ", ".join(f"{t}: {n}" for t, n in sorted(state["other_types"].items()))
        print(f"  ℹ  прочих типов: {len(state['others'])} ({breakdown})")
    if state["failed"] and state["successful"]:
        print(f"  ⚠  {state['failed']} источник(ов) не прочитано, сборка неполная")


def _process_line(line, state):
    """Разбирает одну строку и обновляет состояние. Возвращает кол-во правил."""
    src_rules = 0
    for rtype, value in parse_any_line(line):
        if rtype in IGNORED_RULE_TYPES:
            state["ignored"] += 1
            continue
        
        src_rules += 1
        if rtype in PORT_RULE_TYPES:
            state["invalid_ports"] += count_invalid_port_tokens(value)
        _add_to_state(rtype, value, state)
    return src_rules


def _process_source(src, state):
    """Читает один источник и прогоняет все его строки через парсер."""
    print(f"  → Читаю {src}")
    try:
        text = read_source(src)
        state["successful"] += 1
    except Exception as e:
        print(f"  ! Ошибка чтения {src}: {e}", file=sys.stderr)
        state["failed"] += 1
        return

    src_rules = 0
    for line in text.splitlines():
        src_rules += _process_line(line, state)

    if src_rules == 0 and text.strip():
        print("     ⚠ 0 правил из источника (возможно, формат не распознан)")


def collect(cfg):
    state = {
        "domains": set(), "ips_cidr": set(), "ips_asn": set(),
        "dst_ports": set(), "geoips": set(), "others": set(),
        "other_types": Counter(), "ignored": 0, "invalid_ports": 0,
        "successful": 0, "failed": 0,
    }

    for src in cfg["sources"]:
        _process_source(src, state)

    _log_collect_stats(state)
    
    return (
        state["domains"], state["ips_cidr"], state["ips_asn"],
        state["dst_ports"], state["geoips"], state["others"],
        state["successful"] > 0
    )


# ---------------------------------------------------------------------------
# Формирование строк и запись
# ---------------------------------------------------------------------------

def _safe_subnet_or_overlap(net, ex):
    try:
        return net.subnet_of(ex) or net.overlaps(ex)
    except TypeError:
        return False


def build_lines(domains, ips_cidr, ips_asn, dst_ports, geoips, others, excluded):
    by_type = {}

    for rtype, value in domains:
        by_type.setdefault(rtype, []).append(value)

    ipv4 = [n for n in ips_cidr if n.version == 4]
    ipv6 = [n for n in ips_cidr if n.version == 6]
    merged_v4 = list(ipaddress.collapse_addresses(ipv4)) if ipv4 else []
    merged_v6 = list(ipaddress.collapse_addresses(ipv6)) if ipv6 else []

    merged_v4 = [n for n in merged_v4 if not any(_safe_subnet_or_overlap(n, ex) for ex in excluded)]
    merged_v6 = [n for n in merged_v6 if not any(_safe_subnet_or_overlap(n, ex) for ex in excluded)]
    
    merged_v4.sort(key=lambda n: int(n.network_address))
    merged_v6.sort(key=lambda n: int(n.network_address))

    if merged_v4:
        by_type["IP-CIDR"] = [str(n) for n in merged_v4]
    if merged_v6:
        by_type["IP-CIDR6"] = [str(n) for n in merged_v6]
    if ips_asn:
        by_type["IP-ASN"] = [str(x) for x in sorted(ips_asn, key=lambda x: int(x))]
    if dst_ports:
        by_type["DST-PORT"] = sorted(dst_ports, key=port_sort_key)
    if geoips:
        by_type["GEOIP"] = sorted(geoips)

    for rtype, value in others:
        by_type.setdefault(rtype, []).append(value)

    lines = []
    ordered_types = sorted(
        by_type.keys(),
        key=lambda t: (SECTION_ORDER.get(t, OTHER_SECTION_ORDER), t),
    )
    for rtype in ordered_types:
        values = by_type[rtype]
        if rtype not in ("IP-CIDR", "IP-CIDR6", "IP-ASN", "DST-PORT"):
            values = sorted(values)
        for v in values:
            lines.append(f"{rtype},{v}")
    return lines


def write_list_file(path, lines):
    if not lines:
        if os.path.exists(path):
            os.remove(path)
            print(f"  🗑  {os.path.basename(path)} — 0 записей, файл удалён")
        else:
            print(f"  ⏭  {os.path.basename(path)} — 0 записей, файл не создаётся")
        return
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    print(f"  ✓ {os.path.basename(path)} ({len(lines)} правил)")


def build_list(cfg, out_dir):
    excluded = []
    for ex in cfg.get("exclude", []):
        try:
            excluded.append(ipaddress.ip_network(ex, strict=False))
        except ValueError:
            print(f"  ! Некорректный exclude: {ex}", file=sys.stderr)

    domains, ips_cidr, ips_asn, dst_ports, geoips, others, ok = collect(cfg)
    if not ok:
        print("  ⚠  ни один источник не прочитан, существующий файл сохранён")
        return False

    lines = build_lines(domains, ips_cidr, ips_asn, dst_ports, geoips, others, excluded)
    
    print(
        f"  Собрано: {len(domains)} доменов, {len(ips_cidr)} CIDR, "
        f"{len(ips_asn)} ASN, {len(dst_ports)} DST-PORT, "
        f"{len(geoips)} GEOIP, {len(others)} прочих → {len(lines)} строк"
    )

    write_list_file(os.path.join(out_dir, cfg["name"] + ".list"), lines)
    return True


# ---------------------------------------------------------------------------
# Очистка папки со списками
# ---------------------------------------------------------------------------

def _check_and_remove_item(out_dir, fname, expected):
    """Проверяет один файл/папку и удаляет, если нужно."""
    path = os.path.join(out_dir, fname)

    if os.path.isdir(path):
        try:
            os.rmdir(path)
            return "orphan", fname + "/"
        except OSError:
            print(f"  ! {fname}/ — непустая папка, пропущена", file=sys.stderr)
            return None, None

    if not os.path.isfile(path):
        return None, None

    if fname not in expected:
        os.remove(path)
        return "orphan", fname

    if os.path.getsize(path) == 0:
        os.remove(path)
        return "empty", fname

    return None, None


def cleanup_output_dir(out_dir, expected):
    removed_orphan = []
    removed_empty = []

    for fname in sorted(os.listdir(out_dir)):
        status, name = _check_and_remove_item(out_dir, fname, expected)
        
        if status == "orphan":
            removed_orphan.append(name)
        elif status == "empty":
            removed_empty.append(name)

    for fname in removed_orphan:
        print(f"  🗑  {fname} — не входит в текущие списки, удалён")
    
    for fname in removed_empty:
        print(f"  🗑  {fname} — пустой, удалён")

    if not removed_orphan and not removed_empty:
        print("  ✓ лишних файлов нет")


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def main():
    with open(SOURCES_FILE, encoding="utf-8") as f:
        config = json.load(f)

    out_dir = os.path.join(ROOT, config.get("output_dir", DEFAULT_OUTPUT_DIR))
    os.makedirs(out_dir, exist_ok=True)

    expected = set()
    failed_lists = []

    for cfg in config["lists"]:
        print(f"[{cfg['name']}]")
        ok = build_list(cfg, out_dir)
        expected.add(cfg["name"] + ".list")
        if not ok:
            failed_lists.append(cfg["name"])
        print()

    print("[cleanup]")
    cleanup_output_dir(out_dir, expected)

    if failed_lists:
        print()
        print(f"⚠  списки с ошибками сборки (файлы сохранены): {', '.join(failed_lists)}")


if __name__ == "__main__":
    main()