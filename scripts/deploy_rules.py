#!/usr/bin/env python3
"""
QRadar Rule Deploy Script — JSON to AQL + Reference Set
GitHub Actions CI/CD Pipeline

Hər rules/*.json üçün:
  1. AQL-i QRadar Ariel API-sinə göndərir, search icra edir (COMPLETED gözləyir).
  2. Tapılan event-lərdən indikatoru (sourceip) çıxarır.
  3. Həmin indikatorları **API ilə** rule-un Reference Set-inə yazır
     (POST /api/reference_data/sets/{name}). Set yoxdursa, API ilə yaradır.

QRadar-dakı tək "umbrella" rule bu set-lərə baxır və yeni indikator
gələn kimi OFFENSE yaradır. Beləcə detection tam API ilə deploy olunur,
offense-i QRadar mühərriki çıxarır.

Env (GitHub Secrets):
  QRADAR_HOST        məs: https://10.0.0.10
  QRADAR_SEC_TOKEN  (və ya QRADAR_TOKEN)
"""

import os
import re
import json
import glob
import sys
import time
import urllib3
import requests
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

QRADAR_HOST  = os.environ.get('QRADAR_HOST', '').rstrip('/')
QRADAR_TOKEN = os.environ.get('QRADAR_SEC_TOKEN') or os.environ.get('QRADAR_TOKEN', '')

if not QRADAR_HOST or not QRADAR_TOKEN:
    print("XETA: QRADAR_HOST ve ya QRADAR_SEC_TOKEN tapilmadi!")
    sys.exit(1)

HEADERS = {'SEC': QRADAR_TOKEN, 'Accept': 'application/json', 'Version': '17.0'}


# ── AQL hazirla ───────────────────────────────────────────────────
def build_aql(aql):
    aql = re.sub(r'\bORDER\s+BY\s+[^()]+?\b(ASC|DESC)?\b(?=\s+LAST\b|\s*$)', ' ', aql, flags=re.I)
    aql = re.sub(r'\bLAST\s+\d+\s+(SECONDS|MINUTES|HOURS|DAYS)\b', '', aql, flags=re.I)
    aql = re.sub(r'\s+', ' ', aql).strip().rstrip(';').strip()
    now = datetime.utcnow(); start = now - timedelta(hours=1)
    return f"{aql} START '{start:%Y-%m-%d %H:%M}' STOP '{now:%Y-%m-%d %H:%M}'"


# ── AQL search ────────────────────────────────────────────────────
def run_aql_search(aql_template):
    aql = build_aql(aql_template)
    print("   AQL gonderilir...")
    print(f"   {aql[:140]}...")
    ph = dict(HEADERS); ph['Content-Type'] = 'application/x-www-form-urlencoded'
    r = requests.post(f'{QRADAR_HOST}/api/ariel/searches', headers=ph,
                      data=f'query_expression={requests.utils.quote(aql)}', verify=False)
    if r.status_code not in (200, 201):
        print(f"   XETA: HTTP {r.status_code} — {r.text[:200]}"); return None
    sid = r.json().get('search_id'); print(f"   Search ID: {sid}")
    for i in range(20):
        time.sleep(3)
        st = requests.get(f'{QRADAR_HOST}/api/ariel/searches/{sid}', headers=HEADERS, verify=False).json().get('status')
        print(f"   Status [{i+1}]: {st}")
        if st == 'COMPLETED': break
        if st == 'ERROR': print("   XETA: AQL icra xetasi"); return None
    rr = requests.get(f'{QRADAR_HOST}/api/ariel/searches/{sid}/results', headers=HEADERS, verify=False)
    if rr.status_code == 200:
        ev = rr.json().get('events', []); print(f"   {len(ev)} event tapildi"); return ev
    print(f"   XETA: Neticeler alinmadi HTTP {rr.status_code}"); return None


# ── Reference Set əməliyyatları (API) ─────────────────────────────
def ensure_set(name, etype):
    """Set yoxdursa yarat; tipi yanlisdirsa sil ve duzgun tiple yenat (API)."""
    g = requests.get(f'{QRADAR_HOST}/api/reference_data/sets/{name}', headers=HEADERS, verify=False)
    if g.status_code == 200:
        existing = g.json().get('element_type')
        if existing == etype:
            return True
        # tip uygunsuzlugu -> sil ve yenat
        print(f"   Set tipi yanlis ({existing} != {etype}), yeniden yaradilir: {name}")
        requests.delete(f'{QRADAR_HOST}/api/reference_data/sets/{name}?purge_only=false',
                        headers=HEADERS, verify=False)
    c = requests.post(f'{QRADAR_HOST}/api/reference_data/sets',
                      headers=HEADERS, params={'name': name, 'element_type': etype}, verify=False)
    if c.status_code in (200, 201):
        print(f"   Reference set yaradildi: {name}")
        return True
    print(f"   XETA: set yaradilmadi {name} — HTTP {c.status_code}: {c.text[:150]}")
    return False


def add_to_set(name, value):
    r = requests.post(f'{QRADAR_HOST}/api/reference_data/sets/{name}',
                      headers=HEADERS, params={'value': value}, verify=False)
    return r.status_code in (200, 201)


# ── JSON rule-u işlət ─────────────────────────────────────────────
def process_rule(d):
    q = d.get('qradar', {})
    aql = d.get('aql', '')
    name = q.get('rule_name', d.get('title', 'Unnamed'))
    refset = q.get('reference_set')
    rtype = q.get('reference_type', 'IP')
    indicator = q.get('indicator', 'sourceip')

    print("\n" + "=" * 55)
    print(f"Rule    : {name}")
    print(f"Severity: {q.get('severity', 'HIGH')}")
    print(f"MITRE   : {d.get('mitre', {}).get('technique', 'N/A')}")
    print(f"RefSet  : {refset}  (indicator: {indicator})")
    print("=" * 55)

    if not aql:
        print("   XETA: AQL yoxdur!"); return False

    events = run_aql_search(aql.strip())
    if events is None:
        return False

    # set-i hazirla (API)
    if refset:
        ensure_set(refset, rtype)

    # indikatorlari cixar ve set-e yaz (API)
    vals = set()
    for ev in events:
        v = ev.get(indicator)
        if v is None:
            continue
        v = str(v).strip()
        if not v or v in ('::1', '127.0.0.1', 'N/A', 'null'):
            continue
        vals.add(v)

    added = 0
    for v in vals:
        if add_to_set(refset, v):
            added += 1
    if refset:
        print(f"   Reference set '{refset}': {added} indikator yazildi (API)")
        if vals:
            print(f"   -> {', '.join(list(vals)[:5])}" + (" ..." if len(vals) > 5 else ""))
        else:
            print("   (Bu pencerede tehlikeli indikator tapilmadi)")
    return True


def main():
    print("=" * 55)
    print("  QRadar JSON+AQL Deploy (Reference Set) — GitHub Actions")
    print("=" * 55)
    print(f"  Host: {QRADAR_HOST}")
    print("=" * 55)

    files = sorted(glob.glob('rules/*.json'))
    if not files:
        print("XETA: rules/ qovlugunda JSON yoxdur!"); sys.exit(1)
    print(f"\n{len(files)} JSON rule fayl tapildi.\n")

    ok = fail = 0
    for f in files:
        print(f"\nFayl: {f}")
        try:
            d = json.load(open(f, encoding='utf-8'))
            if d and process_rule(d):
                ok += 1
            else:
                fail += 1
        except Exception as e:
            print(f"   XETA: {e}"); fail += 1

    print("\n" + "=" * 55)
    print(f"  Ugurlu : {ok}")
    print(f"  Xetali : {fail}")
    print("=" * 55)
    sys.exit(0)


if __name__ == '__main__':
    main()
