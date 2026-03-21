#!/usr/bin/env python3
"""
🏠 분양 아파트 만료 도메인 헌터 (웹 출력 버전)
GitHub Actions에서 실행 → HTML 결과 페이지 생성 → GitHub Pages 배포
"""

import socket, subprocess, csv, json, os, sys, time, re, argparse, ssl
import concurrent.futures
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode, urlparse, quote

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ============================================================
# 1. 청약홈 API
# ============================================================

API_ENDPOINTS = {
    "APT": {"name": "APT 분양정보", "url": "https://api.odcloud.kr/api/ApplyhomeInfoDetailSvc/v1/getAPTLttotPblancDetail"},
}

def fetch_applyhome(service_key, endpoint_key="APT", max_pages=50):
    ep = API_ENDPOINTS[endpoint_key]
    all_data, page = [], 1
    print(f"\n📡 [{ep['name']}] 수집 중...")
    while page <= max_pages:
        params = {"page": page, "perPage": 500, "serviceKey": service_key}
        url = f"{ep['url']}?{urlencode(params, quote_via=quote)}"
        try:
            req = Request(url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"})
            data = json.loads(urlopen(req, timeout=30).read().decode("utf-8"))
            if "data" not in data:
                print(f"   ❌ API 에러: {data.get('msg', '알 수 없는 에러')}"); break
            items = data["data"]; total = data.get("totalCount", 0)
            if not items: break
            all_data.extend(items)
            print(f"   📄 페이지 {page}: {len(items)}건 (누적 {len(all_data)}/{total})")
            if len(all_data) >= total: break
            page += 1; time.sleep(0.3)
        except Exception as e:
            print(f"   ❌ {e}"); break
    print(f"   ✅ 총 {len(all_data)}건")
    return all_data

def filter_by_date(api_data, date_from=None, date_to=None):
    if not date_from and not date_to: return api_data
    return [item for item in api_data
            if (item.get("RCRIT_PBLANC_DE") or "") and
               (not date_from or (item.get("RCRIT_PBLANC_DE") or "") >= date_from) and
               (not date_to or (item.get("RCRIT_PBLANC_DE") or "") <= date_to)]

def extract_domains(api_data):
    complexes, seen = [], set()
    for item in api_data:
        name = (item.get("HOUSE_NM") or "").strip()
        homepage = (item.get("HMPG_ADRES") or "").strip()
        if not name: continue
        domains = []
        if homepage:
            for u in re.split(r'[,\s]+', homepage):
                u = u.strip()
                if not u: continue
                if not u.startswith("http"): u = "http://" + u
                try:
                    dom = urlparse(u).netloc.lower().replace("www.", "")
                    if dom and dom not in seen: domains.append(dom); seen.add(dom)
                except: pass
        complexes.append({
            "name": name, "homepage": homepage, "domains": domains,
            "region": (item.get("SUBSCRPT_AREA_CODE_NM") or ""),
            "notice_date": (item.get("RCRIT_PBLANC_DE") or ""),
        })
    return complexes


# ============================================================
# 2. WHOIS
# ============================================================

WHOIS_SERVERS = {
    "kr": "whois.kr", "co.kr": "whois.kr", "or.kr": "whois.kr",
    "ne.kr": "whois.kr", "pe.kr": "whois.kr", "go.kr": "whois.kr",
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
}

SKIP_DOMAINS = ["naver.com","daum.net","tistory.com","modoo.at","imweb.me",
                "wixsite.com","iwinv.net","quv.kr","kro.kr"]

DROP_DAYS = {"kr":31,"co.kr":31,"or.kr":31,"ne.kr":31,"pe.kr":31,"go.kr":31}
DROP_DAYS_DEFAULT = 70

def to_punycode(domain):
    try:
        return ".".join(p.encode("idna").decode("ascii") for p in domain.split("."))
    except: return domain

def get_main_domain(domain):
    domain = domain.split(":")[0].lower().strip()
    parts = domain.split(".")
    kr_slds = ["co","or","ne","go","pe","re","ac"]
    if len(parts) >= 3 and parts[-1] == "kr" and parts[-2] in kr_slds:
        return ".".join(parts[-3:])
    if len(parts) >= 2: return ".".join(parts[-2:])
    return domain

def get_tld(domain):
    parts = domain.split(".")
    kr_slds = ["co","or","ne","go","pe","re","ac"]
    if len(parts) >= 2 and parts[-1] == "kr" and parts[-2] in kr_slds:
        return f"{parts[-2]}.{parts[-1]}"
    return parts[-1] if parts else ""

def whois_socket(domain, server, timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server, 43))
        s.send(f"{domain}\r\n".encode())
        result = b""
        while True:
            data = s.recv(4096)
            if not data: break
            result += data
        s.close()
        return result.decode("utf-8", errors="ignore")
    except: return ""

def whois_command(domain, timeout=10):
    try:
        r = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except: return ""

def parse_whois(text):
    info = {"만료일_원본": "", "등록일": ""}
    if not text: return info
    tl = text.lower()
    not_found = ["no match for","not found","no data found","is free","available",
                  "no entries found","도메인이름이 등록되어 있지 않습니다",
                  "above domain name is not registered","this query returned 0 objects"]
    for nf in not_found:
        if nf in tl:
            info["만료일_원본"] = "🎯 미등록"; return info

    for p in [r"Registry Expiry Date:\s*(.+)", r"Registrar Registration Expiration Date:\s*(.+)",
              r"Expiration Date\s*:\s*(.+)", r"Expiry Date\s*:\s*(.+)",
              r"등록기간만료일\s*:\s*(.+)", r"expire\s*:\s*(.+)"]:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if len(val) >= 8: info["만료일_원본"] = val; break

    for p in [r"Creation Date:\s*(.+)", r"등록일\s*:\s*(.+)"]:
        m = re.search(p, text, re.IGNORECASE)
        if m: info["등록일"] = m.group(1).strip(); break
    return info

def parse_expiry(raw):
    if not raw or "미등록" in raw: return raw, ""
    raw = raw.strip()
    m = re.match(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})", raw)
    if m: return m.group(1), m.group(2)
    m = re.match(r"(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})", raw)
    if m: return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}", ""
    m = re.match(r"(\d{4})[/-](\d{1,2})[/-](\d{1,2})", raw)
    if m: return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}", ""
    return raw, ""

def calc_purchase_date(expiry_str, tld):
    if not expiry_str or "미등록" in expiry_str:
        return "즉시 등록 가능" if "미등록" in (expiry_str or "") else ""
    try:
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", expiry_str)
        if not m: return ""
        exp = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        days = DROP_DAYS.get(tld, DROP_DAYS_DEFAULT)
        return (exp + timedelta(days=days)).strftime("%Y-%m-%d")
    except: return ""

def check_whois(domain):
    main_dom = get_main_domain(domain)
    result = {"만료일": "", "만료시간": "", "등록일": "", "구매가능일": ""}
    if any(main_dom == s or domain.endswith("." + s) for s in SKIP_DOMAINS): return result

    tld = get_tld(main_dom)
    query_dom = to_punycode(main_dom)
    info = None

    server = WHOIS_SERVERS.get(tld)
    if server:
        raw = whois_socket(query_dom, server)
        if raw:
            info = parse_whois(raw)
            if info["만료일_원본"]:
                d, t = parse_expiry(info["만료일_원본"])
                result["만료일"] = d; result["만료시간"] = t; result["등록일"] = info["등록일"]
                result["구매가능일"] = calc_purchase_date(d, tld)
                return result

    for try_dom in [query_dom, main_dom]:
        raw = whois_command(try_dom)
        if raw:
            info = parse_whois(raw)
            if info["만료일_원본"]:
                d, t = parse_expiry(info["만료일_원본"])
                result["만료일"] = d; result["만료시간"] = t; result["등록일"] = info["등록일"]
                result["구매가능일"] = calc_purchase_date(d, tld)
                return result
    return result


# ============================================================
# 3. 도메인 체크
# ============================================================

def check_domain(domain):
    r = {"도메인": domain, "만료일": "", "만료시간": "", "등록일": "", "구매가능일": ""}
    w = check_whois(domain)
    r.update(w)
    time.sleep(0.5)
    return r


# ============================================================
# 4. HTML 생성
# ============================================================

def generate_html(results, complexes, run_time):
    today = datetime.now()

    now_avail = [r for r in results if "즉시" in r.get("구매가능일","") or
                 (r.get("구매가능일","") and "즉시" not in r.get("구매가능일","") and
                  try_date(r.get("구매가능일","")) and try_date(r.get("구매가능일","")) <= today)]
    in30 = [r for r in results if in_range(r.get("구매가능일",""), today, 0, 30)]
    in90 = [r for r in results if in_range(r.get("구매가능일",""), today, 30, 90)]

    def row_class(r):
        p = r.get("구매가능일","")
        if "즉시" in p: return "now"
        if p:
            pd = try_date(p)
            if pd:
                diff = (pd - today).days
                if diff <= 0: return "now"
                if diff <= 30: return "soon"
                if diff <= 90: return "later"
        return ""

    def esc(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

    rows_html = ""
    for r in results:
        cls = row_class(r)
        rows_html += f"""<tr class="{cls}">
<td>{esc(r.get('_name',''))}</td>
<td class="domain">{esc(r['도메인'])}</td>
<td class="purchase">{esc(r['구매가능일'])}</td>
<td>{esc(r['만료일'])}</td>
<td>{esc(r['만료시간'])}</td>
<td>{esc(r['등록일'])}</td>
<td>{esc(r.get('_region',''))}</td>
<td>{esc(r.get('_notice_date',''))}</td>
<td><a href="https://whois.kr/kor/whois/whois.jsp" target="_blank" class="whois-link">조회</a></td>
</tr>
"""

    html = f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🏠 분양 도메인 헌터</title>
<style>
@import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard/dist/web/static/pretendard.css');
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: 'Pretendard', -apple-system, sans-serif;
    background: #0f172a; color: #e2e8f0; min-height: 100vh;
}}
.header {{
    background: linear-gradient(135deg, #1e293b, #0f172a);
    padding: 24px 20px; border-bottom: 1px solid rgba(255,255,255,0.05);
    text-align: center;
}}
.header h1 {{ font-size: 22px; font-weight: 800; }}
.header .sub {{ font-size: 12px; color: #64748b; margin-top: 6px; }}
.stats {{
    display: flex; gap: 12px; padding: 20px; max-width: 900px; margin: 0 auto;
    flex-wrap: wrap; justify-content: center;
}}
.stat-card {{
    flex: 1; min-width: 140px; padding: 16px; border-radius: 12px;
    text-align: center; border: 1px solid rgba(255,255,255,0.06);
}}
.stat-card.green {{ background: rgba(34,197,94,0.1); border-color: rgba(34,197,94,0.2); }}
.stat-card.orange {{ background: rgba(249,115,22,0.1); border-color: rgba(249,115,22,0.2); }}
.stat-card.blue {{ background: rgba(59,130,246,0.1); border-color: rgba(59,130,246,0.2); }}
.stat-card.gray {{ background: rgba(255,255,255,0.03); }}
.stat-num {{ font-size: 28px; font-weight: 800; }}
.stat-card.green .stat-num {{ color: #22c55e; }}
.stat-card.orange .stat-num {{ color: #f97316; }}
.stat-card.blue .stat-num {{ color: #3b82f6; }}
.stat-card.gray .stat-num {{ color: #94a3b8; }}
.stat-label {{ font-size: 11px; color: #94a3b8; margin-top: 4px; }}
.filters {{
    padding: 12px 20px; max-width: 900px; margin: 0 auto;
    display: flex; gap: 8px; flex-wrap: wrap;
}}
.filter-btn {{
    padding: 6px 14px; border-radius: 999px; border: 1px solid rgba(255,255,255,0.1);
    background: transparent; color: #94a3b8; cursor: pointer; font-size: 12px;
    font-family: inherit; font-weight: 600; transition: all 0.15s;
}}
.filter-btn:hover {{ border-color: rgba(255,255,255,0.2); color: #e2e8f0; }}
.filter-btn.active {{ background: rgba(34,211,238,0.15); color: #22d3ee; border-color: rgba(34,211,238,0.3); }}
input.search {{
    flex: 1; min-width: 150px; padding: 6px 14px; border-radius: 999px;
    border: 1px solid rgba(255,255,255,0.1); background: rgba(0,0,0,0.2);
    color: #e2e8f0; font-size: 12px; font-family: inherit; outline: none;
}}
input.search:focus {{ border-color: rgba(34,211,238,0.4); }}
.table-wrap {{
    padding: 0 12px 40px; max-width: 100%; overflow-x: auto;
}}
table {{
    width: 100%; border-collapse: collapse; font-size: 12px; min-width: 800px;
}}
th {{
    background: #1e293b; color: #94a3b8; padding: 10px 8px; text-align: left;
    font-weight: 700; font-size: 11px; position: sticky; top: 0; z-index: 10;
    cursor: pointer; white-space: nowrap; border-bottom: 1px solid rgba(255,255,255,0.06);
}}
th:hover {{ color: #e2e8f0; }}
td {{
    padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.03);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 200px;
}}
tr:hover {{ background: rgba(255,255,255,0.03); }}
tr.now {{ background: rgba(34,197,94,0.08); }}
tr.now td {{ color: #86efac; }}
tr.soon {{ background: rgba(249,115,22,0.06); }}
tr.soon td {{ color: #fdba74; }}
tr.later {{ background: rgba(59,130,246,0.04); }}
.domain {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; }}
.purchase {{ font-weight: 700; }}
tr.now .purchase {{ color: #22c55e; }}
tr.soon .purchase {{ color: #f97316; }}
tr.later .purchase {{ color: #3b82f6; }}
.whois-link {{
    color: #64748b; text-decoration: none; padding: 2px 8px; border-radius: 4px;
    border: 1px solid rgba(255,255,255,0.08); font-size: 10px;
}}
.whois-link:hover {{ color: #22d3ee; border-color: rgba(34,211,238,0.3); }}
.footer {{
    text-align: center; padding: 20px; font-size: 11px; color: #475569;
    border-top: 1px solid rgba(255,255,255,0.03);
}}
</style>
</head>
<body>

<div class="header">
    <h1>🏠 분양 아파트 만료 도메인 헌터</h1>
    <div class="sub">마지막 업데이트: {run_time} KST · 청약홈 API 기준 · 매일 자동 갱신</div>
</div>

<div class="stats">
    <div class="stat-card green">
        <div class="stat-num">{len(now_avail)}</div>
        <div class="stat-label">⭐ 지금 구매 가능</div>
    </div>
    <div class="stat-card orange">
        <div class="stat-num">{len(in30)}</div>
        <div class="stat-label">🔥 30일 이내</div>
    </div>
    <div class="stat-card blue">
        <div class="stat-num">{len(in90)}</div>
        <div class="stat-label">📅 90일 이내</div>
    </div>
    <div class="stat-card gray">
        <div class="stat-num">{len(results)}</div>
        <div class="stat-label">전체 도메인</div>
    </div>
</div>

<div class="filters">
    <button class="filter-btn active" onclick="filterRows('all')">전체</button>
    <button class="filter-btn" onclick="filterRows('now')">⭐ 지금 구매가능</button>
    <button class="filter-btn" onclick="filterRows('soon')">🔥 30일 이내</button>
    <button class="filter-btn" onclick="filterRows('later')">📅 90일 이내</button>
    <input type="text" class="search" placeholder="🔍 단지명/도메인 검색..." oninput="searchRows(this.value)">
</div>

<div class="table-wrap">
<table id="mainTable">
<thead>
<tr>
    <th onclick="sortTable(0)">단지명 ↕</th>
    <th onclick="sortTable(1)">도메인 ↕</th>
    <th onclick="sortTable(2)">구매가능일 ↕</th>
    <th onclick="sortTable(3)">만료일 ↕</th>
    <th>만료시간</th>
    <th onclick="sortTable(5)">등록일 ↕</th>
    <th onclick="sortTable(6)">지역 ↕</th>
    <th onclick="sortTable(7)">공고일 ↕</th>
    <th>WHOIS</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>

<div class="footer">
    구매가능일 계산: .kr = 만료+31일 / .com,.net = 만료+70일<br>
    총 {len(complexes)}개 단지 · {len(results)}개 도메인 · 소요시간 {run_time}
</div>

<script>
function filterRows(cls) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('#mainTable tbody tr').forEach(tr => {{
        if (cls === 'all') tr.style.display = '';
        else tr.style.display = tr.classList.contains(cls) ? '' : 'none';
    }});
}}

function searchRows(q) {{
    q = q.toLowerCase();
    document.querySelectorAll('#mainTable tbody tr').forEach(tr => {{
        const text = tr.textContent.toLowerCase();
        tr.style.display = text.includes(q) ? '' : 'none';
    }});
}}

let sortDir = {{}};
function sortTable(col) {{
    const table = document.getElementById('mainTable');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    sortDir[col] = !sortDir[col];
    rows.sort((a, b) => {{
        const av = a.cells[col]?.textContent || '';
        const bv = b.cells[col]?.textContent || '';
        const cmp = av.localeCompare(bv, 'ko');
        return sortDir[col] ? cmp : -cmp;
    }});
    rows.forEach(r => tbody.appendChild(r));
}}
</script>
</body>
</html>"""

    return html


def try_date(s):
    try: return datetime.strptime(s, "%Y-%m-%d")
    except: return None

def in_range(p, today, min_d, max_d):
    if not p or "즉시" in p: return False
    pd = try_date(p)
    if not pd: return False
    diff = (pd - today).days
    return min_d < diff <= max_d


# ============================================================
# 5. 메인
# ============================================================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=str, required=True)
    parser.add_argument("--date-from", type=str, default="")
    parser.add_argument("--date-to", type=str, default="")
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()

    t0 = time.time()
    print("🏠 도메인 헌터 (웹 버전) 시작\n")

    # API 수집
    all_data = fetch_applyhome(args.key, "APT")
    if args.date_from or args.date_to:
        all_data = filter_by_date(all_data, args.date_from, args.date_to)
        print(f"📅 기간 필터 → {len(all_data)}건")

    complexes = extract_domains(all_data)
    to_check = []
    for c in complexes:
        for d in c.get("domains", []):
            to_check.append({"domain": d, "name": c["name"], "homepage": c.get("homepage",""),
                             "region": c.get("region",""), "notice_date": c.get("notice_date","")})

    print(f"\n🔍 {len(to_check)}개 도메인 WHOIS 체크 중...\n")

    # WHOIS 체크
    results, checked = [], 0
    total = len(to_check)

    def proc(item):
        r = check_domain(item["domain"])
        r["_name"]=item["name"]; r["_homepage"]=item["homepage"]
        r["_region"]=item["region"]; r["_notice_date"]=item["notice_date"]
        return r

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        fmap = {ex.submit(proc, i): i for i in to_check}
        for f in concurrent.futures.as_completed(fmap):
            checked+=1; r=f.result(); results.append(r)
            if checked % 50 == 0:
                print(f"  [{checked}/{total}] 진행 중...")

    # 정렬
    def sort_key(r):
        p = r.get("구매가능일","")
        if "즉시" in p: return "0000-00-00"
        if p: return p
        return "9999-99-99"
    results.sort(key=sort_key)

    elapsed = time.time() - t0
    run_time = datetime.now().strftime("%Y-%m-%d %H:%M")

    print(f"\n✅ {len(results)}개 완료 ({elapsed:.0f}초)")

    # HTML 생성
    os.makedirs("output", exist_ok=True)
    html = generate_html(results, complexes, run_time)

    with open("output/index.html", "w", encoding="utf-8") as f:
        f.write(html)

    # JSON 데이터도 저장 (API로 활용 가능)
    json_data = []
    for r in results:
        json_data.append({
            "name": r.get("_name",""), "domain": r["도메인"],
            "purchase_date": r["구매가능일"], "expiry": r["만료일"],
            "expiry_time": r["만료시간"], "registered": r["등록일"],
            "region": r.get("_region",""), "notice_date": r.get("_notice_date",""),
        })
    with open("output/data.json", "w", encoding="utf-8") as f:
        json.dump({"updated": run_time, "count": len(json_data), "domains": json_data}, f, ensure_ascii=False, indent=2)

    print(f"💾 output/index.html 생성 완료")
    print(f"💾 output/data.json 생성 완료")

if __name__ == "__main__":
    main()
