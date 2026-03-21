#!/usr/bin/env python3
"""
🏠 분양 도메인 헌터 (GitHub Pages 웹 버전) v3.4
GitHub Actions에서 실행 → HTML 결과 → GitHub Pages 배포

구매가능일 계산:
  .kr: 만료+31일
  .com/.net: WHOIS 상태 기반
    pendingDelete + Updated Date → +5일
    redemptionPeriod + Updated Date → +35일
    상태 모름 → 만료일 +35~80일
"""

import socket, subprocess, json, os, sys, time, re, argparse, ssl
import concurrent.futures
from datetime import datetime, timedelta
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode, urlparse, quote

ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# ── 청약홈 API ──
def fetch_applyhome(service_key, max_pages=50):
    url_base = "https://api.odcloud.kr/api/ApplyhomeInfoDetailSvc/v1/getAPTLttotPblancDetail"
    all_data, page = [], 1
    print(f"\n📡 수집 중...")
    while page <= max_pages:
        params = {"page": page, "perPage": 500, "serviceKey": service_key}
        url = f"{url_base}?{urlencode(params, quote_via=quote)}"
        try:
            req = Request(url, headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"})
            data = json.loads(urlopen(req, timeout=30).read().decode("utf-8"))
            if "data" not in data: break
            items = data["data"]; total = data.get("totalCount", 0)
            if not items: break
            all_data.extend(items)
            print(f"   페이지 {page}: {len(items)}건 ({len(all_data)}/{total})")
            if len(all_data) >= total: break
            page += 1; time.sleep(0.3)
        except Exception as e: print(f"   ❌ {e}"); break
    print(f"   ✅ 총 {len(all_data)}건")
    return all_data

def filter_by_date(data, df=None, dt=None):
    if not df and not dt: return data
    return [i for i in data if (i.get("RCRIT_PBLANC_DE") or "") and
            (not df or (i.get("RCRIT_PBLANC_DE") or "") >= df) and
            (not dt or (i.get("RCRIT_PBLANC_DE") or "") <= dt)]

def extract_domains(data):
    cx, seen = [], set()
    for item in data:
        name = (item.get("HOUSE_NM") or "").strip()
        hp = (item.get("HMPG_ADRES") or "").strip()
        if not name: continue
        doms = []
        if hp:
            for u in re.split(r'[,\s]+', hp):
                u = u.strip()
                if not u: continue
                if not u.startswith("http"): u = "http://" + u
                try:
                    d = urlparse(u).netloc.lower().replace("www.", "")
                    if d and d not in seen: doms.append(d); seen.add(d)
                except: pass
        cx.append({"name": name, "homepage": hp, "domains": doms,
                   "region": item.get("SUBSCRPT_AREA_CODE_NM") or "",
                   "notice_date": item.get("RCRIT_PBLANC_DE") or ""})
    return cx

# ── WHOIS ──
WHOIS_SERVERS = {"kr":"whois.kr","co.kr":"whois.kr","or.kr":"whois.kr",
    "ne.kr":"whois.kr","pe.kr":"whois.kr","go.kr":"whois.kr",
    "com":"whois.verisign-grs.com","net":"whois.verisign-grs.com","org":"whois.pir.org"}
SKIP = ["naver.com","daum.net","tistory.com","modoo.at","imweb.me","wixsite.com","iwinv.net","quv.kr","kro.kr"]

def to_puny(d):
    try: return ".".join(p.encode("idna").decode("ascii") for p in d.split("."))
    except: return d
def get_main(d):
    d = d.split(":")[0].lower().strip(); p = d.split(".")
    kr = ["co","or","ne","go","pe","re","ac"]
    if len(p)>=3 and p[-1]=="kr" and p[-2] in kr: return ".".join(p[-3:])
    return ".".join(p[-2:]) if len(p)>=2 else d
def get_tld(d):
    p = d.split("."); kr = ["co","or","ne","go","pe","re","ac"]
    if len(p)>=2 and p[-1]=="kr" and p[-2] in kr: return f"{p[-2]}.{p[-1]}"
    return p[-1] if p else ""

def wsock(domain, server, timeout=10):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(timeout)
        s.connect((server, 43)); s.send(f"{domain}\r\n".encode())
        r = b""
        while True:
            d = s.recv(4096)
            if not d: break
            r += d
        s.close(); return r.decode("utf-8", errors="ignore")
    except: return ""

def wcmd(domain, timeout=10):
    try: return subprocess.run(["whois", domain], capture_output=True, text=True, timeout=timeout).stdout
    except: return ""

def parse_dt(raw):
    if not raw: return ""
    m = re.match(r"(\d{4}-\d{2}-\d{2})", raw.strip())
    if m: return m.group(1)
    m = re.match(r"(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})", raw.strip())
    if m: return f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"
    return ""
def parse_tm(raw):
    if not raw: return ""
    m = re.search(r"(\d{2}:\d{2}:\d{2})", raw)
    return m.group(1) if m else ""

def parse_whois(text):
    info = {"exp": "", "reg": "", "status": "", "updated": ""}
    if not text: return info
    tl = text.lower()
    nf = ["no match for","not found","no data found","is free","available",
          "no entries found","도메인이름이 등록되어 있지 않습니다","above domain name is not registered","this query returned 0 objects"]
    for n in nf:
        if n in tl: info["exp"] = "🎯 미등록"; return info
    for p in [r"Registry Expiry Date:\s*(.+)",r"Registrar Registration Expiration Date:\s*(.+)",
              r"Expiration Date\s*:\s*(.+)",r"Expiry Date\s*:\s*(.+)",r"등록기간만료일\s*:\s*(.+)",r"expire\s*:\s*(.+)"]:
        m = re.search(p, text, re.IGNORECASE)
        if m and len(m.group(1).strip())>=8: info["exp"] = m.group(1).strip(); break
    for p in [r"Creation Date:\s*(.+)",r"등록일\s*:\s*(.+)"]:
        m = re.search(p, text, re.IGNORECASE)
        if m: info["reg"] = m.group(1).strip(); break
    for p in [r"Updated Date:\s*(.+)",r"최근변경일\s*:\s*(.+)"]:
        m = re.search(p, text, re.IGNORECASE)
        if m: info["updated"] = m.group(1).strip(); break
    sts = [s.lower() for s in re.findall(r"(?:Domain )?Status:\s*(\S+)", text, re.IGNORECASE)]
    if any("pendingdelete" in s for s in sts): info["status"] = "pendingDelete"
    elif any("redemption" in s for s in sts): info["status"] = "redemptionPeriod"
    elif any("hold" in s or "expired" in s for s in sts): info["status"] = "expired"
    elif any("ok" in s or "active" in s for s in sts): info["status"] = "active"
    return info

def calc_drop(exp_str, upd_str, status, tld):
    r = {"drop": "", "range": "", "basis": "", "time": ""}
    if "미등록" in (exp_str or ""):
        r["drop"] = "즉시 등록 가능"; r["basis"] = "WHOIS 미등록"; return r
    ed = parse_dt(exp_str); ud = parse_dt(upd_str)
    is_kr = tld in ("kr","co.kr","or.kr","ne.kr","pe.kr","go.kr")
    if is_kr:
        if ed:
            try:
                r["drop"] = (datetime.strptime(ed,"%Y-%m-%d")+timedelta(days=31)).strftime("%Y-%m-%d")
                r["basis"] = "만료+31일"; r["time"] = "오전 9~10시 KST"
            except: pass
        return r
    r["time"] = "새벽 3~5시 KST"
    if status == "pendingDelete" and ud:
        try:
            r["drop"] = (datetime.strptime(ud,"%Y-%m-%d")+timedelta(days=5)).strftime("%Y-%m-%d")
            r["basis"] = f"pendingDelete→Updated({ud})+5일"
        except: pass
        return r
    if status == "redemptionPeriod" and ud:
        try:
            r["drop"] = (datetime.strptime(ud,"%Y-%m-%d")+timedelta(days=35)).strftime("%Y-%m-%d")
            r["basis"] = f"redemption→Updated({ud})+35일"
        except: pass
        return r
    if ed:
        try:
            e = datetime.strptime(ed,"%Y-%m-%d")
            ea = (e+timedelta(days=35)).strftime("%Y-%m-%d")
            tp = (e+timedelta(days=75)).strftime("%Y-%m-%d")
            la = (e+timedelta(days=80)).strftime("%Y-%m-%d")
            r["drop"] = tp; r["range"] = f"{ea} ~ {la}"
            r["basis"] = "만료+35~80일 (추정)"
        except: pass
    return r

def check_whois(domain):
    md = get_main(domain)
    res = {"만료일":"","만료시간":"","등록일":"","상태":"","updated":"",
           "구매가능일":"","범위":"","근거":"","삭제시간":""}
    if any(md==s or domain.endswith("."+s) for s in SKIP): return res
    tld = get_tld(md); qd = to_puny(md)
    sv = WHOIS_SERVERS.get(tld)
    raw = wsock(qd, sv) if sv else ""
    if not raw or "미등록" not in raw:
        for td in [qd, md]:
            raw2 = wcmd(td)
            if raw2 and not raw: raw = raw2
            elif raw2: raw = raw  # keep first result
            if raw: break
    if raw:
        info = parse_whois(raw)
        if info["exp"]:
            res["만료일"] = parse_dt(info["exp"]); res["만료시간"] = parse_tm(info["exp"])
            res["등록일"] = info["reg"]; res["상태"] = info["status"]; res["updated"] = parse_dt(info["updated"])
            d = calc_drop(info["exp"], info["updated"], info["status"], tld)
            res["구매가능일"]=d["drop"]; res["범위"]=d["range"]; res["근거"]=d["basis"]; res["삭제시간"]=d["time"]
    return res

def check_domain(domain):
    r = {"도메인":domain,"만료일":"","만료시간":"","등록일":"","상태":"","updated":"",
         "구매가능일":"","범위":"","근거":"","삭제시간":""}
    r.update(check_whois(domain)); time.sleep(0.5); return r

def try_date(s):
    try: return datetime.strptime(s,"%Y-%m-%d")
    except: return None

# ── HTML 생성 ──
def gen_html(results, complexes, run_time):
    today = datetime.now()
    na = [r for r in results if "즉시" in r.get("구매가능일","") or (try_date(r.get("구매가능일","")) and try_date(r.get("구매가능일",""))<=today)]
    i30 = [r for r in results if r.get("구매가능일","") and "즉시" not in r.get("구매가능일","") and try_date(r.get("구매가능일","")) and 0<(try_date(r.get("구매가능일",""))-today).days<=30]
    i90 = [r for r in results if r.get("구매가능일","") and "즉시" not in r.get("구매가능일","") and try_date(r.get("구매가능일","")) and 30<(try_date(r.get("구매가능일",""))-today).days<=90]

    def rc(r):
        p=r.get("구매가능일","")
        if "즉시" in p: return "now"
        pd=try_date(p)
        if pd:
            d=(pd-today).days
            if d<=0: return "now"
            if d<=30: return "soon"
            if d<=90: return "later"
        return ""
    def e(s): return str(s).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    rows=""
    for r in results:
        c=rc(r)
        st=r.get("상태","")
        st_badge=""
        if st=="pendingDelete": st_badge='<span style="background:#ef444420;color:#ef4444;padding:1px 6px;border-radius:4px;font-size:10px">pendingDelete</span>'
        elif st=="redemptionPeriod": st_badge='<span style="background:#f59e0b20;color:#f59e0b;padding:1px 6px;border-radius:4px;font-size:10px">redemption</span>'
        elif st: st_badge=f'<span style="color:#64748b;font-size:10px">{e(st)}</span>'

        range_info = f'<br><span style="font-size:10px;color:#64748b">{e(r.get("범위",""))}</span>' if r.get("범위") else ""
        basis = f'<span style="font-size:10px;color:#475569">{e(r.get("근거",""))}</span>' if r.get("근거") else ""
        drop_time = f'<span style="font-size:10px;color:#94a3b8">{e(r.get("삭제시간",""))}</span>' if r.get("삭제시간") else ""

        rows+=f'''<tr class="{c}">
<td>{e(r.get("_name",""))}</td>
<td class="domain">{e(r["도메인"])}</td>
<td class="purchase">{e(r["구매가능일"])}{range_info}</td>
<td>{basis}</td>
<td>{drop_time}</td>
<td>{e(r["만료일"])}</td>
<td>{e(r["만료시간"])}</td>
<td>{st_badge}</td>
<td>{e(r.get("_region",""))}</td>
<td><a href="https://whois.kr/kor/whois/whois.jsp" target="_blank" class="wl">조회</a></td>
</tr>\n'''

    return f'''<!DOCTYPE html>
<html lang="ko"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>🏠 분양 도메인 헌터</title>
<style>
@import url('https://cdn.jsdelivr.net/gh/orioncactus/pretendard/dist/web/static/pretendard.css');
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Pretendard',-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}}
.hd{{background:linear-gradient(135deg,#1e293b,#0f172a);padding:24px 20px;border-bottom:1px solid rgba(255,255,255,.05);text-align:center}}
.hd h1{{font-size:22px;font-weight:800}} .hd .sub{{font-size:12px;color:#64748b;margin-top:6px}}
.st{{display:flex;gap:12px;padding:20px;max-width:900px;margin:0 auto;flex-wrap:wrap;justify-content:center}}
.sc{{flex:1;min-width:140px;padding:16px;border-radius:12px;text-align:center;border:1px solid rgba(255,255,255,.06)}}
.sc.g{{background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.2)}}
.sc.o{{background:rgba(249,115,22,.1);border-color:rgba(249,115,22,.2)}}
.sc.b{{background:rgba(59,130,246,.1);border-color:rgba(59,130,246,.2)}}
.sc.x{{background:rgba(255,255,255,.03)}}
.sn{{font-size:28px;font-weight:800}}
.sc.g .sn{{color:#22c55e}}.sc.o .sn{{color:#f97316}}.sc.b .sn{{color:#3b82f6}}.sc.x .sn{{color:#94a3b8}}
.sl{{font-size:11px;color:#94a3b8;margin-top:4px}}
.fl{{padding:12px 20px;max-width:900px;margin:0 auto;display:flex;gap:8px;flex-wrap:wrap}}
.fb{{padding:6px 14px;border-radius:999px;border:1px solid rgba(255,255,255,.1);background:0;color:#94a3b8;cursor:pointer;font-size:12px;font-family:inherit;font-weight:600}}
.fb:hover{{border-color:rgba(255,255,255,.2);color:#e2e8f0}}
.fb.ac{{background:rgba(34,211,238,.15);color:#22d3ee;border-color:rgba(34,211,238,.3)}}
input.sr{{flex:1;min-width:150px;padding:6px 14px;border-radius:999px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.2);color:#e2e8f0;font-size:12px;font-family:inherit;outline:none}}
.tw{{padding:0 12px 40px;max-width:100%;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px;min-width:900px}}
th{{background:#1e293b;color:#94a3b8;padding:10px 8px;text-align:left;font-weight:700;font-size:11px;position:sticky;top:0;z-index:10;cursor:pointer;white-space:nowrap;border-bottom:1px solid rgba(255,255,255,.06)}}
td{{padding:8px;border-bottom:1px solid rgba(255,255,255,.03);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px}}
tr:hover{{background:rgba(255,255,255,.03)}}
tr.now{{background:rgba(34,197,94,.08)}} tr.now td{{color:#86efac}}
tr.soon{{background:rgba(249,115,22,.06)}} tr.soon td{{color:#fdba74}}
tr.later{{background:rgba(59,130,246,.04)}}
.domain{{font-family:'JetBrains Mono',monospace;font-size:11px}}
.purchase{{font-weight:700}}
tr.now .purchase{{color:#22c55e}} tr.soon .purchase{{color:#f97316}} tr.later .purchase{{color:#3b82f6}}
.wl{{color:#64748b;text-decoration:none;padding:2px 8px;border-radius:4px;border:1px solid rgba(255,255,255,.08);font-size:10px}}
.wl:hover{{color:#22d3ee;border-color:rgba(34,211,238,.3)}}
.ft{{text-align:center;padding:20px;font-size:11px;color:#475569;border-top:1px solid rgba(255,255,255,.03)}}
</style></head><body>
<div class="hd"><h1>🏠 분양 아파트 만료 도메인 헌터</h1>
<div class="sub">업데이트: {run_time} KST · WHOIS 상태+Updated Date 기반 낙장일 계산 · 매일 자동 갱신</div></div>
<div class="st">
<div class="sc g"><div class="sn">{len(na)}</div><div class="sl">⭐ 지금 구매 가능</div></div>
<div class="sc o"><div class="sn">{len(i30)}</div><div class="sl">🔥 30일 이내</div></div>
<div class="sc b"><div class="sn">{len(i90)}</div><div class="sl">📅 90일 이내</div></div>
<div class="sc x"><div class="sn">{len(results)}</div><div class="sl">전체 도메인</div></div>
</div>
<div class="fl">
<button class="fb ac" onclick="ff('all')">전체</button>
<button class="fb" onclick="ff('now')">⭐ 지금 가능</button>
<button class="fb" onclick="ff('soon')">🔥 30일 이내</button>
<button class="fb" onclick="ff('later')">📅 90일 이내</button>
<input type="text" class="sr" placeholder="🔍 검색..." oninput="fs(this.value)">
</div>
<div class="tw"><table id="mt"><thead><tr>
<th onclick="ss(0)">단지명 ↕</th><th onclick="ss(1)">도메인 ↕</th>
<th onclick="ss(2)">구매가능일 ↕</th><th>계산근거</th><th>삭제시간</th>
<th onclick="ss(5)">만료일 ↕</th><th>만료시간</th><th>상태</th>
<th onclick="ss(8)">지역 ↕</th><th>WHOIS</th>
</tr></thead><tbody>{rows}</tbody></table></div>
<div class="ft">
구매가능일: .kr=만료+31일 / .com: pendingDelete→Updated+5일, redemption→Updated+35일, 추정→만료+35~80일<br>
삭제시간: .kr 오전9~10시 / .com 새벽3~5시 KST · {len(complexes)}개 단지 · {len(results)}개 도메인
</div>
<script>
function ff(c){{document.querySelectorAll('.fb').forEach(b=>b.classList.remove('ac'));event.target.classList.add('ac');
document.querySelectorAll('#mt tbody tr').forEach(t=>{{t.style.display=c==='all'?'':t.classList.contains(c)?'':'none'}})}}
function fs(q){{q=q.toLowerCase();document.querySelectorAll('#mt tbody tr').forEach(t=>{{t.style.display=t.textContent.toLowerCase().includes(q)?'':'none'}})}}
let sd={{}};function ss(c){{const tb=document.querySelector('#mt tbody'),rs=Array.from(tb.querySelectorAll('tr'));sd[c]=!sd[c];
rs.sort((a,b)=>{{const av=a.cells[c]?.textContent||'',bv=b.cells[c]?.textContent||'';return sd[c]?av.localeCompare(bv,'ko'):-av.localeCompare(bv,'ko')}});
rs.forEach(r=>tb.appendChild(r))}}
</script></body></html>'''

# ── 메인 ──
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--date-from", default="")
    parser.add_argument("--date-to", default="")
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()

    t0 = time.time()
    all_data = fetch_applyhome(args.key)
    if args.date_from or args.date_to:
        all_data = filter_by_date(all_data, args.date_from, args.date_to)
    cx = extract_domains(all_data)
    to_check = []
    for c in cx:
        for d in c["domains"]:
            to_check.append({"domain":d,"name":c["name"],"homepage":c["homepage"],
                             "region":c["region"],"notice_date":c["notice_date"]})
    print(f"\n🔍 {len(to_check)}개 WHOIS 체크 중...\n")
    results, checked = [], 0
    total = len(to_check)
    def proc(item):
        r = check_domain(item["domain"])
        r["_name"]=item["name"];r["_homepage"]=item["homepage"]
        r["_region"]=item["region"];r["_notice_date"]=item["notice_date"]
        return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        fmap={ex.submit(proc,i):i for i in to_check}
        for f in concurrent.futures.as_completed(fmap):
            checked+=1;r=f.result();results.append(r)
            if checked%50==0: print(f"  [{checked}/{total}]")
    results.sort(key=lambda r:r.get("구매가능일","") if r.get("구매가능일","") and "즉시" not in r.get("구매가능일","") else ("0000" if "즉시" in r.get("구매가능일","") else "9999"))
    run_time=datetime.now().strftime("%Y-%m-%d %H:%M")
    print(f"\n✅ {len(results)}개 완료 ({time.time()-t0:.0f}초)")
    os.makedirs("output",exist_ok=True)
    with open("output/index.html","w",encoding="utf-8") as f: f.write(gen_html(results,cx,run_time))
    jd=[{"name":r.get("_name",""),"domain":r["도메인"],"drop_date":r["구매가능일"],
         "drop_range":r["범위"],"basis":r["근거"],"drop_time":r["삭제시간"],
         "expiry":r["만료일"],"expiry_time":r["만료시간"],"status":r["상태"],
         "updated":r["updated"],"region":r.get("_region",""),"notice":r.get("_notice_date","")} for r in results]
    with open("output/data.json","w",encoding="utf-8") as f:
        json.dump({"updated":run_time,"count":len(jd),"domains":jd},f,ensure_ascii=False,indent=2)
    print(f"💾 output/index.html + data.json 생성")

if __name__ == "__main__": main()
