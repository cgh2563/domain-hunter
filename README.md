# 🏠 분양 아파트 만료 도메인 헌터

청약홈 API에서 분양 단지를 수집하고, WHOIS 조회를 통해 만료/구매 가능한 도메인을 자동으로 찾아줍니다.

**매일 자동 실행** → 결과를 웹페이지로 확인 가능

## 기능

- 청약홈 공공데이터 API 연동 (과거 5년 APT 분양정보)
- WHOIS 만료일 자동 조회 (.kr → whois.kr / .com → verisign)
- 구매가능일 자동 계산 (.kr +31일 / .com +70일)
- 한글 도메인 퓨니코드 자동 변환
- 매일 자동 실행 (GitHub Actions)
- 웹 결과 페이지 (GitHub Pages)

## 설정

1. 이 저장소를 Fork
2. Settings → Secrets → `APPLYHOME_API_KEY` 추가
3. Settings → Pages → Source를 "GitHub Actions"로 설정
4. Actions 탭에서 수동 실행 또는 매일 오전 7시(KST) 자동 실행
