# mky_backup — 네트워크 패킷 패턴 매칭 엔진 (C)

네트워크 패킷 페이로드에서 시그니처 룰을 고속으로 탐지하는 C 구현체입니다.
Bitmap 기반 pre-filter → Exact match → Port/Offset 필터의 다단계 파이프라인으로 구성됩니다.

---

## 전체 처리 파이프라인

```
rule.txt
   │
   ▼
[rule_loader]   ── 룰 파싱 (id / pattern / proto / port / offset / priority)
   │
   ▼
[ngram_extract] ── 각 패턴에서 3-gram 슬라이딩 윈도 추출
   │
   ▼
[singleton]     ── 룰별 대표 3-gram 선정 (greedy, 최소 degree 우선)
   │             ── multi-stage: 연속 3-gram 체이닝 지원
   ▼
[bitmap]        ── 대표 gram → 32KiB Bitmap (2^18 bit) 등록
                ── 6-bit 폴딩: idx = g[0][5:0]<<12 | g[1][5:0]<<6 | g[2][5:0]
   │
   ▼
pcap_file
   │
   ▼
[pcap_reader]   ── libpcap 없이 raw pcap 파일 순회
   │
   ▼
[packet_parser] ── IPv4/IPv6 + TCP/UDP/ICMP 헤더 파싱 → payload 추출
   │
   ▼
  (ASCII 대소문자 통합: A-Z → a-z)
   │
   ▼
[match_scan]    ── payload를 1 byte씩 슬라이딩
                ── Stage-1 Bitmap hit? → Stage-N verifier bitmap 체크
                ── 64-bank HashTable(Cuckoo)로 gram_idx → assign_idx 조회
                ── 후보 목록(MatchCandidate[]) 수집
   │
   ▼
[exact_match]   ── 후보별 패턴 전체 memcmp 수행
   │
   ▼
[port_offset_match] ── proto / port / direction(req/res) / offset 조건 필터
   │
   ▼
[priority_sort] ── 우선순위(high/low) 정렬
   │
   ▼
  ALERT 출력 / pm_log 기록
```

---

## 모듈 구성

| 파일 | 역할 |
|---|---|
| `rule_loader.c/h` | 룰 파일 파싱. URL 디코딩 + 소문자 정규화 후 `RuleSet` 구성 |
| `ngram_extract.c/h` | 패턴 문자열에서 N-gram(기본 N=3) 추출 |
| `singleton.c/h` | 각 룰의 대표 3-gram 선정. degree=1(고유 gram)을 최우선 처리하는 greedy 알고리즘 |
| `bitmap.c/h` | 32KiB(2^18 bit) Bitmap. 3-gram을 18-bit 인덱스로 압축하여 O(1) 존재 확인 |
| `hashtable.c/h` | 64-bank Cuckoo hashing 기반 `gram_idx → assign_idx` 인덱스 테이블 |
| `cuckoo_hash.c/h` | Cuckoo hash 저수준 구현 (2-테이블, 최대 64회 loop) |
| `match.c/h` | Bitmap hit + multi-stage verifier + HashTable 조회로 후보 수집 (최대 8 stage) |
| `exact_match.c/h` | 후보 위치에서 패턴 전체 exact 비교 |
| `port_offset_matcher.c/h` | proto/port/direction/offset 메타 조건 필터링 |
| `priority.c/h` | 최종 매치 결과를 priority 기준으로 정렬 |
| `pcap_reader.c/h` | pcap 파일 직접 읽기 (외부 라이브러리 불필요) |
| `packet_parser.c/h` | Ethernet → IPv4/IPv6 → TCP/UDP/ICMP 헤더 파싱 |
| `pm_output.c/h` | 매치 결과 출력 유틸리티 |
| `xor_filter.c/h` | Xor Filter(확률적 필터) 구현체 — 현재 메인 파이프라인 미통합 |

---

## Singleton 알고리즘

각 룰에서 **탐지에 사용할 3-gram 하나**를 고른다.

1. 모든 룰의 3-gram을 수집하고 각 gram이 몇 개의 룰에 등장하는지(`degree`) 계산
2. `degree == 1`인 gram(오직 한 룰에만 등장)을 BFS 큐에 우선 투입
3. 큐가 빌 때는 전체에서 `degree` 최솟값을 가진 gram 선택
4. 한 gram이 커버하는 룰들을 모두 커버 처리 → 인접 gram의 degree 감소
5. 선정된 gram 위치에서 연속 3-gram을 `next_grams[]`로 저장 (multi-stage 검증용)

---

## Bitmap 구조

```
bit index = (gram[0] & 0x3F) << 12
          | (gram[1] & 0x3F) <<  6
          | (gram[2] & 0x3F)
```

- 크기: 2^18 bit = 32 KiB per Bitmap
- Stage Bitmap(`max_stage`개) + Verifier Bitmap(`max_stage - 1`개)로 false positive 감소
- `--max_stage` 파라미터로 단계 수 조절 (기본값 3, 최대 `MATCH_MAX_STAGES = 8`)

---

## HashTable 구조

- 64-bank 분산 구조 (`HT_BANKS = 64`)
- 각 bank: Cuckoo hash 2-테이블, 최대 64회 eviction loop
- key: `gram_idx` (18-bit), value: `assign_idx` (int)
- `gram_idx & HT_BANK_MASK`로 bank 선택 (bank skew 통계 런타임 출력)

---

## 빌드 및 실행

```bash
# 빌드
make

# 실행 (룰파일 pcap파일 최대스테이지 verbosity)
# verbosity: 0=통계만, 1=기본(default), 2=ALERT 상세+pm_log
make run RULE=<rule 파일> PCAP=<pcap 파일> MAX_STAGE=3 VERBOSE=1

# 직접 실행
./main <rule.txt> [pcap_file] [max_stage] [verbose]

# 단위 테스트
make run-test-bm        # bitmap 테스트
make run-test-unit      # rule_loader / singleton / bitmap 통합 테스트
```

### Makefile 기본값

| 변수 | 기본값 |
|---|---|
| `RULE` | `rule.txt` |
| `PCAP` | `full.pcap` |
| `MAX_STAGE` | `3` |
| `VERBOSE` | `1` |
