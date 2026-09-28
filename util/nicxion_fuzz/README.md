# nicxion_fuzz — 칩 위에서 돌리는 차등 퍼저

nicxion PM 커널(U50, 250 MHz 빌드)의 패킷별 매칭 결과를 C 레퍼런스와 비교해
버그를 찾습니다. 외부 크레이트 의존성이 없고, C 레퍼런스도 `oracle/cref/`에 함께 들어 있어 이 디렉터리만으로 빌드됩니다.

## 구성

| 경로 | 역할 |
|---|---|
| `oracle/pm_oracle.c` | 패킷별 정답 오라클. `oracle/cref/`의 C 레퍼런스 모듈(match → exact → port/offset → priority, stage 2)을 링크 |
| `src/gen.rs` | 룰셋·패킷 생성기 (아래 전략) |
| `src/hw.rs` | DB 생성(`ngram_db_gen`) → 카드 리셋 → 호스트 프로그램 실행 → `pkt[i] matched rule_id=` 파싱 |
| `src/judge.rs` | 패킷별 판정 |
| `src/main.rs` | 캠페인 루프, 실패 저장, 최소화 |

## 빌드와 실행

```bash
cd util/nicxion_fuzz
make -C oracle                 # pm_oracle
cargo build --release

# 하드웨어 없이 생성기+오라클만 점검
./target/release/nicxion_fuzz --no-hw --iters 4 --pkts 2000

# 칩에서 캠페인 (반복당 약 1분: 카드 리셋 + DB 적재 + 실행)
./target/release/nicxion_fuzz --iters 40 --pkts 3000 --seed 1 --synth 0.5
```

옵션: `--rules FILE`(기본 `$NX_RULES`, 없으면 `<호스트 dir>/rule.txt` — `*.txt`는 git에 없으므로 직접 두거나 지정), `--synth P`(합성 룰셋 비율), `--max-payload N`(기본 1460),
`--minimize K`(실패 패킷 재실행 개수), `--timeout SECS`, `--out DIR`.
환경변수: `NX_KERNEL_DIR` `NX_HOST_DIR` `NX_XCLBIN` `NX_ORACLE` `NX_ORACLE_ARGS` `NX_RULES` `NX_BDF`(기본 `0000:01:00.1`).
`NX_ORACLE_ARGS` 기본값은 `--parser host6`(현재 IPv6 호스트). IPv4 전용인 예전 호스트(`nicxion_downgrade`, `nicxion_downscale_refined`, `nicxion_downscale_rev2`)는 `--parser host`.
`NX_V6=P`: 모양을 쓰는 패킷 중 비율 P를 IPv6로(예: 0.8 → 전체의 약 절반). 미설정이면 기존 시드 그대로 재현.
`NX_EDGE=P`: 생성 단계 중 비율 P를 경계 전략으로 — 1..17바이트 패킷 연속(tiny-run), 16/64바이트 경계 ±1 길이에
끝에서 끝나는 매치(tail-len), 한 gram을 반복한 최대 길이 payload(gram-flood), 끝 매치 큰 패킷 직후 작은 매치 패킷(tail-then-tiny).
미설정이면 기존 시드 그대로 재현.
기본 대상은 이 저장소의 `vitis/hw/nicxion_rev2_perf_opt` + `vitis/sw/nicxion_rev2_perf_opt`(xclbin은 `<커널 dir>/hw/kernel.xclbin`, 호스트는 `make host`로 먼저 빌드).

**카드 사용 중에는 돌리지 마십시오** — 반복마다 `xrt-smi reset`을 합니다
(free-running 커널은 리셋 직후 DB를 한 번만 적재하므로 필수).

## 오라클이 기준으로 삼는 것

- `--parser host`(기본): **호스트 프로그램(`main.cpp parse_packet`)과 똑같이** 패킷을 해석합니다.
  커널이 실제로 받은 입력(payload + tuser)으로 커널을 판정하기 위해서입니다. `--parser cref`는 C 파서(발견 #4).
- `--match spec`(기본): **모든 패턴의 모든 출현**을 찾아(3바이트 접두사 색인) C 레퍼런스의
  port/offset·priority 함수에 넣습니다. 커널의 bitmap/bloom/cuckoo는 거짓 음성이 없도록 설계된 필터이므로
  이것이 사양입니다. `--match cref`는 C 레퍼런스의 gram 파이프라인(발견 #5 같은 자체 특이점 포함).

## 생성 전략

- 룰 패턴을 16B 피드 청크·64B payload 라인 경계를 걸치게, payload 시작/끝에, offset 경계(val−1/val/val+1)에 배치
- 근접 오답: 1바이트 변경, payload 끝에서 잘림, 포트/프로토콜 어긋남
- 한 패킷에 같은 L4의 룰 2~4개 → 우선순위 선택
- 룰 조각으로 만든 "gram soup" 필러 → bitmap/cuckoo/exact 파이프라인 과부하 (경합 버그가 부하에서만 나타났던 이력)
- 최대 크기 패킷 연속 후 초소형 패킷 연속 → 에폭 재사용
- 대소문자 무작위(양쪽 모두 fold), VLAN·QinQ·IP 옵션·TCP 옵션 섞인 헤더, IPv6(확장 헤더 0~2개),
  첫 조각이 아닌 fragment(L4 바이트가 payload가 됨), 이더넷 패딩, 빈 payload, IPv4 아닌 프레임
- 합성 룰셋: 3~64B 패턴(바이너리, 공통 접두사, 저엔트로피 반복), tcp/udp/icmp, 방향 request/response/미지정,
  offset small/big/same, **priority는 공백 없는 형식**(발견 #1 때문에 실제로 적재되도록)

## 판정

| 판정 | 의미 |
|---|---|
| `Ok` | 일치 |
| `OkTie` | 최고 우선순위 동점 그룹 안의 다른 룰 — 알려진 TODO(`PRIORITY_TIEBREAK_TODO.md`), 버그로 세지 않음 |
| `FalseNegative` / `FalsePositive` | 매칭 여부 불일치 |
| `WrongPriority` | 매칭된 룰이긴 하나 최고 우선순위가 아님 |
| `WrongRule` | 오라클 기준 매칭되지 않는 룰 |
| `SkipHit` | (`--parser cref`에서만) C 파서가 버린 프레임에 HW가 매칭 |
| HANG/INCOMPLETE | 결과 수 부족·타임아웃·mover STUCK |

실패한 반복만 `out/<seed>/iter_NNNN/`에 남깁니다: `pkts.pcap`, `rules.txt`, `failures.tsv`, `hw.log`,
그리고 실패 패킷별로 단독 재실행(`min_<i>.pcap`)과 앞 16패킷 포함 재실행(`ctx_<i>.pcap`) 결과를
`minimize.tsv`에 기록해 **단독 재현(ISOLATED)** 인지 **문맥 의존(CONTEXT)** 인지 구분합니다.

## 지금까지의 발견

퍼저를 만들면서 찾은 것들입니다. #1~#4는 커널이 아니라 **룰 로더·레퍼런스·파서** 쪽 문제이며,
HW와 C가 같은 로더를 쓰기 때문에 차등 비교로는 드러나지 않습니다.

1. **priority가 전부 0으로 적재됨.** 룰 파일은 `priority= high`(공백 포함)로 쓰는데 `rule_loader.c`가
   공백을 건너뛰지 않아 `strncmp(" high","high",4)`가 실패합니다. rule5k의 high 2,215개·low 1,072개가
   모두 0(medium)으로 적재되어 **우선순위가 사실상 무시**됩니다. C 레퍼런스와 DB 생성기(`ngram_db_gen`)가
   같은 로더를 쓰므로 HW 결과도 동일하게 틀립니다.
2. **C 레퍼런스 메모리 오류.** `exact_match()`는 `out_max`개만 기록하면서 전체 개수를 반환하고,
   `cref_bench`는 그 값을 그대로 `port_offset_match()`에 넘겨 **스택 버퍼(256) 밖을 읽습니다**
   (ASan 확인, 한 패킷에 exact 매칭 256개 초과 시 — 저엔트로피 패턴에서 3,500~5,800개 관측).
   오라클은 버퍼를 늘려 재시도하도록 우회했습니다. 레퍼런스 원본은 수정하지 않았습니다.
3. **ICMP 룰 900개 오파싱.** 파일은 `"protocol=icmp/11 0/request"`(type과 code 사이 공백)인데 로더는
   `11,0`(쉼표)를 기대합니다. 결과적으로 type/code가 0/0으로, 포트 11로 적재됩니다(의도는 11/0 time exceeded).
4. **호스트 파서와 C 레퍼런스 파서 불일치.** rule5k의 642개 룰(protocol 51/50/47/132 각 128~130개,
   58 128개)이 영향: C 파서는 TCP/UDP/ICMP 외 프로토콜 패킷을 **버리고**(해당 514개 룰은 C에서 절대 매칭 불가),
   proto 58은 앞 2바이트를 type/code로 떼어 payload를 2바이트 밀어 봅니다. 호스트는 L4 바이트를 그대로
   payload로 넘기므로 HW는 이 룰들을 매칭합니다. 어느 쪽이 사양인지 결정이 필요합니다.
   (그 밖에 C는 IP total length로 payload를 자르고 호스트는 프레임 끝까지 씁니다.)

5. **C 레퍼런스가 진짜 매칭을 놓침.** 한 gram이 stage-1 룰과 stage-2 룰의 앵커를 겸할 때, 다음 gram이
   없으면(예: 패킷 끝) `match_scan`이 앵커 전체를 건너뛰어 stage-1 룰까지 버렸습니다. HW가 맞습니다.
   → **수정함**(2026-09-25): 해당 위치에서 만족 가능한 stage까지만 후보를 남김. 이후 C 파이프라인과
   spec 전수 탐색이 24,000패킷에서 완전 일치. (오라클 기본값은 계속 `--match spec`.)

#1(우선순위 무시)·#2(버퍼 초과)·#3(ICMP 오파싱)도 수정했습니다.
#4는 2026-09-26 해소: IPv6가 사양에 포함되면서 C 레퍼런스 파서를 IPv6 호스트와 같게 맞춤
(`oracle/cref/packet_parser.c`, 기타 프로토콜 수용, IPv4 total length 0에서 버퍼 밖 읽기 버그 수정 포함).

### 커널 버그 (수정함)

- **A. 한 패킷으로 커널 영구 정지** — exact 후보가 64개를 넘는 패킷에서 `pomHoldQ` 교착.
  store-and-forward 리더로 수정.
- **B. stage-1 룰이 패킷 끝 외에서 매칭 안 됨** — cuckoo 키에 stage-1도 패킷의 다음 gram을 사용.
  키 선택 수정 + 겸용 lane 2차 조회.

