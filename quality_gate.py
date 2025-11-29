import os
import csv
import sys
from collections import Counter

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "metrics_output")
CSV_PATH = os.path.join(OUTPUT_DIR, "metrics.csv")  # metrics_aggregator.py가 만든 파일

BLOCKING_SEVERITIES = ["CRITICAL", "HIGH"]  # 여기서 정책 조정 가능

def load_counts_from_csv(csv_path):
    if not os.path.exists(csv_path):
        print(f"❌ CSV 파일이 없습니다: {csv_path}")
        sys.exit(1)

    counts_by_sev = Counter()

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sev = row.get("severity", "").upper()
            try:
                count = int(row.get("count", 0))
            except ValueError:
                count = 0
            counts_by_sev[sev] += count

    return counts_by_sev


def main():
    counts_by_sev = load_counts_from_csv(CSV_PATH)
    print("[Quality Gate] 전체 severity 집계:", dict(counts_by_sev))

    blocking_total = 0
    for sev in BLOCKING_SEVERITIES:
        blocking_total += counts_by_sev.get(sev, 0)

    if blocking_total > 0:
        print(f"❌ Quality Gate FAILED: {BLOCKING_SEVERITIES} 합계 = {blocking_total}")
        sys.exit(1)
    else:
        print("✅ Quality Gate PASSED: blocking severity 없음")
        sys.exit(0)


if __name__ == "__main__":
    main()
