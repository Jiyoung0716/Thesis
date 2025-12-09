import os
import csv
import sys
from collections import Counter

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "metrics_output")

# 요약 CSV (severity별 count)
CSV_PATH = os.path.join(OUTPUT_DIR, "metrics.csv")
# 상세 CSV (툴/룰/메시지까지)
DETAILED_CSV_PATH = os.path.join(OUTPUT_DIR, "metrics_detailed.csv")

BLOCKING_SEVERITIES = ["CRITICAL", "HIGH"]  # 여기서 정책 조정 가능


def load_counts_from_csv(csv_path):
    if not os.path.exists(csv_path):
        print(f"No CSV file: {csv_path}")
        sys.exit(1)

    counts_by_sev = Counter()

    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sev = (row.get("severity") or "").upper()
            try:
                count = int(row.get("count", 0))
            except ValueError:
                count = 0
            counts_by_sev[sev] += count

    return counts_by_sev


ALLOWED_ZAP_HIGH_MESSAGES = [
    'Server Leaks Version Information via "Server" HTTP Response Header Field',
    "CSP: Failure to Define Directive with No Fallback",
    "GET for POST",
]


def subtract_allowed_exceptions(detailed_csv_path, original_count):
    """
    ZAP HIGH 예외 + SonarCloud CRITICAL (staticfiles/admin/js) 예외를 차감한다.
    """
    if original_count <= 0:
        return original_count

    if not os.path.exists(detailed_csv_path):
        return original_count

    adjusted = original_count  # 여기서부터 차감

    with open(detailed_csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            tool = (row.get("tool") or "").lower()
            severity = (row.get("severity") or "").upper()
            message = row.get("message", "") or ""
            file_path = row.get("file", "") or ""

            # 1) ZAP HIGH 예외
            if (
                tool == "zap"
                and severity == "HIGH"
                and any(allowed in message for allowed in ALLOWED_ZAP_HIGH_MESSAGES)
            ):
                adjusted -= 1
                continue

            # 2) SonarCloud CRITICAL + staticfiles/admin/js 예외
            if (
                tool == "sonarcloud"
                and severity == "CRITICAL"
                and "staticfiles/admin/js" in file_path
            ):
                adjusted -= 1

    return max(adjusted, 0)


def main():
    counts_by_sev = load_counts_from_csv(CSV_PATH)
    print("[Quality Gate] 전체 severity 집계:", dict(counts_by_sev))

    blocking_total = 0
    for sev in BLOCKING_SEVERITIES:
        blocking_total += counts_by_sev.get(sev, 0)

    print(f"[Quality Gate] 차감 전 blocking_total = {blocking_total}")

    # 상세 CSV 기준으로 예외 이슈 차감
    blocking_total = subtract_allowed_exceptions(DETAILED_CSV_PATH, blocking_total)

    print(f"[Quality Gate] 예외 적용 후 blocking_total = {blocking_total}")

    if blocking_total > 0:
        print(f"❌ Quality Gate FAILED: {BLOCKING_SEVERITIES} Total = {blocking_total}")
        print("Please check regarding issues to deploy successfully!!!!!")
        sys.exit(1)
    else:
        print("✅ Quality Gate PASSED: No blocking severity (with allowed exceptions)")
        print("This version has no blocking vulnerabilities. It can be deployed right now ^^.")
        sys.exit(0)


if __name__ == "__main__":
    main()
