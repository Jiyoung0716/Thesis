import os
import json
from collections import Counter
import csv
import matplotlib
matplotlib.use("Agg")  # GitHub Actions 같은 headless 환경용
import matplotlib.pyplot as plt

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
OUTPUT_DIR = os.path.join(BASE_DIR, "metrics_output")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------------------- 데이터 로더 -------------------- #

def load_tfsec():
    path = os.path.join(REPORTS_DIR, "tfsec-report", "tfsec.json")
    if not os.path.exists(path):
        print(f"[tfsec] 파일 없음: {path}")
        return Counter()

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    for r in data.get("results", []):
        sev = r.get("severity", "UNKNOWN")
        counts[sev] += 1

    print("[tfsec] severity counts:", dict(counts))
    return counts


def load_sonarcloud():
    path = os.path.join(REPORTS_DIR, "sonarcloud-report", "sonarcloud.json")
    if not os.path.exists(path):
        print(f"[SonarCloud] 파일 없음: {path}")
        return Counter()

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    for issue in data.get("issues", []):
        sev = issue.get("severity", "UNKNOWN")
        counts[sev] += 1

    print("[SonarCloud] severity counts:", dict(counts))
    return counts


def load_zap():
    path = os.path.join(REPORTS_DIR, "zap-report", "report_json.json")
    if not os.path.exists(path):
        print(f"[ZAP] 파일 없음: {path}")
        return Counter()

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()

    sites = data.get("site", data.get("sites", []))
    code_map = {
        "0": "INFO",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH",
    }

    for site in sites:
        for alert in site.get("alerts", []):
            risk = alert.get("risk") or alert.get("riskdesc")
            riskcode = alert.get("riskcode")

            sev = "UNKNOWN"

            if isinstance(risk, str):
                r = risk.lower()
                if "high" in r:
                    sev = "HIGH"
                elif "medium" in r:
                    sev = "MEDIUM"
                elif "low" in r:
                    sev = "LOW"
                elif "inform" in r:
                    sev = "INFO"
            if sev == "UNKNOWN" and riskcode is not None:
                sev = code_map.get(str(riskcode), "UNKNOWN")

            counts[sev] += 1

    print("[ZAP] severity counts:", dict(counts))
    return counts


# -------------------- CSV -------------------- #

def write_csv(all_tools_counts, csv_path):
    severities = set()
    for c in all_tools_counts.values():
        severities.update(c.keys())
    severities = sorted(severities)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tool", "severity", "count"])

        for tool, counts in all_tools_counts.items():
            for sev in severities:
                writer.writerow([tool, sev, counts.get(sev, 0)])

    print(f"[CSV] 저장 완료: {csv_path}")


# -------------------- 시각화 유틸 -------------------- #

# severity 순서 고정 (있으면 이 순서, 없으면 무시)
SEVERITY_ORDER = ["BLOCKER", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

# 색상 맵 (툴/그래프가 달라도 같은 severity면 같은 톤)
COLOR_MAP = {
    "BLOCKER": "#7f0000",
    "CRITICAL": "#d7301f",
    "HIGH": "#fc8d59",
    "MEDIUM": "#fdae61",
    "LOW": "#fee090",
    "INFO": "#e0f3f8",
    "UNKNOWN": "#cccccc",
}

plt.style.use("ggplot")


def ordered_items(counts: Counter):
    """SEVERITY_ORDER 기준으로 정렬된 (label, value) 리스트."""
    labels = []
    values = []
    for sev in SEVERITY_ORDER:
        if sev in counts:
            labels.append(sev)
            values.append(counts[sev])
    return labels, values


def plot_bar(tool_name, counts):
    labels, values = ordered_items(counts)
    if not labels:
        print(f"[{tool_name}] 데이터 없음, 그래프 스킵")
        return

    colors = [COLOR_MAP.get(sev, "#999999") for sev in labels]

    plt.figure(figsize=(6, 4))
    bars = plt.bar(labels, values, color=colors)
    plt.title(f"{tool_name} severity distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")

    # 막대 위에 숫자 표시
    for bar, val in zip(bars, values):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            str(val),
            ha="center",
            va="bottom",
            fontsize=9,
        )

    out_path = os.path.join(OUTPUT_DIR, f"{tool_name}_severity.png")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    print(f"[PNG] 저장 완료: {out_path}")


def plot_combined_severity(all_tools_counts):
    combined = Counter()
    for c in all_tools_counts.values():
        combined.update(c)

    labels, values = ordered_items(combined)
    if not labels:
        print("[combined] 데이터 없음, 그래프 스킵")
        return

    colors = [COLOR_MAP.get(sev, "#999999") for sev in labels]

    plt.figure(figsize=(6, 4))
    bars = plt.bar(labels, values, color=colors)
    plt.title("Combined Severity Distribution (All Tools)")
    plt.xlabel("Severity")
    plt.ylabel("Total Findings")

    for bar, val in zip(bars, values):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            str(val),
            ha="center",
            va="bottom",
            fontsize=9,
        )

    out_path = os.path.join(OUTPUT_DIR, "combined_severity.png")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    print(f"[PNG] 저장 완료: {out_path}")


def plot_findings_by_tool(all_tools_counts):
    tools = list(all_tools_counts.keys())
    counts = [sum(c.values()) for c in all_tools_counts.values()]

    plt.figure(figsize=(6, 4))
    bars = plt.bar(tools, counts)
    plt.title("Security Findings by Tool")
    plt.ylabel("Finding Count")

    for bar, val in zip(bars, counts):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            str(val),
            ha="center",
            va="bottom",
            fontsize=9,
        )

    out_path = os.path.join(OUTPUT_DIR, "findings_by_tool.png")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    print(f"[PNG] 저장 완료: {out_path}")


# -------------------- main -------------------- #

def main():
    tfsec_counts = load_tfsec()
    sonar_counts = load_sonarcloud()
    zap_counts = load_zap()

    all_tools = {
        "tfsec": tfsec_counts,
        "sonarcloud": sonar_counts,
        "zap": zap_counts,
    }

    # CSV 생성
    csv_path = os.path.join(OUTPUT_DIR, "metrics.csv")
    write_csv(all_tools, csv_path)

    # 개별 그래프
    plot_bar("sonarcloud", sonar_counts)
    plot_bar("tfsec", tfsec_counts)
    plot_bar("zap", zap_counts)

    # 통합 그래프
    plot_combined_severity(all_tools)
    plot_findings_by_tool(all_tools)

    print("\n[✓] metrics_output 디렉터리 생성 완료")


if __name__ == "__main__":
    main()
