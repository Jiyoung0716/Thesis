import os
import json
from collections import Counter
import csv
import matplotlib.pyplot as plt

# GitHub Actions에서 download-artifact로 받은 파일들이 들어갈 경로
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
OUTPUT_DIR = os.path.join(BASE_DIR, "metrics_output")

os.makedirs(OUTPUT_DIR, exist_ok=True)


def load_tfsec():
    path = os.path.join(REPORTS_DIR, "tfsec-report", "tfsec.json")
    if not os.path.exists(path):
        print(f"[tfsec] 파일 없음: {path}")
        return Counter()

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    for r in data.get("results", []):
        sev = r.get("severity", "UNKNOWN")  # LOW / MEDIUM / HIGH ...
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
        sev = issue.get("severity", "UNKNOWN")  # BLOCKER / CRITICAL / MAJOR ...
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

    # ZAP JSON 구조: data["site"][...]["alerts"][...]["risk"]
    sites = data.get("site", data.get("sites", []))
    
    # riskcode 기준 매핑 (0~3)
    code_map = {
        "0": "INFO",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH",
    }
    
    for site in sites:
        for alert in site.get("alerts", []):
            # 1) 먼저 risk 필드 (예: "High", "Medium"...)
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
            elif riskcode is not None:
                sev = code_map.get(str(riskcode), "UNKNOWN")

            counts[sev] += 1

    print("[ZAP] severity counts:", dict(counts))
    return counts


def write_csv(all_tools_counts, csv_path):
    """
    all_tools_counts: { "tfsec": Counter(...), "sonarcloud": Counter(...), "zap": Counter(...) }
    """
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


def plot_bar(tool_name, counts):
    labels = list(counts.keys())
    values = [counts[k] for k in labels]

    if not labels:
        print(f"[{tool_name}] 데이터 없음, 그래프 스킵")
        return

    plt.figure()
    plt.bar(labels, values)
    plt.title(f"{tool_name} severity distribution")
    plt.xlabel("Severity")
    plt.ylabel("Count")
    out_path = os.path.join(OUTPUT_DIR, f"{tool_name}_severity.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[PNG] 저장 완료: {out_path}")


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

    # 도구별 그래프 생성
    plot_bar("tfsec", tfsec_counts)
    plot_bar("sonarcloud", sonar_counts)
    plot_bar("zap", zap_counts)

    print("\n[✓] metrics_output 디렉터리 생성 완료")
    
    # 3개 도구 전체 취약점 비교
    tools = ['SonarCloud', 'tfsec', 'ZAP']
    counts = [
        sum(sonar_counts.values()),
        sum(tfsec_counts.values()),
        sum(zap_counts.values()),
    ]

    plt.figure()
    plt.bar(tools, counts)
    plt.title("Security Findings by Tool")
    plt.ylabel("Finding Count")
    out_path = os.path.join(OUTPUT_DIR, "findings_by_tool.png")
    plt.savefig(out_path)
    plt.close()
    print(f"[PNG] 저장 완료: {out_path}")
    
    # --- 여기까지 도구별 그래프 생성 ---

    # 통합 severity Counter (세 도구 합산)
    combined_counts = Counter()
    combined_counts.update(tfsec_counts)
    combined_counts.update(sonar_counts)
    combined_counts.update(zap_counts)

    # 통합 severity 그래프
    if combined_counts:
        labels = list(combined_counts.keys())
        values = [combined_counts[k] for k in labels]

        plt.figure()
        plt.bar(labels, values)
        plt.title("Combined Severity Distribution (All Tools)")
        plt.xlabel("Severity")
        plt.ylabel("Total Findings")
        out_path = os.path.join(OUTPUT_DIR, "combined_severity.png")
        plt.savefig(out_path)
        plt.close()
        print(f"[PNG] 저장 완료: {out_path}")



if __name__ == "__main__":
    main()
