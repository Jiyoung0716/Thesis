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
        return Counter(), []

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    details = []
    
    for r in data.get("results", []):
        sev = r.get("severity", "UNKNOWN")
        rule_id = r.get("rule_id") or r.get("long_id")
        desc = r.get("description", "")

        loc = r.get("location", {}) or {}
        filename = loc.get("filename", "")
        start_line = loc.get("start_line") or loc.get("startLine")
        end_line = loc.get("end_line") or loc.get("endLine")

        counts[sev] += 1

        details.append({
            "tool": "tfsec",
            "severity": sev,
            "rule_id": rule_id,
            "message": desc,
            "target": filename,
            "location": f"{start_line}-{end_line}" if start_line else "",
        })

    print("[tfsec] severity counts:", dict(counts))
    return counts, details


def load_sonarcloud():
    path = os.path.join(REPORTS_DIR, "sonarcloud-report", "sonarcloud.json")
    if not os.path.exists(path):
        print(f"[SonarCloud] 파일 없음: {path}")
        return Counter(), []

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    details = []
    
    # component key -> 파일 경로 매핑
    comp_paths = {}
    for c in data.get("components", []):
        key = c.get("key")
        path_ = c.get("path") or c.get("name")
        if key:
            comp_paths[key] = path_
    
    for issue in data.get("issues", []):
        
        status = issue.get("status")
        if status in ("RESOLVED", "CLOSED"):
            continue
        
        sev = issue.get("severity", "UNKNOWN")
        rule = issue.get("rule", "")
        msg = issue.get("message", "")

        comp_key = issue.get("component")
        path_ = comp_paths.get(comp_key, comp_key)
        line = issue.get("line")

        counts[sev] += 1

        if line:
            target = f"{path_}:{line}"
        else:
            target = path_ or ""

        details.append({
            "tool": "sonarcloud",
            "severity": sev,
            "rule_id": rule,
            "message": msg,
            "target": target,
            "location": str(line) if line else "",
        })

    print("[SonarCloud] severity counts:", dict(counts))
    return counts, details

def _zap_determine_severity(alert, code_map):
    """ZAP alert로부터 severity 계산"""
    risk = alert.get("risk") or alert.get("riskdesc")
    riskcode = alert.get("riskcode")

    if isinstance(risk, str):
        r = risk.lower()
        if "high" in r:
            return "HIGH"
        if "medium" in r:
            return "MEDIUM"
        if "low" in r:
            return "LOW"
        if "inform" in r:
            return "INFO"

    if riskcode is not None:
        return code_map.get(str(riskcode), "UNKNOWN")

    return "UNKNOWN"


def _zap_get_alert_url(alert):
    """ZAP alert에서 대표 URL 하나 추출"""
    url = alert.get("url", "")
    inst = alert.get("instances") or []
    if inst and isinstance(inst, list):
        return inst[0].get("uri", url)
    return url

def load_zap():
    path = os.path.join(REPORTS_DIR, "zap-report", "report_json.json")
    if not os.path.exists(path):
        print(f"[ZAP] 파일 없음: {path}")
        return Counter(), []

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    details = []

    sites = data.get("site") or data.get("sites") or []

    code_map = {
        "0": "INFO",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH",
    }

    for site in sites:
        for alert in site.get("alerts") or []:
            name = alert.get("name", "")
            plugin_id = alert.get("pluginId", "")

            # 🔽 복잡한 로직 helper로 분리 → Cognitive Complexity 감소
            sev = _zap_determine_severity(alert, code_map)
            url = _zap_get_alert_url(alert)

            counts[sev] += 1

            details.append({
                "tool": "zap",
                "severity": sev,
                "rule_id": plugin_id,
                "message": name,
                "target": url,
                "location": "",
            })

    print("[ZAP] severity counts:", dict(counts))
    return counts, details

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
    
def write_detailed_csv(all_details, csv_path):
    """
    all_details: [{tool, severity, rule_id, message, target, location}, ...]
    """
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tool", "severity", "rule_id", "target", "location", "message"])
        for d in all_details:
            writer.writerow([
                d.get("tool", ""),
                d.get("severity", ""),
                d.get("rule_id", ""),
                d.get("target", ""),
                d.get("location", ""),
                d.get("message", "").replace("\n", " "),
            ])
    print(f"[CSV] 상세 저장 완료: {csv_path}")


# -------------------- 시각화 유틸 -------------------- #

# severity 순서 고정 (있으면 이 순서, 없으면 무시)
SEVERITY_ORDER = ["BLOCKER", "CRITICAL","MAJOR", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

# 색상 맵 (툴/그래프가 달라도 같은 severity면 같은 톤)
COLOR_MAP = {
    "BLOCKER": "#7f0000",
    "CRITICAL": "#d7301f",
    "MAJOR": "#fc4e2a",
    "HIGH": "#fc8d59",
    "MEDIUM": "#fdae61",
    "LOW": "#fee090",
    "INFO": "#e0f3f8",
    "UNKNOWN": "#cccccc",
}

# tfsec 전용 (파란 계열)
TFSEC_COLOR_MAP = {
    "HIGH": "#1f77b4",
    "MEDIUM": "#6baed6",
    "LOW": "#9ecae1",
    "INFO": "#c7e9f1",
    "UNKNOWN": "#d0d0d0",
}

# ZAP 전용 (초록 계열)
ZAP_COLOR_MAP = {
    "HIGH": "#2ca02c",
    "MEDIUM": "#74c476",
    "LOW": "#a1d99b",
    "INFO": "#c7e9c0",
    "UNKNOWN": "#d0d0d0",
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

    # 툴별 컬러 팔레트 선택
    if tool_name.lower() == "tfsec":
        palette = TFSEC_COLOR_MAP
    elif tool_name.lower() in ("zap", "owasp zap"):
        palette = ZAP_COLOR_MAP
    else:
        # 기본은 기존 severity 기반 팔레트 (SonarCloud 등)
        palette = COLOR_MAP

    colors = [palette.get(sev, "#999999") for sev in labels]

    plt.figure(figsize=(6, 4))

    # 막대 너비를 조금 줄임
    bars = plt.bar(labels, values, color=colors, width=0.5)

    # 타이틀을 굵게
    plt.title(f"{tool_name} severity distribution", fontweight="bold")
    plt.xlabel("Severity")
    plt.ylabel("Count")

    # y축 최대값 조정 (tfsec처럼 값이 1일 때 너무 위로 치솟지 않게)
    max_val = max(values)
    if max_val <= 1:
        ymax = 1.5
    elif max_val <= 2:
        ymax = 2.5
    else:
        ymax = max_val * 1.15  # 살짝 여유
    plt.ylim(0, ymax)

    # 막대 위에 숫자 표시 – y축 스케일에 맞게 위치 조정
    for bar, val in zip(bars, values):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + (ymax * 0.03),
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

    # 도구별 고정 색상
    tool_colors = ["#fc8d59", "#d7301f", "#91bfdb"]  # tfsec, sonarcloud, zap

    plt.figure(figsize=(10, 4))  # 가로로 배치

    # ---------------------
    # (1) Left: Bar Chart
    # ---------------------
    plt.subplot(1, 2, 1)
    bars = plt.bar(tools, counts, color=tool_colors)
    plt.title("Security Findings by Tool (Bar)")
    plt.ylabel("Finding Count")

    for bar, val in zip(bars, counts):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.2,
            str(val),
            ha="center",
            va="bottom",
            fontsize=9,
        )

    # ---------------------
    # (2) Right: Pie Chart
    # ---------------------
    plt.subplot(1, 2, 2)
    plt.pie(
        counts,
        labels=tools,
        autopct="%1.1f%%",
        startangle=140,
        colors=tool_colors,
        textprops={"fontsize": 10},
    )
    plt.title("Security Findings by Tool (Pie)")

    # ---------------------
    # Export
    # ---------------------
    out_path = os.path.join(OUTPUT_DIR, "findings_by_tool.png")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

    print(f"[PNG] 저장 완료: {out_path}")

# -------------------- main -------------------- #

def main():
    tfsec_counts, tfsec_details = load_tfsec()
    sonar_counts, sonar_details = load_sonarcloud()
    zap_counts, zap_details = load_zap()

    all_tools = {
        "tfsec": tfsec_counts,
        "sonarcloud": sonar_counts,
        "zap": zap_counts,
    }

    # CSV 생성
    csv_path = os.path.join(OUTPUT_DIR, "metrics.csv")
    write_csv(all_tools, csv_path)
    
    # 상세용 CSV
    detailed_path = os.path.join(OUTPUT_DIR, "metrics_detailed.csv")
    all_details = tfsec_details + sonar_details + zap_details
    write_detailed_csv(all_details, detailed_path)

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
