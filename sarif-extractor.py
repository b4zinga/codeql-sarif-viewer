#!/usr/bin/env python3
"""
SARIF 漏洞提取工具
"""

import json
import os
from typing import Dict, List, Any
from pathlib import Path
from urllib.parse import urlparse


class SarifVulnerabilityExtractor:
    """SARIF 漏洞提取器"""

    def __init__(
        self, sarif_file: str, source_root: str = None, with_line_number: bool = False
    ):
        self.sarif_file = sarif_file
        self.with_line_number = with_line_number
        if source_root:
            self.source_root = Path(source_root)
        else:
            self.source_root = Path(sarif_file).parent

        with open(sarif_file, "r", encoding="utf-8") as f:
            self.sarif_data = json.load(f)

    @staticmethod
    def _normalize_path(uri: str) -> str:
        """统一路径格式，去掉 file:/// 前缀"""
        if uri.startswith("file://"):
            parsed = urlparse(uri)
            return parsed.path.lstrip("/")
        return uri

    def extract_vulnerabilities(self) -> List[Dict[str, Any]]:
        vulnerabilities = []
        for run in self.sarif_data.get("runs", []):
            artifacts = run.get("artifacts", [])
            for result in run.get("results", []):
                vulns = self._extract_vulnerability(result, artifacts)
                if vulns:
                    vulnerabilities.extend(vulns)
        return vulnerabilities

    def _extract_vulnerability(
        self, result: Dict, artifacts: List[Dict]
    ) -> List[Dict[str, Any]]:
        rule_id = result.get("ruleId", "")
        message = result.get("message", {}).get("text", "")
        level = result.get("level", "warning")

        vulnerabilities = []
        code_flows = result.get("codeFlows", [])

        if code_flows:
            # 每个 codeFlow 单独生成一个漏洞实例
            for code_flow in code_flows:
                data_flow = self._extract_data_flow_from_codeflow(result, code_flow)
                files = self._collect_files(data_flow, artifacts)
                vulnerabilities.append(
                    {
                        "rule_id": rule_id,
                        "message": message,
                        "level": level,
                        "data_flow": data_flow,
                        "files": files,
                    }
                )
        else:
            data_flow = self._extract_data_flow_from_locations(result)
            files = self._collect_files(data_flow, artifacts)
            vulnerabilities.append(
                {
                    "rule_id": rule_id,
                    "message": message,
                    "level": level,
                    "data_flow": data_flow,
                    "files": files,
                }
            )

        return vulnerabilities

    def _extract_data_flow_from_locations(self, result: Dict) -> List[Dict[str, Any]]:
        data_flow = []
        locations = result.get("locations", [])
        for idx, loc in enumerate(locations):
            step = self._extract_location_info(loc.get("physicalLocation", {}), idx + 1)
            if step:
                data_flow.append(step)
        return data_flow

    def _extract_data_flow_from_codeflow(
        self, result: Dict, code_flow: Dict
    ) -> List[Dict[str, Any]]:
        data_flow = []

        # 先加 relatedLocations 作为源头(只加第一个有消息的)
        related_locations = result.get("relatedLocations", [])
        if related_locations:
            # 只添加第一个 relatedLocation (通常是漏洞源头)
            rel = related_locations[0]
            step = self._extract_location_info(rel.get("physicalLocation", {}), 1)
            if step:
                step["message"] = rel.get("message", {}).get("text", "")
                data_flow.append(step)

        # 再加 threadFlows 按顺序
        for thread_flow in code_flow.get("threadFlows", []):
            for idx, location_obj in enumerate(
                thread_flow.get("locations", []), start=len(data_flow) + 1
            ):
                step = self._extract_location_info(
                    location_obj.get("location", {}).get("physicalLocation", {}), idx
                )
                if step:
                    step["message"] = (
                        location_obj.get("location", {})
                        .get("message", {})
                        .get("text", "")
                    )
                    data_flow.append(step)

        return data_flow

    def _extract_location_info(
        self, physical_location: Dict, step: int
    ) -> Dict[str, Any]:
        if not physical_location:
            return None
        artifact_location = physical_location.get("artifactLocation", {})
        region = physical_location.get("region", {})
        file_path = self._normalize_path(artifact_location.get("uri", ""))
        return {
            "step": step,
            "file": file_path,
            "start_line": region.get("startLine", 0),
            "end_line": region.get("endLine", region.get("startLine", 0)),
            "start_column": region.get("startColumn", 0),
            "end_column": region.get("endColumn", 0),
        }

    def _collect_files(
        self, data_flow: List[Dict], artifacts: List[Dict]
    ) -> List[Dict[str, str]]:
        files_dict = {}
        for step in data_flow:
            file_path = step.get("file", "")
            if file_path and file_path not in files_dict:
                files_dict[file_path] = None

        artifact_map = {}
        for artifact in artifacts:
            uri = self._normalize_path(artifact.get("location", {}).get("uri", ""))
            content = artifact.get("contents", {}).get("text", "")
            if uri and content:
                artifact_map[uri] = content

        result_files = []
        for file_path in files_dict.keys():
            content = None
            if file_path in artifact_map:
                content = artifact_map[file_path]
            else:
                full_path = self.source_root / file_path
                if full_path.exists():
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            content = f.read()
                    except Exception as e:
                        content = f"[无法读取文件: {str(e)}]"
                else:
                    content = "[文件不存在]"
            result_files.append({"file": file_path, "content": content or "[无内容]"})
        return result_files

    def save_to_json(
        self, output_file: str, vulnerabilities: List[Dict] = None, pretty: bool = True
    ):
        if vulnerabilities is None:
            vulnerabilities = self.extract_vulnerabilities()
        with open(output_file, "w", encoding="utf-8") as f:
            if pretty:
                json.dump(vulnerabilities, f, indent=2, ensure_ascii=False)
            else:
                json.dump(vulnerabilities, f, ensure_ascii=False, separators=(",", ":"))
        print(f"✓ 已保存 {len(vulnerabilities)} 个漏洞到 {output_file}")

    def save_to_text(self, output_file: str, vulnerabilities: List[Dict] = None):
        if vulnerabilities is None:
            vulnerabilities = self.extract_vulnerabilities()
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("SARIF 漏洞分析报告\n")
            f.write(f"总漏洞数: {len(vulnerabilities)}\n")
            f.write("=" * 80 + "\n\n")
            for idx, vuln in enumerate(vulnerabilities, 1):
                f.write(f"\n{'=' * 80}\n漏洞 #{idx}\n{'=' * 80}\n\n")
                f.write(f"规则 ID:    {vuln['rule_id']}\n")
                f.write(f"严重程度:   {vuln['level']}\n")
                f.write(f"描述:       {vuln['message']}\n\n")
                f.write(
                    f"{'─' * 80}\n数据流路径 ({len(vuln['data_flow'])} 个步骤)\n{'─' * 80}\n\n"
                )
                for step in vuln["data_flow"]:
                    location = (
                        f"{step['file']}:{step['start_line']}:{step['start_column']}"
                    )
                    f.write(f"  [{step['step']}] {location}\n")
                    if step.get("message"):
                        f.write(f"      → {step['message']}\n")
                f.write(
                    f"\n{'─' * 80}\n涉及的文件 ({len(vuln['files'])} 个)\n{'─' * 80}\n\n"
                )
                for file_info in vuln["files"]:
                    lines = (
                        file_info["content"].count("\n") + 1
                        if file_info["content"]
                        else 0
                    )
                    f.write(f"  • {file_info['file']} ({lines} 行)\n")

                # 输出文件内容（可选行号）
                f.write(f"\n{'─' * 80}\n文件内容\n{'─' * 80}\n\n")
                for file_info in vuln["files"]:
                    f.write(f">>> {file_info['file']}\n")
                    f.write(f"{'─' * 80}\n")
                    lines = file_info["content"].splitlines()
                    if self.with_line_number:
                        width = len(str(len(lines)))  # 行号宽度
                        for i, line in enumerate(lines, start=1):
                            f.write(f"{str(i).rjust(width)} | {line}\n")
                    else:
                        for line in lines:
                            f.write(f"{line}\n")
                    f.write(f"{'─' * 80}\n\n")
        print(f"✓ 已保存 {len(vulnerabilities)} 个漏洞到 {output_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="从 CodeQL SARIF 报告中提取漏洞链路和源代码"
    )
    parser.add_argument("sarif_file", help="SARIF 文件路径")
    parser.add_argument("-o", "--output", help="输出文件路径")
    parser.add_argument("-s", "--source-root", help="源代码根目录")
    parser.add_argument(
        "-f", "--format", choices=["json", "json-compact", "text"], default="json"
    )
    parser.add_argument(
        "-n", "--with-line-number", action="store_true", help="输出文件内容时带行号"
    )
    args = parser.parse_args()

    extractor = SarifVulnerabilityExtractor(
        args.sarif_file, args.source_root, with_line_number=args.with_line_number
    )
    vulnerabilities = extractor.extract_vulnerabilities()

    if args.output:
        output_file = args.output
    else:
        base_name = os.path.splitext(args.sarif_file)[0]
        if args.format == "text":
            output_file = f"{base_name}_vulnerabilities.txt"
        elif args.format == "json-compact":
            output_file = f"{base_name}_vulnerabilities_compact.json"
        else:
            output_file = f"{base_name}_vulnerabilities.json"

    if args.format == "text":
        extractor.save_to_text(output_file, vulnerabilities)
    elif args.format == "json-compact":
        extractor.save_to_json(output_file, vulnerabilities, pretty=False)
    else:
        extractor.save_to_json(output_file, vulnerabilities, pretty=True)

    print("\n统计信息:")
    print(f"  总漏洞数: {len(vulnerabilities)}")
    rule_counts = {}
    for vuln in vulnerabilities:
        rule_counts[vuln["rule_id"]] = rule_counts.get(vuln["rule_id"], 0) + 1
    print("  规则分布:")
    for rule_id, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {rule_id}: {count}")


if __name__ == "__main__":
    main()
