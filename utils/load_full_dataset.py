import pandas as pd
import zlib
import base64
import sys
from typing import Any


def _safe_base64_zlib_decode(value: Any) -> str | None:
    """尝试对传入的字符串进行 base64 解码并 zlib 解压，失败返回 None。

    返回 utf-8 解码的字符串（errors='replace'），以便不会因为单个非法字节抛出异常。
    """
    if value is None:
        return None
    try:
        # 如果已经是 bytes，跳过 base64 解码
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
        else:
            # 有些行可能不是字符串
            v = str(value)
            raw = base64.b64decode(v)
        decompressed = zlib.decompress(raw)
        return decompressed.decode("utf-8", errors="replace")
    except Exception as e:
        # 记录但不抛出异常，保持 dataframe 完成读取
        print(f"[warn] payload decode failed: {e}", file=sys.stderr)
        return None


def _decode_cve_labels(value: Any) -> list:
    """把空格分隔的 cve 标签字符串转换为列表；对 None/NaN 返回空列表。"""
    try:
        if value is None or (isinstance(value, float) and pd.isna(value)):
            return []
        s = str(value)
        # 多个空格会产生空字符串，过滤掉
        return [xx for xx in s.split(" ") if xx]
    except Exception:
        return []


def load_full_dataset(file_path: str) -> pd.DataFrame:
    """加载完整数据并返回增强过的 DataFrame。

    - 支持当输入缺少 `payload` 或 `cve_labels` 字段时仍可工作。
    - payload 解码失败会被捕获并记录到 stderr，对应单元格值为 None。
    """
    # 尝试按行读取 JSON（最常见的场景），若失败再尝试非行格式
    try:
        df = pd.read_json(file_path, orient="records", lines=True)
    except ValueError:
        df = pd.read_json(file_path, orient="records")

    # payload 解码（如果列存在）
    if "payload" in df.columns:
        df["payload_decoded"] = df["payload"].apply(_safe_base64_zlib_decode)
    else:
        print("[warn] 'payload' 列未在输入数据中找到；跳过 payload 解码", file=sys.stderr)
        df["payload_decoded"] = [None for _ in range(len(df))]

    # cve_labels 解码到列表形式（兼容缺失或 NaN）
    if "cve_labels" in df.columns:
        df["cve_labels_decoded"] = df["cve_labels"].apply(_decode_cve_labels)
    else:
        # 尝试常见替代列名
        alt = None
        for candidate in ("labels", "cves", "cve_label"):
            if candidate in df.columns:
                alt = candidate
                break
        if alt:
            print(f"[info] 'cve_labels' 列未找到，使用替代列 '{alt}' 进行解析", file=sys.stderr)
            df["cve_labels_decoded"] = df[alt].apply(_decode_cve_labels)
        else:
            print("[warn] 'cve_labels' 列未在输入数据中找到；将使用空列表占位", file=sys.stderr)
            df["cve_labels_decoded"] = [ [] for _ in range(len(df)) ]

    return df


if __name__ == "__main__":
    # 默认路径（与原脚本保持一致），但使用 __main__ 保护以便模块被导入时不会立即执行
    default_input = "../data/test_payload.json"
    default_output = "../data/test_payload.csv"

    try:
        df = load_full_dataset(default_input)
    except FileNotFoundError:
        print(f"输入文件 {default_input} 未找到，请传入正确路径。", file=sys.stderr)
        raise

    # 确保存在 id 列：如果没有，尝试用常见替代列或生成连续 id
    if "id" not in df.columns:
        for candidate in ("uuid", "uid", "doc_id", "index"):
            if candidate in df.columns:
                df["id"] = df[candidate]
                break
        else:
            # 生成一个简单的连续 id
            df["id"] = range(len(df))

    # 只保留用户要求的三列：id, payload_decoded, cve_labels_decoded
    # 说明：你请求的列名中有拼写 'cve_lables_decoded'，这里我使用代码中一致的
    # 名称 'cve_labels_decoded'。如果你确实要不同拼写，请告诉我，我会改为你指定的名称。
    keep_cols = ["id", "payload_decoded", "cve_labels_decoded"]
    # 如果某些列不存在，先用占位列补齐，以保证输出 CSV 包含这三个列头
    for col in keep_cols:
        if col not in df.columns:
            if col == "payload_decoded":
                df[col] = None
            elif col == "cve_labels_decoded":
                df[col] = [[] for _ in range(len(df))]
            else:
                df[col] = None

    out_df = df[keep_cols]
    out_df.to_csv(default_output, index=False)
    print(f"已写出 {len(out_df)} 行到 {default_output}，仅保留列: {', '.join(keep_cols)}")

