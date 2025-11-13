#!/usr/bin/env python3
"""
转换规则：
- 表头：去掉每个字段名外层的双引号 -> id,payload_decoded,cve_labels
- 数据行：仅去掉第1列与最后1列外层的双引号；中间列保持原有CSV转义/内容（按需求保留）。

使用方式：
  1) 指定输入输出文件
	 python utils/preprocess.py --in input.csv --out output.csv
  2) 管道
	 cat input.csv | python utils/preprocess.py > output.csv

注意：
- 本脚本假定至少3列（示例为 id, payload_decoded, cve_labels）。
- 若多于3列，将仅对第1列和最后1列去除外层引号，其余列按CSV规则保持（会按CSV规范重新转义）。
"""

from __future__ import annotations

import sys
import io
import argparse
import csv
from typing import List


def _set_csv_field_size_limit(limit: int | None = None) -> None:
	"""设置 csv 字段大小限制。默认尽可能增大（到 sys.maxsize 或 2**31-1）。"""
	try:
		if limit is None or limit <= 0:
			# 优先尝试 sys.maxsize；如溢出则退回 2**31-1
			try:
				csv.field_size_limit(sys.maxsize)
			except OverflowError:
				csv.field_size_limit(2**31 - 1)
		else:
			csv.field_size_limit(limit)
	except Exception as e:
		# 不能因设置失败阻断主流程
		print(f"[warn] failed to set csv.field_size_limit: {e}", file=sys.stderr)


def quote_csv_field(value: str) -> str:
	"""返回单个字段的CSV文本（不含换行）。
	用于在保持CSV正确性的前提下，尽量不改变字段内容的转义语义。
	"""
	buf = io.StringIO()
	w = csv.writer(buf, delimiter=",", quotechar='"', lineterminator="\n", quoting=csv.QUOTE_MINIMAL, doublequote=True)
	w.writerow([value])
	out = buf.getvalue()
	# 去掉 writerow 写入的换行
	return out[:-1]


def quote_csv_field_always(value: str) -> str:
	"""返回强制带双引号的CSV字段文本（不含换行）。
	使用 QUOTE_ALL 以保证外层始终有引号。
	"""
	buf = io.StringIO()
	w = csv.writer(
		buf,
		delimiter=",",
		quotechar='"',
		lineterminator="\n",
		quoting=csv.QUOTE_ALL,
		doublequote=True,
	)
	w.writerow([value])
	out = buf.getvalue()
	return out[:-1]


def _row_to_csv_line(row: List[str], is_header: bool, *, enforce_quote_second: bool = False) -> str:
	"""按规则把一行转换为目标 CSV 文本（带结尾换行）。"""
	if is_header:
		# 表头：去掉双引号（csv.reader 解析后字段已无外层引号），直接连接
		return ",".join(row) + "\n"

	if not row:
		return "\n"

	# 第1列不加引号；第2列强制保留引号（如果 enforce_quote_second=True）；
	# 中间列（除最后1列外）按 CSV 规范最小化引号；最后1列按 CSV 规范最小化引号（含逗号/引号/换行时会自动加引号）。
	n = len(row)
	if n == 1:
		return f"{row[0]}\n"
	if n == 2:
		first = row[0]
		second = quote_csv_field_always(row[1]) if enforce_quote_second else quote_csv_field(row[1])
		return f"{first},{second}\n"

	first = row[0]
	second = row[1]
	middle_cols: List[str] = row[2:-1]
	last_raw = row[-1]

	out_parts: List[str] = [first]
	out_parts.append(quote_csv_field_always(second) if enforce_quote_second else quote_csv_field(second))
	for mid in middle_cols:
		out_parts.append(quote_csv_field(mid))
	# 最后一列：采用最小化引号（必要时加引号），避免 CSV 解析错误
	out_parts.append(quote_csv_field(last_raw))
	return ",".join(out_parts) + "\n"


def _build_part_name(base: str, index: int) -> str:
	# base.csv -> base.part{index}.csv ；否则 base -> base.part{index}.csv
	if base.lower().endswith(".csv"):
		return f"{base[:-4]}.part{index}.csv"
	return f"{base}.part{index}.csv"


def process_rows(
	reader: csv.reader,
	writer: io.TextIOBase,
	*,
	batch_size: int = 0,
	out_path: str | None = None,
	id_start: int = 0,
	enforce_quote_second: bool = True,
) -> None:
	"""写出所有行；可选分批输出。

	- 当 batch_size <= 0：写到单一 writer。
	- 当 batch_size > 0：要求 out_path 非空，输出为 out_path.part{n}.csv，每个分片带表头且包含至多 batch_size 条数据行。
	"""
	row_idx = 0
	header_line: str | None = None

	current_id = id_start

	if batch_size <= 0:
		# 单文件模式
		for row in reader:
			row_idx += 1
			is_header = (row_idx == 1)
			if is_header:
				line = _row_to_csv_line(row, True)
			else:
				# 覆盖第1列为顺序 id
				row = list(row)
				row[0] = str(current_id)
				current_id += 1
				line = _row_to_csv_line(row, False, enforce_quote_second=enforce_quote_second)
			writer.write(line)
		return

	# 分批模式
	if not out_path:
		raise ValueError("batch_size > 0 时必须提供 --out 作为输出基名")

	part_index = 0
	current_rows = 0  # 当前分片内的数据行计数（不含表头）
	current_file: io.TextIOBase | None = None

	def open_next_file() -> io.TextIOBase:
		nonlocal part_index, current_rows
		part_index += 1
		current_rows = 0
		fname = _build_part_name(out_path, part_index)
		f = open(fname, "w", encoding="utf-8", newline="")
		# 写表头
		assert header_line is not None
		f.write(header_line)
		return f

	for row in reader:
		row_idx += 1
		is_header = (row_idx == 1)
		if is_header:
			line = _row_to_csv_line(row, True)
			# 记录标准化后的表头（带换行）
			header_line = line
			continue

		# 数据行：按 batch 切分
		if current_file is None or current_rows >= batch_size:
			if current_file is not None:
				current_file.close()
			current_file = open_next_file()
		# 覆盖第1列为顺序 id
		row = list(row)
		row[0] = str(current_id)
		current_id += 1
		line = _row_to_csv_line(row, False, enforce_quote_second=enforce_quote_second)
		current_file.write(line)
		current_rows += 1

	# 关闭最后一个分片
	if current_file is not None:
		current_file.close()



def main(argv: List[str] | None = None) -> int:
	parser = argparse.ArgumentParser(description="按规则移除CSV中表头与特定列的外层双引号")
	parser.add_argument("--in", dest="in_path", help="输入CSV路径；缺省为stdin")
	parser.add_argument("--out", dest="out_path", help="输出CSV路径；缺省为stdout")
	parser.add_argument("--csv-limit", dest="csv_limit", type=int, default=0, help="csv.field_size_limit，0 表示自动最大")
	parser.add_argument("--batch-size", dest="batch_size", type=int, default=0, help="按数据行数分批写出；0 表示不分批")
	parser.add_argument("--id-start", dest="id_start", type=int, default=0, help="第一列id的起始值（顺序编号），默认0")
	args = parser.parse_args(argv)

	# 提升 csv 字段大小限制，避免 large field 错误
	_set_csv_field_size_limit(args.csv_limit)

	# 以 newline='' 打开，交由 csv 模块处理换行
	if args.in_path:
		infile = open(args.in_path, "r", encoding="utf-8", newline="")
		close_in = True
	else:
		infile = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", newline="")
		close_in = False

	if args.out_path:
		outfile = open(args.out_path, "w", encoding="utf-8", newline="")
		close_out = True
	else:
		# 直接写 stdout；注意不要包裹 TextIOWrapper 以免重复换行处理
		outfile = sys.stdout
		close_out = False

	try:
		reader = csv.reader(infile, delimiter=",", quotechar='"', doublequote=True)
		if args.batch_size and args.batch_size > 0:
			if not args.out_path:
				print("[error] 使用 --batch-size 时必须指定 --out 作为输出基名", file=sys.stderr)
				return 2
			# 分批输出到多个文件；此时忽略单一 outfile
			process_rows(reader, outfile, batch_size=args.batch_size, out_path=args.out_path, id_start=args.id_start, enforce_quote_second=True)
		else:
			process_rows(reader, outfile, id_start=args.id_start, enforce_quote_second=True)
	finally:
		if close_in:
			infile.close()
		if close_out:
			outfile.close()

	return 0


if __name__ == "__main__":
	sys.exit(main())

