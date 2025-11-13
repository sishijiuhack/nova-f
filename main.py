from __future__ import annotations

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Dict, List, Sequence

import faiss
import numpy as np
import pandas as pd

from src import build_faiss as build_mod
from src import preprocess as preprocess_mod
from src import search_faiss as search_mod


def configure_logging(verbose: bool) -> None:
	"""Configure root logger for the pipeline."""
	level = logging.DEBUG if verbose else logging.INFO
	logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(message)s")


def preprocess_training_data(
	train_path: Path,
	output_path: Path,
	*,
	payload_column: str,
	id_column: str,
	overwrite: bool,
) -> Path:
	"""Clean raw training data and persist the normalized dataset."""
	if output_path.exists() and not overwrite:
		logging.info("检测到已有清洗文件，跳过预处理: %s", output_path)
		return output_path

	logging.info("开始加载训练数据: %s", train_path)
	df = pd.read_csv(train_path)
	logging.info("训练数据加载完成，共 %d 行", len(df))

	processed = preprocess_mod.preprocess_dataframe(
		df,
		payload_column=payload_column,
		id_column=id_column,
	)

	output_path.parent.mkdir(parents=True, exist_ok=True)
	processed.to_csv(output_path, index=False)
	logging.info("已写出清洗后的训练数据: %s", output_path)
	return output_path


def preprocess_test_data(
	test_path: Path,
	output_path: Path,
	*,
	payload_column: str,
	id_column: str,
	overwrite: bool,
) -> Path:
	"""Clean raw test data and persist the normalized dataset."""
	if output_path.exists() and not overwrite:
		logging.info("检测到已有清洗测试文件，跳过预处理: %s", output_path)
		return output_path

	logging.info("开始加载测试数据: %s", test_path)
	df = pd.read_csv(test_path)
	logging.info("测试数据加载完成，共 %d 行", len(df))

	processed = preprocess_mod.preprocess_dataframe(
		df,
		payload_column=payload_column,
		id_column=id_column,
	)
	processed = processed.drop(columns=["cve_labels"], errors="ignore")

	output_path.parent.mkdir(parents=True, exist_ok=True)
	processed.to_csv(output_path, index=False)
	logging.info("已写出清洗后的测试数据: %s", output_path)
	return output_path


def build_vector_store(
	clean_train_path: Path,
	store_dir: Path,
	*,
	model_path: str,
	device: str | None,
	batch_size: int,
	overwrite: bool,
) -> tuple[Path, Path]:
	"""Create (or reuse) the FAISS index and metadata."""
	index_path = store_dir / "faiss.index"
	meta_path = store_dir / "meta.json"

	store_dir.mkdir(parents=True, exist_ok=True)

	if index_path.exists() and meta_path.exists() and not overwrite:
		logging.info("检测到现有索引与元数据，跳过索引重建: %s", store_dir)
		return index_path, meta_path

	if overwrite:
		logging.info("覆盖模式开启，将清理输出目录: %s", store_dir)
		for item in store_dir.iterdir():
			if item.is_file():
				item.unlink()

	payloads, ids, label_lists = build_mod.load_dataset(
		clean_train_path,
		payload_column="payload_clean",
		id_column="id",
	)

	model = build_mod.load_sentence_encoder(model_path, device)
	vectors = build_mod.embed_texts(
		model,
		payloads,
		batch_size=max(1, batch_size),
		desc="生成训练向量",
	)

	npy_path = store_dir / "train_embeddings.npy"
	np.save(npy_path, vectors)
	logging.info("训练向量已保存: %s", npy_path)

	index_path = build_mod.build_faiss_index(
		vectors,
		store_dir=store_dir,
		index_name="faiss.index",
	)

	meta: Dict[str, Sequence] = {
		"ids": ids,
		"cve_labels": label_lists,
		"vector_file": npy_path.name,
		"index_file": index_path.name,
		"payload_column": "payload_clean",
		"id_column": "id",
		"embedding_model": model_path,
		"created_at": datetime.now(tz=UTC).isoformat(),
	}
	meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
	logging.info("索引元数据已保存: %s", meta_path)

	return index_path, meta_path


def label_test_payloads(
	test_path: Path,
	store_dir: Path,
	output_path: Path,
	*,
	payload_column: str,
	id_column: str,
	model_path: str | None,
	device: str | None,
	batch_size: int,
	top_k: int,
	max_candidates: int,
	base_threshold: float,
	high_confidence: float,
	medium_confidence: float,
	second_gap: float,
	third_gap: float,
	search_batch_size: int,
	reuse_cache: bool,
) -> Path:
	"""Generate CVE predictions for the provided test dataset."""
	index_path = store_dir / "faiss.index"
	meta_path = store_dir / "meta.json"
	cache_emb_path = store_dir / "test_embeddings.npy"
	cache_meta_path = store_dir / "test_cache_meta.json"

	if not index_path.exists() or not meta_path.exists():
		raise FileNotFoundError("缺少索引或元数据，请先完成索引构建步骤")

	meta: Dict[str, Sequence] = json.loads(meta_path.read_text(encoding="utf-8"))
	train_ids = list(meta.get("ids", []))
	raw_train_labels = meta.get("cve_labels", [])
	if not train_ids or not raw_train_labels:
		raise ValueError("元数据缺少 ids 或 cve_labels 信息，无法执行检索")

	train_labels: List[List[str]] = [
		preprocess_mod.normalize_cve_labels(labels) for labels in raw_train_labels
	]

	index = faiss.read_index(str(index_path))

	payloads, test_ids = search_mod.load_test_payloads(test_path, payload_column, id_column)

	model_name = model_path or meta.get("embedding_model")
	if not model_name:
		raise ValueError("无法确定嵌入模型，请在参数或元数据中指定 embedding_model")

	test_vectors: np.ndarray | None = None
	if reuse_cache and cache_emb_path.exists() and cache_meta_path.exists():
		cache_info = json.loads(cache_meta_path.read_text(encoding="utf-8"))
		cached_ids = cache_info.get("ids") if isinstance(cache_info, dict) else None
		cached_model = cache_info.get("embedding_model") if isinstance(cache_info, dict) else None
		if cached_ids == test_ids and cached_model == model_name:
			logging.info("检测到匹配的测试向量缓存，将直接复用: %s", cache_emb_path)
			test_vectors = np.load(cache_emb_path)
		else:
			logging.info("缓存与当前任务不匹配，将重新计算测试向量。")

	if test_vectors is None:
		model = build_mod.load_sentence_encoder(model_name, device)
		test_vectors = search_mod.embed_texts(
			model,
			payloads,
			batch_size=max(1, batch_size),
			desc="生成测试向量",
		)
		np.save(cache_emb_path, test_vectors)
		cache_payload = {
			"ids": test_ids,
			"embedding_model": model_name,
		}
		cache_meta_path.write_text(json.dumps(cache_payload, ensure_ascii=False, indent=2), encoding="utf-8")
		logging.info("测试向量与缓存元数据已保存，可使用 --reuse-cache 复用。")

	faiss.normalize_L2(test_vectors)

	results: List[dict[str, str]] = []
	total_candidates = 0
	filtered_out = 0
	score_stats: List[float] = []
	pred_counts: Dict[int, int] = {}

	for start in range(0, len(test_vectors), search_batch_size):
		end = min(start + search_batch_size, len(test_vectors))
		batch_vectors = test_vectors[start:end]
		D, I = index.search(batch_vectors, top_k)

		for offset, row_id in enumerate(test_ids[start:end]):
			sims = D[offset]
			idxs = I[offset]
			seen: set[str] = set()
			candidates: List[tuple[str, float]] = []

			for idx, score in zip(idxs, sims):
				total_candidates += 1
				if idx < 0 or idx >= len(train_ids):
					continue
				score_float = float(score)
				score_stats.append(score_float)
				if score_float < base_threshold:
					filtered_out += 1
					continue

				for cve in train_labels[idx]:
					base_cve = cve.upper()
					if not base_cve.startswith("CVE-"):
						continue
					if base_cve in seen:
						continue
					seen.add(base_cve)
					candidates.append((base_cve, score_float))
					if len(candidates) >= max_candidates:
						break
				if len(candidates) >= max_candidates:
					break

			preds = search_mod.adaptive_predict(
				candidates,
				base_threshold=base_threshold,
				high_confidence=high_confidence,
				medium_confidence=medium_confidence,
				max_diff_second=second_gap,
				max_diff_third=third_gap,
			)
			pred_counts[len(preds)] = pred_counts.get(len(preds), 0) + 1
			results.append({"id": row_id, "cve_labels": " ".join(preds)})

	output_path.parent.mkdir(parents=True, exist_ok=True)
	pd.DataFrame(results).to_csv(output_path, index=False)
	logging.info("预测结果已保存: %s", output_path)

	if score_stats:
		scores = np.asarray(score_stats)
		logging.info(
			"候选数量: %d | 过滤数量: %d (%.1f%%) | 相似度均值: %.3f 中位数: %.3f",
			total_candidates,
			filtered_out,
			filtered_out / max(total_candidates, 1) * 100,
			float(scores.mean()),
			float(np.median(scores)),
		)
	logging.info("预测数量分布: %s", {k: f"{v} ({v / max(len(results), 1) * 100:.1f}%)" for k, v in sorted(pred_counts.items())})

	return output_path


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="一站式 CVE 标注流水线")
	parser.add_argument("--train-path", required=True, help="原始训练集 CSV 路径")
	parser.add_argument("--test-path", required=True, help="测试集 CSV 路径")
	parser.add_argument("--train-payload-column", default="payload_decoded", help="训练集报文字段名")
	parser.add_argument("--test-payload-column", default="payload_decoded", help="测试集报文字段名")
	parser.add_argument("--train-id-column", default="id", help="训练集 ID 字段名")
	parser.add_argument("--test-id-column", default="id", help="测试集 ID 字段名")
	parser.add_argument("--clean-train-path", default=None, help="清洗后训练集输出路径 (默认与输入同目录)")
	parser.add_argument("--clean-test-path", default=None, help="清洗后测试集输出路径 (默认与输入同目录)")
	parser.add_argument("--store-dir", default="embeddings/faiss_store", help="FAISS 索引输出目录")
	parser.add_argument("--output-path", default="ans/test_label_pipeline.csv", help="预测结果输出路径")
	parser.add_argument("--model-path", default=None, help="SentenceTransformer 模型路径或名称 (默认 all-MiniLM-L6-v2)")
	parser.add_argument("--device", default=None, help="模型加载设备，如 cpu/cuda")
	parser.add_argument("--train-batch-size", type=int, default=32, help="训练向量编码批量大小")
	parser.add_argument("--test-batch-size", type=int, default=32, help="测试向量编码批量大小")
	parser.add_argument("--search-batch-size", type=int, default=512, help="FAISS 检索批量大小")
	parser.add_argument("--top-k", type=int, default=50, help="检索候选数量")
	parser.add_argument("--max-candidates", type=int, default=5, help="每条样本保留的候选 CVE 数量")
	parser.add_argument("--base-threshold", type=float, default=0.84, help="基础相似度阈值")
	parser.add_argument("--high-confidence", type=float, default=0.87, help="第二候选高置信阈值")
	parser.add_argument("--medium-confidence", type=float, default=0.78, help="第二候选中置信阈值")
	parser.add_argument("--second-gap", type=float, default=0.15, help="第二候选与第一候选最大差值")
	parser.add_argument("--third-gap", type=float, default=0.05, help="第三候选与第二候选最大差值")
	parser.add_argument("--overwrite-clean", action="store_true", help="强制重新生成清洗数据")
	parser.add_argument("--overwrite-test-clean", action="store_true", help="强制重新生成测试清洗数据")
	parser.add_argument("--overwrite-index", action="store_true", help="强制重新构建索引")
	parser.add_argument("--reuse-cache", action="store_true", help="复用缓存的测试向量 (如存在)")
	parser.add_argument("--verbose", action="store_true", help="输出详细日志")
	return parser.parse_args()


def main() -> None:
	args = parse_args()
	configure_logging(args.verbose)

	train_path = Path(args.train_path)
	test_path = Path(args.test_path)
	if not train_path.exists():
		raise FileNotFoundError(f"未找到训练数据: {train_path}")
	if not test_path.exists():
		raise FileNotFoundError(f"未找到测试数据: {test_path}")

	clean_train_path = (
		Path(args.clean_train_path)
		if args.clean_train_path
		else train_path.with_name(f"{train_path.stem}_cleaned.csv")
	)

	clean_test_path = (
		Path(args.clean_test_path)
		if args.clean_test_path
		else test_path.with_name(f"{test_path.stem}_cleaned.csv")
	)

	clean_path = preprocess_training_data(
		train_path,
		clean_train_path,
		payload_column=args.train_payload_column,
		id_column=args.train_id_column,
		overwrite=args.overwrite_clean,
	)

	clean_test = preprocess_test_data(
		test_path,
		clean_test_path,
		payload_column=args.test_payload_column,
		id_column=args.test_id_column,
		overwrite=args.overwrite_test_clean or args.overwrite_clean,
	)

	store_dir = Path(args.store_dir)
	model_for_training = args.model_path or "sentence-transformers/all-MiniLM-L6-v2"
	build_vector_store(
		clean_path,
		store_dir,
		model_path=model_for_training,
		device=args.device,
		batch_size=args.train_batch_size,
		overwrite=args.overwrite_index,
	)

	predictions_path = label_test_payloads(
		clean_test,
		store_dir,
		Path(args.output_path),
		payload_column="payload_clean",
		id_column="id",
		model_path=args.model_path or model_for_training,
		device=args.device,
		batch_size=args.test_batch_size,
		top_k=args.top_k,
		max_candidates=args.max_candidates,
		base_threshold=args.base_threshold,
		high_confidence=args.high_confidence,
		medium_confidence=args.medium_confidence,
		second_gap=args.second_gap,
		third_gap=args.third_gap,
		search_batch_size=args.search_batch_size,
		reuse_cache=args.reuse_cache,
	)

	logging.info("流水线执行完毕，最终预测文件: %s", predictions_path)


if __name__ == "__main__":
	main()

