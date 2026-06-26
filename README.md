# NOVA-F

NOVA-F 是一个面向 DataCon 2025 漏洞攻击流量识别任务的本地离线识别系统。输入 HTTP 请求流量，输出对应的 CVE 标签。

当前系统不是端到端训练分类器，而是检索式识别系统：

```text
HTTP payload 清洗
-> SentenceTransformer 向量编码
-> FAISS 近邻检索
-> CVE 候选聚合
-> 负样本近邻抑制
-> OOF blocklist
-> 可选结构化 rerank
-> 可选规则配置补召回
```

## 当前状态

项目已经完成主要工程化优化，并在 WSL-Ubuntu 下跑通过全量主流程。

WSL 全量验证命令已成功运行，输出：

```text
data/experiments/wsl_full_recall_first.csv
```

全量主流程 rerank+blocklist 阶段评估：

```text
precision: 0.735511
recall:    0.737037
micro_f1:  0.736273
macro_f1:  0.549538
```

当前推荐保留两种使用模式。

## 推荐模式

### precision-first

默认推荐主线。误报更低，泛化证据最强。

```text
OOF blocklist + wsman-38649 + exact/structured high-precision rules

precision: 0.758397
recall:    0.735355
micro_f1:  0.746699
macro_f1:  0.538537
```

适合误报代价较高的场景。

### recall-first

召回优先路线。提高 recall 和 Macro-F1，但 precision 会下降。

```text
structured rerank + OOF blocklist + rule-config structured rules only-empty + wsman-38649

precision: 0.739922
recall:    0.756264
micro_f1:  0.748004
macro_f1:  0.548448
```

适合后面还有人工复核的安全告警场景。

## 和初始版本对比

初始版本主要依赖扩展训练集做 embedding 检索，误报严重：

```text
precision: 0.156417
recall:    0.757105
micro_f1:  0.259270
macro_f1:  0.479125
```

当前保守主线：

```text
precision: 0.758397
recall:    0.735355
micro_f1:  0.746699
macro_f1:  0.538537
```

主要提升来自：

```text
combined 正负样本索引
CVE 候选聚合
空标签近邻负证据抑制
训练集 OOF blocklist
训练验证的结构化规则
可选 structured rerank
```

## Linux / WSL 环境配置

推荐使用 conda 环境。当前验证环境为：

```text
WSL-Ubuntu
Python 3.12.13
conda env: nova-f
```

创建环境示例：

```bash
conda create -n nova-f python=3.12 -y
conda activate nova-f
python -m pip install --upgrade pip
python -m pip install numpy pandas tqdm faiss-cpu sentence-transformers
```

如果 WSL 访问 HuggingFace 不稳定，建议先在 Windows 下载模型，然后放到：

```text
models/all-MiniLM-L6-v2
```

运行时显式指定：

```bash
--model-path ./models/all-MiniLM-L6-v2
```

## 数据准备

官方授权数据不进入 Git。

约定原始数据位置：

```text
data/datacon2025/datacon2025-xlab-httpcve/data-release/train.json.gz
data/datacon2025/datacon2025-xlab-httpcve/data-release/test.json.gz
```

转换为项目 CSV：

```bash
python utils/convert_datacon_jsonl.py \
  --input ./data/datacon2025/datacon2025-xlab-httpcve/data-release/train.json.gz \
  --output ./data/train_payload.csv

python utils/convert_datacon_jsonl.py \
  --input ./data/datacon2025/datacon2025-xlab-httpcve/data-release/test.json.gz \
  --output ./data/test_payload.csv
```

CSV 字段：

```text
id
payload_decoded
labeled
cve_labels
```

## 启动项目

### 1. 构建 combined 训练集

```bash
python utils/merge_training_csv.py \
  --input ./data/train_with_ultimate.csv \
  --input ./data/train_payload.csv \
  --output ./data/experiments/train_combined.csv
```

### 2. 运行基础主流程

```bash
python main.py \
  --train-path ./data/train_with_ultimate.csv \
  --test-path ./data/test_payload.csv \
  --test-payload-column payload_decoded \
  --store-dir ./embeddings/faiss_store_combined \
  --output-path ./data/experiments/test_official_base.csv \
  --model-path ./models/all-MiniLM-L6-v2 \
  --reuse-cache
```

### 3. 启用 OOF blocklist

```bash
python main.py \
  --train-path ./data/train_with_ultimate.csv \
  --test-path ./data/test_payload.csv \
  --test-payload-column payload_decoded \
  --store-dir ./embeddings/faiss_store_combined \
  --output-path ./data/experiments/test_official_precision_first.csv \
  --model-path ./models/all-MiniLM-L6-v2 \
  --reuse-cache \
  --prediction-blocklist ./data/experiments/fold_blocklist_fp20_p002_mf2.txt
```

### 4. 启用 structured rerank

`--train-feature-path` 必须和 FAISS meta 的训练顺序一致。当前本地实验使用：

```text
data/experiments/train_combined_cleaned.csv
```

如果该文件不存在，可生成：

```bash
python - <<'PY'
import pandas as pd
paths = ["data/train_with_ultimate_cleaned.csv", "data/experiments/train_payload_cleaned.csv"]
pd.concat([pd.read_csv(path) for path in paths], ignore_index=True).to_csv(
    "data/experiments/train_combined_cleaned.csv",
    index=False,
)
PY
```

运行：

```bash
python main.py \
  --train-path ./data/train_with_ultimate.csv \
  --test-path ./data/test_payload.csv \
  --test-payload-column payload_decoded \
  --store-dir ./embeddings/faiss_store_combined \
  --output-path ./data/experiments/test_official_rerank.csv \
  --model-path ./models/all-MiniLM-L6-v2 \
  --reuse-cache \
  --prediction-blocklist ./data/experiments/fold_blocklist_fp20_p002_mf2.txt \
  --structured-rerank-alpha 0.03 \
  --train-feature-path ./data/experiments/train_combined_cleaned.csv
```

### 5. 应用规则配置

导出规则配置：

```bash
python utils/export_rule_config.py \
  --rules ./data/experiments/structured_rules_train_s20_p1.csv \
  --output ./data/experiments/structured_rules_train_s20_p1_config.json \
  --source train-structured-s20-p1 \
  --min-support 20 \
  --min-precision 1.0 \
  --enabled \
  --risk-level low
```

应用规则：

```bash
python utils/apply_rule_config.py \
  --config ./data/experiments/structured_rules_train_s20_p1_config.json \
  --truth-or-test ./data/test_payload.csv \
  --pred ./data/experiments/test_official_rerank.csv \
  --output ./data/experiments/test_official_recall_first.csv \
  --only-empty \
  --max-additions 1
```

## 评估

整体指标：

```bash
python utils/evaluate_predictions.py \
  --truth ./data/test_payload.csv \
  --pred ./data/experiments/test_official_recall_first.csv
```

per-CVE 指标：

```bash
python utils/evaluate_per_label.py \
  --truth ./data/test_payload.csv \
  --pred ./data/experiments/test_official_recall_first.csv \
  --output-summary ./data/experiments/per_label_recall_first.csv
```

长尾诊断：

```bash
python utils/diagnose_long_tail.py \
  --truth ./data/test_payload.csv \
  --pred ./data/experiments/test_official_recall_first.csv \
  --train ./data/train_with_ultimate_cleaned.csv \
  --train ./data/experiments/train_payload_cleaned.csv \
  --output ./data/experiments/long_tail_diagnosis.csv
```

导出缺样本 CVE：

```bash
python utils/export_data_gap_report.py \
  --per-label ./data/experiments/per_label_recall_first.csv \
  --train ./data/train_with_ultimate_cleaned.csv \
  --train ./data/experiments/train_payload_cleaned.csv \
  --min-fn 20 \
  --max-train-support 0 \
  --output-csv ./data/experiments/cve_data_gap_no_train_support.csv \
  --output-md ./data/experiments/cve_data_gap_no_train_support.md
```

## 工程架构

```text
main.py
  一站式清洗、建库、检索、预测入口

src/preprocess.py
  HTTP payload 清洗、CVE 标签归一化

src/build_faiss.py
  SentenceTransformer 编码与 FAISS 索引构建

src/search_faiss.py
  FAISS 检索、CVE 候选聚合、空标签负证据抑制、blocklist、rerank

src/structured_features.py
  method/path/query/body/token 结构化特征抽取

utils/convert_datacon_jsonl.py
  官方 json.gz 转 CSV

utils/merge_training_csv.py
  合并训练集

utils/cache_search_results.py
  缓存 FAISS top-k 结果

utils/tune_retrieval_params.py
  基于缓存结果调参

utils/learn_blocklist_from_folds.py
  训练集 OOF blocklist 学习

utils/structured_signature_rules.py
  结构化规则挖掘、OOF 验证、应用

utils/export_rule_config.py / utils/apply_rule_config.py
  规则配置化

utils/evaluate_predictions.py / utils/evaluate_per_label.py
  整体和 per-CVE 评估

utils/diagnose_long_tail.py / utils/export_data_gap_report.py
  长尾诊断和缺样本 CVE 导出
```

## 核心算法

### CVE 候选聚合

对 top-k 近邻中的每个 CVE 聚合证据：

```text
score = best_similarity + min(votes - 1, 8) * vote_weight
```

默认：

```text
vote_weight=0.015
min_votes=1
```

### 空标签近邻负证据

如果空标签近邻与 CVE 近邻非常接近，说明该请求可能是相似但不应标 CVE 的流量，因此抑制输出。

默认：

```text
empty_penalty_margin=0.05
empty_penalty_floor=0.80
empty_penalty_ratio=0.50
```

### OOF blocklist

用训练集 out-of-fold 预测找系统性误报 CVE，而不是从测试集真值写规则。

当前使用：

```text
fold_blocklist_fp20_p002_mf2.txt
```

### Structured rerank

在 embedding 相似度基础上加入 HTTP 结构一致性：

```text
score = semantic_score + alpha * feature_bonus
```

`feature_bonus` 包含：

```text
method match
path exact match
path token Jaccard
query key Jaccard
body key Jaccard
payload token Jaccard
```

当前推荐：

```text
alpha=0.03
```

## 当前限制

仍有一批 CVE 在训练集中没有支持样本，例如：

```text
CVE-2021-20016
CVE-2024-1800
CVE-2020-8949
CVE-2017-17215
CVE-2020-35391
CVE-2017-6514
CVE-2023-3306
CVE-2023-26801
CVE-2013-3307
CVE-2021-43163
```

这些不能靠可靠训练规则解决。继续提升上限需要补充授权样本或公开样本，然后重建索引和规则。

## 更多技术细节

完整优化过程、实验分支和技术分析见：

```text
FINAL_TECHNICAL_REPORT.md
```
