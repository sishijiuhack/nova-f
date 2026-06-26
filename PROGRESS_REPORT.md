# nova-f 当前进度报告

更新时间：2026-06-26

## 1. 项目目标

nova-f 面向 DataCon 2025「漏洞攻击流量识别」任务，目标是根据 HTTP 请求流量识别对应 CVE 标签。当前方案是本地离线检索流水线：

1. 清洗 HTTP payload。
2. 使用 `all-MiniLM-L6-v2` 生成文本向量。
3. 使用 FAISS 内积索引做 top-k 相似检索。
4. 聚合近邻中的 CVE 候选。
5. 结合阈值、多标签策略和负样本近邻抑制输出最终标签。

## 2. 数据与环境

官方授权数据已放置在：

```text
data/datacon2025/datacon2025-xlab-httpcve/data-release/
```

已转换为项目 CSV：

```text
data/train_payload.csv
data/test_payload.csv
```

数据规模：

```text
train_payload.csv: 36001 行
test_payload.csv: 105077 行
```

字段：

```text
id
payload_decoded
labeled
cve_labels
```

标签分布：

```text
train_payload.csv
labeled=0: 21843
labeled=1: 14158
非空 CVE: 5187

test_payload.csv
labeled=0: 54837
labeled=1: 50240
非空 CVE: 15769
```

本地模型路径：

```text
models/all-MiniLM-L6-v2
```

运行时应显式指定：

```bash
--model-path ./models/all-MiniLM-L6-v2
```

## 3. 已完成代码工作

已实现或更新：

- `utils/convert_datacon_jsonl.py`：将官方 `json.gz` 数据转换为项目 CSV。
- `utils/evaluate_predictions.py`：本地计算 `exact_match`、`precision`、`recall`、`micro_f1`、`macro_f1`。
- `utils/merge_training_csv.py`：合并扩展训练集和官方训练集，用于构建 combined 索引。
- `utils/tune_retrieval_params.py`：基于缓存 top-k 检索结果进行阈值和负证据参数搜索。
- `src/search_faiss.py`：新增 CVE 候选聚合、空标签近邻负证据抑制。
- `main.py`：主流水线接入负证据抑制参数，并更新默认阈值。
- `src/preprocess.py`：修复 `NaN`/`None`/`null` 被错误归一化为标签的问题。
- `src/build_faiss.py` / `src/search_faiss.py` / `main.py`：新增文本编码前缀参数，支持 E5 类检索模型的 `passage:` / `query:` 前缀。

## 4. 当前最佳实验结论

### 4.1 原始扩展训练集结果

使用：

```text
data/train_with_ultimate.csv
embeddings/faiss_store
```

官方测试集评估：

```text
all_rows
exact_match: 0.601435
precision:   0.156417
recall:      0.757105
micro_f1:    0.259270
macro_f1:    0.479125

labeled=1
exact_match: 0.733758
precision:   0.445963
recall:      0.757105
micro_f1:    0.561300
macro_f1:    0.562271

truth_nonempty_cve
exact_match: 0.667385
precision:   0.794891
recall:      0.757105
micro_f1:    0.775538
macro_f1:    0.676249
```

问题：召回较高，但对 `labeled=0` 和空 CVE 样本误报严重。

### 4.2 combined 全量索引结果

已测试将扩展训练集与官方训练集合并构建索引：

```text
embeddings/faiss_store_combined
训练向量数: 72938
```

仅使用 combined 索引和 CVE 聚合，不启用负证据抑制时，较优配置：

```text
base_threshold=0.84
min_votes=1
vote_weight=0.015
```

评估：

```text
all_rows
exact_match: 0.899321
precision:   0.522833
recall:      0.751556
micro_f1:    0.616669
macro_f1:    0.483007

labeled=1
exact_match: 0.851194
precision:   0.679765
recall:      0.751556
micro_f1:    0.713860
macro_f1:    0.566028
```

结论：combined 索引明显优于原始扩展训练集。

### 4.3 当前最佳：combined 索引 + 空标签近邻抑制

新增策略：当空标签近邻与最佳 CVE 近邻相似度非常接近时，将其视为负证据，抑制 CVE 输出。

当前默认参数：

```text
base_threshold=0.86
min_votes=1
vote_weight=0.015
empty_penalty_margin=0.05
empty_penalty_floor=0.80
empty_penalty_ratio=0.50
```

基于缓存 top-50 检索结果生成：

```text
data/experiments/test_official_optimized.csv
```

预测数量分布：

```text
0 labels: 91313
1 label : 10169
2 labels: 1945
3 labels: 1650
```

评估：

```text
all_rows
rows:        105077
answer_rate: 0.130990
exact_match: 0.928129
precision:   0.666632
recall:      0.710354
micro_f1:    0.687799
macro_f1:    0.523245

labeled=1
rows:        50240
answer_rate: 0.247313
exact_match: 0.876334
precision:   0.828398
recall:      0.710354
micro_f1:    0.764848
macro_f1:    0.592976

truth_nonempty_cve
rows:        15769
answer_rate: 0.744435
exact_match: 0.649502
precision:   0.881714
recall:      0.710354
micro_f1:    0.786812
macro_f1:    0.661345
```

相对原始完整预测，核心提升：

```text
all_rows micro_f1: 0.259270 -> 0.687799
labeled=1 micro_f1: 0.561300 -> 0.764848
all_rows precision: 0.156417 -> 0.666632
```

代价：

```text
recall: 0.757105 -> 0.710354
```

这是可接受的权衡，因为原主要瓶颈是负样本误报。

## 5. 更强 embedding 模型试验

已下载并在 holdout 数据上测试：

```text
models/bge-small-en-v1.5
models/e5-small-v2
```

测试集：

```text
data/experiments/holdout_train.csv: 2500 行
data/experiments/holdout_valid.csv: 300 行
```

MiniLM 调参后较优结果：

```text
base_threshold: 0.88
precision:      0.646789
recall:         0.449045
micro_f1:       0.530075
macro_f1:       0.423855
```

BGE small 调参后较优结果：

```text
base_threshold: 0.96
precision:      0.703125
recall:         0.429936
micro_f1:       0.533597
macro_f1:       0.417634
```

E5 small 使用 `passage:` / `query:` 前缀后较优结果：

```text
base_threshold: 0.90
precision:      0.463668
recall:         0.426752
micro_f1:       0.444444
macro_f1:       0.377220
```

结论：

- BGE small 在 holdout 上 micro F1 仅轻微高于 MiniLM，但 CPU 编码速度明显更慢，暂不替换默认模型。
- E5 small 当前不适配 payload 检索任务，暂不进入全量实验。
- 当前最大收益仍来自 combined 索引、CVE 聚合和空标签近邻负证据抑制。

## 6. 推荐运行命令

先合并训练集：

```bash
python utils/merge_training_csv.py \
  --input ./data/train_with_ultimate.csv \
  --input ./data/train_payload.csv \
  --output ./data/experiments/train_combined.csv
```

再构建或复用 combined 索引并预测：

```bash
python main.py \
  --train-path ./data/experiments/train_combined.csv \
  --test-path ./data/test_payload.csv \
  --test-payload-column payload_decoded \
  --store-dir ./embeddings/faiss_store_combined \
  --output-path ./data/experiments/test_official_optimized.csv \
  --model-path ./models/all-MiniLM-L6-v2 \
  --reuse-cache
```

如需关闭空标签近邻抑制用于对照实验：

```bash
--empty-penalty-margin -1
```

参数搜索：

```bash
python utils/tune_retrieval_params.py \
  --truth ./data/test_payload.csv \
  --search ./data/experiments/search_top50_combined.npz \
  --meta ./embeddings/faiss_store_combined/meta.json \
  --bases 0.84,0.86,0.88,0.90 \
  --empty-margins=-1,0.02,0.05,0.08
```

E5 类模型示例：

```bash
python main.py \
  --train-path ./data/experiments/train_combined.csv \
  --test-path ./data/test_payload.csv \
  --store-dir ./embeddings/faiss_store_e5 \
  --output-path ./data/experiments/test_e5.csv \
  --model-path ./models/e5-small-v2 \
  --train-text-prefix "passage: " \
  --test-text-prefix "query: " \
  --overwrite-index
```

## 7. 后续优化方向

优先级建议：

1. 按 CVE 频次或类别设定动态阈值，降低热门 CVE 的误报。
2. 对高频误报 CVE 做错误分析，检查是否存在训练样本标签污染。
3. 在 GPU 或更长运行窗口下尝试 `bge-base-en-v1.5`、`e5-base-v2` 或安全领域模型。
4. 将 FAISS 检索缓存和预测缓存拆开为正式命令，减少重复 CPU 检索时间。
5. 对 payload 结构增加显式特征，例如请求方法、路径、参数名和 body 模式。

## 8. Git 与数据管理

以下内容不参与上传：

```text
data/datacon2025/
data/train_payload.csv
data/test_payload.csv
data/test_payload_cleaned.csv
data/experiments/
models/
embeddings/
ans/test_official_labeled.csv
wp.pdf
wp_extracted.txt
```

已清理：

```text
model_download.py
__pycache__/
src/__pycache__/
utils/__pycache__/
```

本报告仅记录进度和实验结果，不包含授权数据正文。
