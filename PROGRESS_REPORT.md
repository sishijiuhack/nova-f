# nova-f 当前进度报告

更新时间：2026-06-26

## 1. 项目目标

nova-f 面向 DataCon 2025「漏洞攻击流量识别」任务，目标是根据 HTTP 请求流量识别对应 CVE 标签。当前实现采用本地离线方案：

1. 清洗 HTTP payload。
2. 使用 SentenceTransformer 编码 payload。
3. 使用 FAISS 构建向量索引。
4. 对测试流量做 top-k 相似检索。
5. 基于候选 CVE 聚合、相似度阈值和多标签策略输出预测结果。

## 2. 已完成工作

### 2.1 WP 与框架理解

已阅读项目 WP。确认原方案核心是：

- 数据清洗。
- `all-MiniLM-L6-v2` 向量化。
- FAISS 内积相似度检索。
- 自适应阈值输出 0 到 3 个 CVE。
- 通过扩展训练集和外部漏洞知识源提升覆盖率。

### 2.2 官方授权数据接入

授权数据已放置在：

```text
data/datacon2025/datacon2025-xlab-httpcve/data-release/
```

包含：

```text
train.json.gz
test.json.gz
```

已通过 `utils/convert_datacon_jsonl.py` 转换为项目 CSV：

```text
data/train_payload.csv
data/test_payload.csv
```

转换结果：

```text
train_payload.csv: 36001 行
test_payload.csv: 105077 行
```

数据字段：

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

### 2.3 运行环境

已在 WSL conda 环境 `nova-f` 中验证核心依赖：

```text
faiss
pandas
numpy
sentence-transformers
```

由于 WSL 中 HuggingFace 证书校验失败，已采用 Windows HuggingFace 缓存复制方式，将模型放置到：

```text
models/all-MiniLM-L6-v2
```

运行时通过以下参数使用本地模型，避免再次访问 HuggingFace：

```bash
--model-path ./models/all-MiniLM-L6-v2
```

### 2.4 代码优化

已新增 CVE 候选聚合逻辑 `aggregate_cve_candidates`。

优化前策略：

- 对 top-k 近邻按顺序遍历。
- 每个 CVE 首次出现即作为候选。
- 容易受单个噪声近邻或多标签样本影响。

优化后策略：

- 跨 top-k 近邻聚合每个 CVE 的最佳相似度。
- 统计近邻投票次数。
- 使用最佳相似度加小额投票奖励排序。
- 支持 `--min-votes` 和 `--vote-weight` 参数。

该逻辑已接入：

```text
src/search_faiss.py
main.py
```

### 2.5 新增工具脚本

新增官方数据转换脚本：

```text
utils/convert_datacon_jsonl.py
```

用途：

```bash
python utils/convert_datacon_jsonl.py \
  --input ./data/datacon2025/datacon2025-xlab-httpcve/data-release/train.json.gz \
  --output ./data/train_payload.csv
```

新增本地评估脚本：

```text
utils/evaluate_predictions.py
```

可计算：

```text
answer_rate
exact_match
precision
recall
micro_f1
macro_f1
```

## 3. 已完成完整预测

使用扩展训练集：

```text
data/train_with_ultimate.csv
```

使用官方测试集：

```text
data/test_payload.csv
```

运行命令：

```bash
python main.py \
  --train-path ./data/train_with_ultimate.csv \
  --test-path ./data/test_payload.csv \
  --test-payload-column payload_decoded \
  --store-dir ./embeddings/faiss_store \
  --output-path ./ans/test_official_labeled.csv \
  --model-path ./models/all-MiniLM-L6-v2 \
  --reuse-cache
```

运行结果：

```text
测试样本: 105077
非空预测: 49902
空预测: 55175

预测 1 个 CVE: 20886
预测 2 个 CVE: 21588
预测 3 个 CVE: 7428
```

输出文件：

```text
ans/test_official_labeled.csv
```

该文件为本地预测结果，不参与 Git 提交。

## 4. 本地评估结果

基于授权数据中的真实 `cve_labels` 做了本地评估。

### 4.1 全量 105077 行

```text
exact_match: 0.601435
precision:   0.156417
recall:      0.757105
micro_f1:    0.259270
macro_f1:    0.479125
```

### 4.2 仅 `labeled=1` 的 50240 行

```text
exact_match: 0.733758
precision:   0.445963
recall:      0.757105
micro_f1:    0.561300
macro_f1:    0.562271
```

### 4.3 仅真实存在 CVE 的 15769 行

```text
exact_match: 0.667385
precision:   0.794891
recall:      0.757105
micro_f1:    0.775538
macro_f1:    0.676249
```

## 5. 当前判断

当前模型的主要特点：

- 对真实存在 CVE 的样本召回较好。
- 对真实非 CVE 或 `labeled=0` 流量误报较多。
- 全量 precision 偏低。
- 下一阶段优化重点不是继续提高召回，而是降低误报。

当前最关键问题：

```text
空样本过滤能力不足。
```

## 6. 后续优化方向

建议按优先级处理：

1. 提高 `base_threshold`，观察 precision 与 recall 变化。
2. 调整 `--min-votes`，要求 CVE 至少被多个近邻支持。
3. 针对 `labeled=0` 和空 CVE 样本建立负样本过滤器。
4. 单独统计高误报 CVE，做黑名单或更高阈值策略。
5. 对不同 CVE 按训练集中出现频次设定动态阈值。
6. 测试官方训练集、扩展训练集、合并训练集三种索引效果。

建议下一轮实验从以下参数开始：

```bash
--base-threshold 0.87
--min-votes 2
--vote-weight 0.01
```

## 7. Git 与数据管理

以下内容已加入忽略，避免上传授权数据、模型和本地预测结果：

```text
data/datacon2025/
data/train_payload.csv
data/test_payload.csv
data/test_payload_cleaned.csv
models/
embeddings/
ans/test_official_labeled.csv
wp.pdf
wp_extracted.txt
```

本次报告 `PROGRESS_REPORT.md` 按当前请求纳入 Git 提交。
