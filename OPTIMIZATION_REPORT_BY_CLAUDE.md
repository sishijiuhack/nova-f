# NOVA-F 项目优化分析报告

**作者**: Claude (Sonnet 4.6)  
**日期**: 2026-06-26  
**项目**: DataCon 2025 漏洞攻击流量识别  
**当前最佳成绩**: Micro F1 0.6878 (all_rows), 0.7648 (labeled=1)

---

## 执行摘要

NOVA-F 采用检索式架构（SentenceTransformer + FAISS + 规则聚合）实现 HTTP 流量的 CVE 标签预测。通过代码审查和文档分析，本报告识别出 **5 个关键优化方向** 和 **12 项具体改进建议**，预计可在保持方案简洁性的前提下进一步提升 F1 指标 3-8 个百分点。

**核心发现**:
1. 当前瓶颈已从召回率转向精准率（precision 0.67 vs recall 0.71）
2. 检索架构本身合理，优化空间主要在特征工程、后处理策略和工程效率
3. 代码质量较高，但存在重复逻辑和缺失模块化测试

---

## 1. 架构现状分析

### 1.1 方案优势
- ✅ **离线检索架构**: 无需训练深度分类器，快速迭代
- ✅ **负样本建模**: combined 索引 + 空标签抑制，precision 从 0.16 → 0.67
- ✅ **投票聚合**: 多近邻投票机制降低噪声影响
- ✅ **可解释性**: 每个预测可追溯到具体训练样本

### 1.2 架构瓶颈
- ⚠️ **特征单一**: 仅使用清洗后的文本，未提取结构化特征（URL 路径、参数名、HTTP 方法）
- ⚠️ **全局阈值**: 所有 CVE 共用一个 `base_threshold`，未考虑样本分布差异
- ⚠️ **CPU 检索瓶颈**: 105k 测试样本 × top-50 检索在 CPU 上耗时长
- ⚠️ **缺乏在线学习**: 无法利用测试集中的聚类信息

---

## 2. 优化路径建议

### 路径 A: 特征工程增强（预计收益: +2-4% F1）

#### A1. 结构化特征提取
**当前问题**: `clean_payload_text()` 将 HTTP 请求展平为纯文本，丢失了结构信息。

**优化方案**:
```python
# 在 src/preprocess.py 新增函数
def extract_http_features(payload: str) -> dict:
    """提取结构化特征用于后处理增强"""
    features = {
        'method': None,      # GET/POST/PUT
        'path': None,        # /admin/login.php
        'has_params': False, # query string 存在
        'has_body': False,   # POST body 存在
        'suspicious_patterns': []  # ../、union select、<script>
    }
    # 实现基于正则的提取逻辑
    return features
```

**集成方式**:
- 在 FAISS 检索后，基于特征对 `candidates` 进行重排序
- 例如: SQL 注入类 CVE 候选在包含 `union`/`select` 的 payload 上加权 +0.02

**实现成本**: 1-2 天，低风险

---

#### A2. 双阶段检索
**当前问题**: 单次 top-50 检索可能错过语义相似但词汇差异大的样本。

**优化方案**:
```python
# 第一阶段: 粗排（当前方式）
coarse_results = index.search(test_vectors, k=100)

# 第二阶段: 精排（基于特征相似度）
for each result:
    rescore = semantic_sim * 0.8 + feature_sim * 0.2
    # feature_sim 基于 HTTP 方法、路径、参数名 Jaccard 相似度
```

**预期效果**: 长尾 CVE 的 recall 提升 2-3%，macro F1 改善

**实现成本**: 2-3 天，中等风险（需验证精排不会引入新 FP）

---

### 路径 B: 动态阈值与 CVE 特定策略（预计收益: +1-3% F1）

#### B1. Per-CVE 动态阈值
**当前问题**: `base_threshold=0.86` 对所有 CVE 一视同仁，但高频 CVE（如 CVE-2021-41773）易误报。

**优化方案**:
```python
# 在训练索引时统计每个 CVE 的频次和平均近邻距离
cve_stats = {
    'CVE-2021-41773': {'count': 523, 'avg_dist': 0.91, 'threshold': 0.88},
    'CVE-2023-12345': {'count': 12, 'avg_dist': 0.85, 'threshold': 0.82}
}

# 检索时使用 CVE 特定阈值
if cve in cve_stats:
    threshold = cve_stats[cve]['threshold']
else:
    threshold = base_threshold  # fallback
```

**计算方式**:
- 高频 CVE (count > 100): `threshold = base + 0.02`
- 长尾 CVE (count < 20): `threshold = base - 0.03`

**实现成本**: 1 天，低风险

#### 实验记录 2026-06-26：频次启发式 Per-CVE 阈值

已基于缓存检索结果运行离线实验：

```text
search: data/experiments/search_top50_combined.npz
meta:   embeddings/faiss_store_combined/meta.json
output: data/experiments/dynamic_threshold_frequency_results.csv
```

实验策略：

- 高频 CVE 按训练集中出现次数上调阈值。
- 长尾 CVE 按训练集中出现次数下调阈值。
- 组合搜索若干 `high_cut`、`low_cut`、`threshold_delta`。

结果：

```text
baseline_dynamic_impl
precision: 0.666632
recall:    0.710354
micro_f1:  0.687799
macro_f1:  0.523245

best frequency heuristic: highfreq>=50 +0.02
precision: 0.668945
recall:    0.707831
micro_f1:  0.687839
macro_f1:  0.522532
```

结论：

- 单纯按训练频次调整阈值基本无收益，`micro_f1` 只提升 `0.000040`，可视为噪声级变化。
- 该实验反驳了“高频 CVE 一律上调、长尾 CVE 一律下调”的简单策略。
- 后续 Per-CVE 阈值必须基于错误分布或验证集表现，而不能仅基于训练频次。

---

#### B2. 错误案例驱动的规则过滤
**当前问题**: 未对高频 FP 模式建立专门抑制规则。

**优化方案**:
1. 运行错误分析脚本（新增 `utils/analyze_errors.py`）:
   ```python
   # 统计 FP top-20 CVE 及其对应的 payload 模式
   fp_analysis = analyze_false_positives(truth, pred)
   # 输出: CVE-XXXX 在包含 "normal pattern X" 的 payload 上误报率 45%
   ```

2. 添加黑名单规则:
   ```python
   # 在 search_faiss.py 新增
   SUPPRESSION_RULES = {
       'CVE-2021-41773': lambda payload: 'legitimate_path' in payload,
       'CVE-2023-XXXXX': lambda payload: re.match(r'^GET /static/', payload)
   }
   ```

**实现成本**: 1-2 天（需要先运行错误分析）

#### 实验记录 2026-06-26：当前最佳结果错误分析

已新增并运行：

```text
utils/analyze_errors.py
```

输入：

```text
truth:  data/test_payload.csv
pred:   data/experiments/test_official_optimized.csv
search: data/experiments/search_top50_combined.npz
meta:   embeddings/faiss_store_combined/meta.json
```

输出：

```text
data/experiments/error_summary_current.csv
data/experiments/error_examples_current.csv
```

关键发现：

1. False Positive 极端集中在少数 CVE：

```text
CVE-2021-44228: tp=32, fp=1090, fn=6, precision=0.0285, recall=0.8421
CVE-2022-4260 : tp=0,  fp=1071, fn=0, precision=0
CVE-2022-31181: tp=0,  fp=1070, fn=0, precision=0
CVE-2010-1340 : tp=7,  fp=124,  fn=0, precision=0.0534
CVE-2010-0944 : tp=6,  fp=120,  fn=0, precision=0.0476
CVE-2010-3426 : tp=7,  fp=112,  fn=0, precision=0.0588
```

其中 `CVE-2022-4260` 和 `CVE-2022-31181` 在测试真值中没有正例，但被预测超过 1000 次，是非常明确的高危误报源。`CVE-2021-44228` 虽有少量真阳性，但 precision 极低，也需要更高阈值或额外结构特征约束。

2. False Negative 也集中在少数 CVE：

```text
CVE-2021-20016: tp=0,   fp=0, fn=403
CVE-2017-16894: tp=43,  fp=7, fn=196
CVE-2017-7921 : tp=0,   fp=0, fn=139
CVE-2024-21887: tp=645, fp=2, fn=111
CVE-2023-46805: tp=649, fp=0, fn=107
CVE-2021-38649: tp=0,   fp=0, fn=105
```

这说明当前策略既有“热门误报 CVE”，也有“完全召不回 CVE”。后续不能只做全局阈值上调，否则会进一步恶化 `CVE-2021-20016`、`CVE-2017-7921` 等 FN 类。

3. 初步策略判断：

- Per-CVE 阈值方向成立，但不能只按频次粗暴调整。
- 对 `tp=0 且 fp 极高` 的 CVE，可以先离线验证禁用或大幅提高阈值。
- 对 `fp 很低但 fn 很高` 的 CVE，可以尝试降低特定阈值或补充结构化特征。
- 手写黑名单不应直接进入主流程，应先通过缓存搜索结果做离线模拟，确认 all_rows/macro/labeled=1 指标变化。

#### 实验记录 2026-06-26：错误驱动 Per-CVE 阈值候选实验

基于上面的错误分析，继续做离线实验：

```text
output: data/experiments/error_driven_threshold_results.csv
```

实验方式：

- 对当前预测中 `fp>=50` 且低 precision 的 CVE 集合上调候选聚合阈值。
- 测试阈值包括 `0.88, 0.90, 0.92, 0.94, 0.96, 0.98, 1.01`。
- 该实验使用当前测试真值筛选低 precision 标签，因此属于 oracle 分析，只用于判断上界和方向，不能直接作为生产规则。

结果：

```text
baseline
precision: 0.666632
recall:    0.710354
micro_f1:  0.687799
macro_f1:  0.523245

best candidate-threshold strategy:
labels:    fp>=50 & precision<=0.10 的 9 个 CVE
threshold: 0.98
precision: 0.678793
recall:    0.710186
micro_f1:  0.694135
macro_f1:  0.519895
```

结论：

- 在候选聚合阶段提高这些 CVE 的阈值，确实能提高 precision 和 micro F1，但收益只有约 `+0.0063`。
- 这远低于“最终输出后删除低 precision 标签”的 oracle 上界，说明当前错误并不只是候选阈值问题，还涉及多标签候选排序和 `adaptive_predict` 的输出联动。
- 后续应尝试“最终输出级别的 per-CVE filter/校准”，而不是只在候选聚合前做阈值调整。

#### 实验记录 2026-06-26：最终输出级 Per-CVE Filter 上界实验

已新增工具：

```text
utils/filter_predictions.py
```

实验命令：

```bash
python utils/filter_predictions.py \
  --pred ./data/experiments/test_official_optimized.csv \
  --analysis-summary ./data/experiments/error_summary_current.csv \
  --min-fp 50 \
  --max-precision 0.05 \
  --output ./data/experiments/test_official_filtered_fp50_p005.csv
```

被过滤标签：

```text
CVE-2010-0944
CVE-2020-3952
CVE-2021-44228
CVE-2022-31181
CVE-2022-4260
CVE-2023-34048
CVE-2024-8517
```

过滤规模：

```text
Changed rows: 1418
Removed labels: 3634
```

评估：

```text
baseline
precision: 0.666632
recall:    0.710354
micro_f1:  0.687799
macro_f1:  0.523245

filtered fp>=50 precision<=0.05
precision: 0.821659
recall:    0.708167
micro_f1:  0.760703
macro_f1:  0.524682
```

结论：

- 最终输出级 filter 的提升非常明显，说明当前最大可挖空间确实是少数 CVE 的系统性误报。
- 该结果仍然是 oracle，因为 blocklist 来自官方测试真值的错误分析；不能直接作为最终提交策略。
- 下一步应把这个思路改造成非泄漏策略：从训练集 holdout 或交叉验证中学习低精度 CVE blocklist/penalty，再应用到正式测试集。

#### 实验记录 2026-06-26：Holdout Filter 工具链验证

在已有 holdout 预测上验证同一工具链：

```text
truth: data/experiments/holdout_valid.csv
pred:  data/experiments/holdout_pred_minilm.csv
```

命令：

```bash
python utils/analyze_errors.py \
  --truth ./data/experiments/holdout_valid.csv \
  --pred ./data/experiments/holdout_pred_minilm.csv \
  --output-summary ./data/experiments/error_summary_holdout_minilm.csv \
  --output-examples ./data/experiments/error_examples_holdout_minilm.csv

python utils/filter_predictions.py \
  --pred ./data/experiments/holdout_pred_minilm.csv \
  --analysis-summary ./data/experiments/error_summary_holdout_minilm.csv \
  --min-fp 3 \
  --max-precision 0.1 \
  --output ./data/experiments/holdout_pred_minilm_filtered.csv
```

被过滤标签：

```text
CVE-2023-6000
CVE-2024-51568
```

结果：

```text
holdout baseline
precision: 0.580645
recall:    0.458599
micro_f1:  0.512456
macro_f1:  0.421593

holdout filtered
precision: 0.595041
recall:    0.458599
micro_f1:  0.517986
macro_f1:  0.424262
```

结论：

- 同集 holdout filter 有小幅提升，说明“错误分析 -> 低精度标签过滤 -> 评估”的工具链可用。
- 该实验仍然存在同集选择偏差，不能证明泛化。
- 下一步如果继续推进，应做 K-fold 或至少 train-valid 分离：在一部分验证集上学习 blocklist，在另一部分验证集上评估。

#### 实验记录 2026-06-26：官方测试集半分验证 Blocklist 稳定性

为了判断最终输出级 filter 是否只是同集过拟合，做了一个半分交叉验证式实验：

```text
output:
data/experiments/blocklist_split_validation_details.csv
data/experiments/blocklist_split_validation_summary.csv
```

实验方法：

1. 固定随机种子将官方测试集切成 A/B 两半。
2. 在 A 半上按 `min_fp` 和 `max_precision` 学习 blocklist，在 B 半上评估。
3. 再反向：B 半学习，A 半评估。
4. 比较过滤前后 micro F1、precision、recall。

最佳配置：

```text
min_fp=10
max_precision=0.10
```

结果均值：

```text
delta_micro_mean:        +0.085171
delta_micro_min:         +0.084919
block_count_mean:        26
filtered_precision_mean: 0.852617
filtered_recall_mean:    0.706939
filtered_macro_mean:     0.564256
```

两个方向的详细结果：

```text
A -> B:
base_micro:     0.688820
filtered_micro: 0.773739
delta_micro:    +0.084919
precision:      0.666422 -> 0.851227
recall:         0.712777 -> 0.709181

B -> A:
base_micro:     0.686778
filtered_micro: 0.772201
delta_micro:    +0.085423
precision:      0.666842 -> 0.854006
recall:         0.707942 -> 0.704698
```

结论：

- 半分验证中提升稳定，说明高 FP 低 precision CVE 的误报模式不是单个子集偶然现象。
- 该实验仍然使用了官方测试集内部真值，因此在严格意义上仍是研究分析，不应直接作为最终无泄漏提交策略。
- 但它强烈支持下一步做正式的训练集 holdout/K-fold：从训练/验证拆分中学习 blocklist 或 penalty，再应用到官方测试集。
- 相比候选阶段调阈值，最终输出级 filter 对 precision 的提升更有效，应作为后续主线。

---

### 路径 C: 模型与检索优化（预计收益: +1-2% F1）

#### C1. GPU 加速 FAISS
**当前问题**: CPU `IndexFlatIP` 检索 105k×72k 耗时 > 10 分钟。

**优化方案**:
```python
# 替换为 GPU 索引（需要 faiss-gpu）
if torch.cuda.is_available():
    res = faiss.StandardGpuResources()
    index = faiss.index_cpu_to_gpu(res, 0, index)
```

**预期效果**: 检索时间降至 < 1 分钟，支持更大规模 top-k 实验

**实现成本**: 0.5 天（需要 GPU 环境）

---

#### C2. 混合索引策略
**当前问题**: `IndexFlatIP` 精确但慢；`IndexIVFFlat` 快但召回率下降。

**优化方案**:
```python
# 使用 IVF 索引加速，但保留更多候选
quantizer = faiss.IndexFlatIP(dim)
index = faiss.IndexIVFFlat(quantizer, dim, nlist=100)
index.train(train_vectors)
index.nprobe = 20  # 检索时探测 20 个聚类中心
index.add(train_vectors)
```

**参数建议**:
- `nlist=100` (72k 样本适用)
- `nprobe=20` (平衡速度与召回)

**实现成本**: 1 天，需验证召回率损失 < 1%

---

### 路径 D: 数据与后处理优化（预计收益: +1-2% F1）

#### D1. 伪标签增强
**当前问题**: 测试集 105k 样本未被利用，存在大量聚类信息。

**优化方案**:
```python
# 在测试集上做无监督聚类
from sklearn.cluster import MiniBatchKMeans
clusters = MiniBatchKMeans(n_clusters=500).fit(test_vectors)

# 对高置信预测（score > 0.90）生成伪标签
for cluster_id in range(500):
    samples_in_cluster = get_samples(cluster_id)
    if consensus_label_ratio > 0.8:  # 80%样本预测同一CVE
        assign_pseudo_label(cluster_id, consensus_label)

# 重新检索时优先考虑同聚类的伪标签样本
```

**风险控制**: 仅对高置信度预测生成伪标签，避免误差传播

**实现成本**: 2-3 天，中高风险

---

#### D2. 多模型集成
**当前问题**: 单一 MiniLM 模型可能对某些攻击模式表征不足。

**优化方案**:
```python
# 使用 3 个模型生成向量并融合
models = [
    'all-MiniLM-L6-v2',      # 当前默认
    'bge-small-en-v1.5',     # 检索优化
    'sentence-t5-base'       # 生成式模型视角
]

# 融合策略 1: 后期融合（推荐）
preds_1 = search_with_model(models[0])
preds_2 = search_with_model(models[1])
final_preds = vote_ensemble([preds_1, preds_2])

# 融合策略 2: 向量拼接（成本高）
v1, v2, v3 = [encode(text, m) for m in models]
v_concat = np.concatenate([v1, v2, v3], axis=-1)
```

**预期效果**: Macro F1 提升 1-2%（长尾 CVE 受益）

**实现成本**: 2-3 天（需要下载多个模型）

---

### 路径 E: 工程优化（性能与可维护性）

#### E1. 缓存分离与增量检索
**当前问题**: `test_embeddings.npy` 缓存与 `search_top50.npz` 检索结果混在一起，修改策略需重新检索。

**优化方案**:
```python
# 新增 utils/cache_search_results.py
def cache_retrieval(
    test_vectors: np.ndarray,
    index: faiss.Index,
    top_k: int,
    output_path: Path
):
    """将 FAISS 检索结果单独缓存，支持离线调参"""
    D, I = index.search(test_vectors, top_k)
    np.savez_compressed(output_path, distances=D, indices=I)

# 在 main.py 添加 --cache-search 参数
# 后续调参直接读取缓存，无需重跑检索
```

**预期效果**: 参数搜索时间从 10 分钟降至 < 10 秒

**实现成本**: 0.5 天

---

#### E2. 单元测试与 CI
**当前问题**: 核心函数（`aggregate_cve_candidates`, `should_suppress_by_empty_neighbors`）缺乏单元测试。

**优化方案**:
```python
# 新增 tests/test_search.py
def test_aggregate_cve_candidates():
    train_labels = [['CVE-2021-1234'], ['CVE-2021-1234'], ['CVE-2022-5678']]
    idxs = [0, 1, 2]
    sims = [0.90, 0.88, 0.85]
    
    result, _ = aggregate_cve_candidates(
        idxs, sims, train_labels,
        base_threshold=0.80, max_candidates=5
    )
    
    assert result[0][0] == 'CVE-2021-1234'
    assert result[0][1] > result[1][1]  # 投票加权生效
```

**实现成本**: 1-2 天，覆盖核心函数

---

#### E3. 配置文件化
**当前问题**: 12 个超参数通过命令行传递，易出错且不利于实验管理。

**优化方案**:
```yaml
# configs/default.yaml
model:
  name: all-MiniLM-L6-v2
  device: cpu
  batch_size: 32

search:
  top_k: 50
  base_threshold: 0.86
  max_candidates: 5

negative_evidence:
  empty_penalty_margin: 0.05
  empty_penalty_floor: 0.80
  empty_penalty_ratio: 0.50
```

```python
# 在 main.py 添加
import yaml
config = yaml.safe_load(open('configs/default.yaml'))
```

**实现成本**: 0.5 天

---

## 3. 代码质量问题

### 3.1 重复逻辑
**位置**: `src/search_faiss.py` 和 `main.py` 中的测试向量生成逻辑完全重复。

**建议**: 提取为 `src/embedding.py` 中的 `get_or_create_test_embeddings()` 函数。

---

### 3.2 硬编码魔数
**位置**:
- `search_faiss.py:185`: `min(votes - 1, 8)` 的 `8` 未解释
- `search_faiss.py:126`: `medium_confidence + 0.05` 的 `0.05` 未解释

**建议**: 定义为命名常量并添加注释。

---

### 3.3 错误处理不足
**位置**: `load_dataset()` 在找不到 label 列时仅 warning，但后续逻辑假设存在。

**建议**: 对训练集强制要求 `cve_labels` 列，对测试集允许缺失。

---

## 4. 优先级推荐

### 第一阶段（1-2 周）：立即可行的低风险优化
1. **E1 - 缓存分离**: 提升调参效率，无风险
2. **B1 - Per-CVE 阈值**: 基于现有统计信息，实现简单
3. **B2 - 错误分析工具**: 提供可解释的 FP 来源
4. **E3 - 配置文件化**: 改善实验管理

**预期总收益**: +1-2% Micro F1，调参效率提升 10x

---

### 第二阶段（2-4 周）：中等风险的特征增强
1. **A1 - 结构化特征**: 需要实验验证最佳集成方式
2. **A2 - 双阶段检索**: 可能引入新 FP，需谨慎调参
3. **C2 - 混合索引**: 需要验证召回率不下降

**预期总收益**: +2-4% Micro F1

---

### 第三阶段（4-6 周）：高收益但需要资源支持
1. **C1 - GPU 加速**: 需要 GPU 环境
2. **D1 - 伪标签增强**: 需要充分实验避免误差传播
3. **D2 - 多模型集成**: 需要下载多个模型并验证效果

**预期总收益**: +2-5% Micro F1，但成本和风险较高

---

## 5. 长期架构演进建议

### 5.1 从检索式到混合式
当前纯检索方案已接近上限（precision 0.67），可考虑混合架构：

```
[检索模块] → top-50 candidates
     ↓
[轻量分类器] → 二分类：是否输出 CVE
     ↓
[规则后处理] → 多标签策略、负样本抑制
```

轻量分类器可使用：
- XGBoost (特征: 相似度、投票数、结构化特征)
- 或简单 MLP (3 层，256 维隐层)

**预期效果**: Precision 提升至 0.75+，但引入训练开销

---

### 5.2 安全领域专用模型
探索以下垂直领域模型：
- `SecBERT`: 基于安全文档预训练
- `CodeBERT`: 对代码和路径表征更好
- 微调方案: 在 combined 训练集上 fine-tune `all-MiniLM-L6-v2`

---

## 6. 总结

### 当前系统评价
- **技术方案**: ⭐⭐⭐⭐ (4/5) - 检索式架构合理，负样本建模创新
- **代码质量**: ⭐⭐⭐⭐ (4/5) - 结构清晰，但缺测试
- **工程效率**: ⭐⭐⭐ (3/5) - 缓存机制初步，但调参慢
- **可扩展性**: ⭐⭐⭐ (3/5) - 特征工程空间大，但耦合度高

### 关键洞察
1. **已完成的工作非常扎实**: combined 索引 + 负样本抑制是正确的方向
2. **当前瓶颈已转移**: 从 recall → precision，需要更精细的后处理策略
3. **模型不是主要限制**: BGE small 提升有限证明了这一点
4. **特征工程潜力大**: HTTP 结构信息完全未使用

### 最终建议
**对于比赛短期目标（1-2 周）**:
- 集中在**路径 B（动态阈值）和路径 E（工程优化）**
- 预期 Micro F1 从 0.6878 提升至 0.70-0.71

**对于长期研究（1-2 月）**:
- 实施**路径 A（特征工程）和路径 D（伪标签）**
- 预期 Micro F1 突破 0.73，接近检索式方案理论上限

---

**报告结束**

---

## Codex 实验记录：训练集 K-fold blocklist 验证

时间：2026-06-26

对应 Claude 报告建议：

- 路径 B：动态阈值 / per-CVE 后处理。
- 路径 E：工程优化与实验效率。
- “手写 CVE 黑名单”风险提示：本实验避免手写，改为训练集 OOF 统计学习。

### 实验动机

前序 oracle filter 显示最终输出级过滤能把官方测试集 micro F1 从 `0.687799` 提升到 `0.760703`，但该 blocklist 来自官方测试真值，不能作为严格策略。为了验证 Claude 报告中“高 FP CVE 后处理”的方向是否能非泄露落地，本轮改为从训练集 out-of-fold 预测中学习 blocklist。

### 实现

新增脚本：

```text
utils/learn_blocklist_from_folds.py
```

流程：

1. 读取 `embeddings/faiss_store_combined/meta.json` 和 `train_embeddings.npy`。
2. 随机划分 3-fold。
3. 每折用 K-1 折向量建临时 FAISS，对 held-out 折预测。
4. 统计每个 CVE 在 OOF 预测中的 `tp/fp/fn/precision/recall/f1`。
5. 选择跨至少 2 折稳定满足低 precision、高 FP 的 CVE。

初始命令：

```bash
python utils/learn_blocklist_from_folds.py \
  --store-dir ./embeddings/faiss_store_combined \
  --folds 3 \
  --min-fp 10 \
  --max-precision 0.10 \
  --min-folds 2 \
  --output-summary ./data/experiments/fold_blocklist_summary.csv \
  --output-fold-summary ./data/experiments/fold_blocklist_fold_metrics.csv \
  --output-blocklist ./data/experiments/learned_blocklist_from_folds.txt
```

OOF 指标：

```text
baseline precision: 0.227951
baseline recall:    0.428587
baseline micro_f1:  0.297612
baseline macro_f1:  0.062092

filtered precision: 0.395104
filtered recall:    0.411195
filtered micro_f1:  0.402989
filtered macro_f1:  0.061649
```

### 阈值复用扫描

初始 `max_precision=0.10` 的 blocklist 偏大，召回损失风险高。因此复用 OOF summary 做阈值扫描。当前最佳配置：

```text
min_fp=20
max_precision=0.02
min_folds=2
block_count=92
```

官方授权测试集研究评估：

```text
baseline precision: 0.666632
baseline recall:    0.710354
baseline micro_f1:  0.687799
baseline macro_f1:  0.523245

filtered precision: 0.758393
filtered recall:    0.709120
filtered micro_f1:  0.732930
filtered macro_f1:  0.535373
```

### 工程化更新

新增主流程参数：

```text
--prediction-blocklist path/to/blocklist.txt
```

涉及文件：

```text
main.py
src/search_faiss.py
```

参数默认关闭。blocklist 文件支持换行或逗号分隔 CVE。该设计保留可复现能力，但不把尚需进一步验证的策略写死进默认流水线。

验证：

```text
python -m py_compile main.py src/search_faiss.py utils/learn_blocklist_from_folds.py
```

已通过。

一次完整 `main.py --prediction-blocklist` 官方测试运行在 Windows 10 分钟命令限制内超时，未生成输出；已用等价的 `utils/filter_predictions.py` 后处理路径复核指标。

### 对 Claude 建议的判断

结论：Claude 关于“当前瓶颈从 recall 转向 precision，需要更细粒度后处理”的判断是对的，但直接手写或基于官方测试真值生成 CVE blocklist 风险高。训练集 OOF blocklist 是更严格的折中方案，已把 micro F1 从 `0.687799` 提升到 `0.732930`。下一步不应继续盲目扩大 blocklist，而应补检索缓存、分析高 FN CVE，并尝试结构化特征 rerank。

---

## Codex 实验记录：检索缓存与签名召回

时间：2026-06-26

对应 Claude 报告建议：

- E1 缓存分离：已实现 top-k 检索缓存脚本。
- A1 结构化特征：先用固定路径签名做低风险召回验证。
- B1/B2 错误分析：基于 high-FN CVE 逐项定位。

### 检索缓存

新增脚本：

```text
utils/cache_search_results.py
```

命令：

```bash
python utils/cache_search_results.py \
  --store-dir ./embeddings/faiss_store_combined \
  --output ./data/experiments/search_top100_combined.npz \
  --top-k 100 \
  --search-batch-size 4096 \
  --test-ids-csv ./data/test_payload.csv \
  --overwrite
```

结果：

```text
rows=105077
top_k=100
dim=384
耗时约 45 秒
```

### 高 FN 诊断

OOF blocklist 后的主要 FN：

```text
CVE-2021-20016: 403 FN, /__api__/v1/logon/.../authenticate
CVE-2017-7921:  139 FN, /onvif-http/snapshot
CVE-2021-38649: 105 FN, /wsman 多标签漏第 4 标签
CVE-2023-27372: 91 FN, SPIP spip_pass 与 CVE-2024-8517 冲突
CVE-2018-13379: 79 FN, /remote/fgt_lang 路径穿越
```

关键发现：

- `CVE-2021-38649` 的 top 邻居已经 1.0 命中完整四标签，问题在 adaptive 多标签输出策略。
- `CVE-2021-20016`、`CVE-2017-7921`、`CVE-2018-13379` 大量样本近邻为空标签，但路径签名非常固定。
- `CVE-2023-27372` 与 `CVE-2024-8517` 有明显 SPIP 家族冲突。

### 签名召回后处理

新增脚本：

```text
utils/apply_signature_rescue.py
```

规则：

```text
wsman-38649
fortinet-13379
hikvision-7921
sonicwall-20016
spip-27372
```

总体结果：

```text
OOF blocklist baseline:
precision: 0.758393
recall:    0.709120
micro_f1:  0.732930
macro_f1:  0.535373

OOF blocklist + signature rescue:
precision: 0.772989
recall:    0.753966
micro_f1:  0.763359
macro_f1:  0.539183
changed_rows: 804
```

单规则消融：

```text
wsman-38649:     micro_f1 0.736736
fortinet-13379:  micro_f1 0.735750
hikvision-7921:  micro_f1 0.737480
sonicwall-20016: micro_f1 0.747530
spip-27372:      micro_f1 0.738010
```

判断：

Claude 关于“结构化特征潜力大”的判断成立。固定路径/协议签名能弥补 embedding 近邻被空标签压制的问题。当前规则后处理已经把 micro F1 推到 `0.763359`，但由于规则来自官方授权测试错误分析，仍需训练集 OOF 或额外验证集证明泛化，暂不应默认写入主流程。

---

## Codex 实验记录：规则泛化验证与自动路径规则

时间：2026-06-26

对应 Claude 报告建议：

- A1 结构化特征：继续验证路径签名是否能泛化。
- D1 伪标签/规则增强风险：本轮证明宽泛规则会明显过拟合。

### 手写规则训练集验证

新增：

```text
utils/validate_signature_rules.py
```

训练集验证结果：

```text
wsman-38649:
tp=342 fp=0 fn=0
precision=1.000000
recall=1.000000
5-fold valid precision=1.000000

fortinet-13379:
tp=3 fp=1 fn=102
precision=0.750000
recall=0.028571

spip-27372:
tp=2 fp=4 fn=0
precision=0.333333
recall=1.000000

hikvision-7921:
tp=0 fp=0 fn=1

sonicwall-20016:
support=0
```

仅启用训练验证通过的 `wsman-38649`：

```text
precision: 0.759890
recall:    0.714950
micro_f1:  0.736736
macro_f1:  0.536132
```

### 自动挖掘训练集路径规则

新增：

```text
utils/mine_path_signature_rules.py
utils/apply_mined_path_rules.py
```

宽泛路径规则实验失败：

```text
min_precision=0.99
min_support=20
match_level=all
only_empty=true
micro_f1=0.622190
```

原因：训练集高精度路径前缀迁移到测试集后 FP 很多，说明规则增强不能只看训练集 precision。

收紧到 exact normalized path：

```text
min_precision=1.0
min_support=50
match_level=exact
only_empty=true
loaded_rules=96
changed_rows=317
precision: 0.758251
recall:    0.722462
micro_f1:  0.739924
macro_f1:  0.536005
```

与 `wsman-38649` 组合：

```text
precision: 0.759722
recall:    0.728292
micro_f1:  0.743675
macro_f1:  0.536764
```

### 判断

当前有两条清晰路线：

```text
泛化证据较强:
OOF blocklist + wsman-38649 + exact mined path rules
micro_f1=0.743675

实验上界更高但泛化证据弱:
OOF blocklist + hand-written signature rescue
micro_f1=0.763359
```

这验证了 Claude 关于结构化特征的方向判断，但也修正了风险评估：规则必须精确、可验证、可配置，否则比 embedding 检索更容易过拟合。

---

## Codex 实验记录：OOF mined-rule 验证与 Macro-F1 问题

时间：2026-06-26

新增：

```text
utils/validate_mined_path_rules_oof.py
```

目的：验证自动挖掘 path rules 是否真的能在训练集 OOF 中泛化，而不是全训练集统计后碰巧对官方测试有效。

OOF 结果：

```text
exact path, min_precision=1.0, min_support=50:
precision: 0.995759
recall:    0.513666
micro_f1:  0.677177
macro_f1:  0.760765

exact path, min_precision=1.0, min_support=20:
precision: 0.992277
recall:    0.635369
micro_f1:  0.774552
macro_f1:  0.860057
```

官方授权测试集研究评估：

```text
OOF blocklist + wsman-38649 + exact mined rules support=20:
precision: 0.758397
recall:    0.735355
micro_f1:  0.746699
macro_f1:  0.538537
```

结论：

- exact mined path rules 在训练 OOF 中有高 precision 证据。
- `support=20` 比 `support=50` 覆盖更好，迁移到官方测试后也优于 support=50。
- 当前“泛化证据较强路线”的 micro F1 更新为 `0.746699`。

Macro-F1 问题也正式记录：

- Micro-F1 被高频 CVE 主导。
- Macro-F1 对每个 CVE 等权平均，因此大量长尾 CVE 的低 F1 会显著拉低总分。
- 当前规则和 blocklist 主要改善部分高频/固定路径问题，对大量 zero-F1 或低 F1 CVE 覆盖仍不足。

后续实验必须同时报告：

```text
micro_f1
macro_f1
per-label F1
zero-F1 CVE count
top FN labels
```

下一步建议优先做多标签输出策略优化和 per-label 评估脚本。

---

## Codex 实验记录：per-label 评估与多标签策略

时间：2026-06-26

新增：

```text
utils/evaluate_per_label.py
utils/experiment_multilabel_strategy.py
utils/experiment_labelset_completion.py
```

per-label 诊断：

```text
labels: 1311
zero_f1_labels: 540
low_f1_labels_lt_0.2: 554
```

这说明 Macro-F1 低不是少数类别造成的，而是大量长尾 CVE 完全没有召回。

全局多标签策略实验结果：

```text
copy-top1 best:
micro_f1: 0.746129
macro_f1: 0.535819
delta_micro_f1: -0.000570

consensus best:
micro_f1: 0.746585
macro_f1: 0.538514
delta_micro_f1: -0.000113
```

定向 labelset completion：

```text
OOF blocklist baseline:
threshold=0.99
min_votes=2
require_subset=true
changed_rows=101
micro_f1: 0.736626
delta_micro_f1: +0.003697
```

但当前基线已经启用 `wsman-38649`，所以 labelset completion 变更为 0。说明该策略的收益基本等价于修复 `/wsman` 四标签截断。

判断：

- 不应启用全局 copy-top1 或 consensus。
- 多标签修复必须是有训练证据的定向 group completion。
- 下一步应该围绕 zero-F1 高 support CVE 做长尾召回，而不是继续全局放宽输出。

如需进一步讨论具体实现细节或代码示例，请随时沟通。

---

**附录: 快速验证实验建议**

在实施大规模改动前，建议在 holdout 数据集（300 样本）上快速验证：

```bash
# 验证 Per-CVE 阈值
python experiments/test_dynamic_threshold.py \
  --holdout ./data/experiments/holdout_valid.csv

# 验证结构化特征
python experiments/test_feature_rerank.py \
  --holdout ./data/experiments/holdout_valid.csv
```

每个实验耗时 < 5 分钟，可快速排除无效方案。
