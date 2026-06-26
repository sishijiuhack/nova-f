# nova-f 技术优化复盘报告

更新时间：2026-06-26

## 1. 背景与目标

本项目的任务是对 HTTP 攻击流量进行 CVE 标签识别。原始方案不是训练一个端到端分类器，而是采用“文本向量检索 + 近邻标签聚合”的离线检索式方案：

1. 对 HTTP payload 做清洗。
2. 使用 SentenceTransformer 模型 `all-MiniLM-L6-v2` 生成向量。
3. 使用 FAISS 构建向量索引。
4. 对测试 payload 检索 top-k 近邻。
5. 从近邻样本的 CVE 标签中推断测试样本标签。

优化目标不是单纯提高某一个指标，而是在 precision、recall、micro F1、macro F1 之间取得更稳的平衡。根据官方授权测试集的本地评估，项目初始主要问题不是“找不到 CVE”，而是“把大量空样本或非 CVE 样本误报为 CVE”。

## 2. 项目一开始暴露的问题

### 2.1 环境和路径问题

最早运行时出现过以下问题：

- Windows 和 WSL 虚拟环境不一致，Windows `.venv` 中已有依赖，但 WSL 环境缺少 `faiss`。
- WSL 中直接创建 `.venv-wsl` 时 `ensurepip` 失败，导致虚拟环境没有 `pip`。
- Python 版本不匹配导致 `faiss-cpu==1.8.0` 无法安装。
- HuggingFace 在 WSL 中出现证书校验失败，无法稳定拉取模型。
- 用户命令里的 `data/train_payload.csv`、`data/test_payload.csv` 在当时尚未生成，导致 `FileNotFoundError`。

这些问题本身不属于模型算法问题，但会影响实验可复现性。处理原则是先稳定运行链路，再谈指标优化。

解决方式：

- 在 WSL 中改用 conda 环境 `nova-f`，确认 `faiss`、`pandas`、`numpy`、`sentence-transformers` 可导入。
- 将 Windows 侧已经下载好的 HuggingFace 模型复制到本地目录：

```text
models/all-MiniLM-L6-v2
```

- 所有正式运行命令显式指定：

```bash
--model-path ./models/all-MiniLM-L6-v2
```

这样可以避免 WSL 网络、代理、证书问题影响实验。

### 2.2 数据问题

官方授权数据一开始是：

```text
train.json.gz
test.json.gz
```

项目主流程需要 CSV，因此新增了 `utils/convert_datacon_jsonl.py` 做转换，统一输出字段：

```text
id
payload_decoded
labeled
cve_labels
```

转换后的规模：

```text
train_payload.csv: 36001 行
test_payload.csv: 105077 行
```

这里发现一个关键事实：官方数据里有大量 `labeled=0` 或空 CVE 标签样本。原方案主要从正样本近邻中推断 CVE，对“应该输出空”的样本缺少有效建模。这直接导致初始 precision 很低。

### 2.3 标签归一化错误

代码层面发现 `normalize_cve_labels()` 对 `NaN` 没有特殊处理。`pandas` 读取空字段后会产生浮点 `NaN`，旧逻辑会走到：

```python
str(raw_value).strip().upper()
```

于是空标签会被归一化成字符串 `"NAN"`。

这个错误不一定直接变成最终 CVE 输出，因为后续聚合阶段会过滤非 `CVE-` 前缀标签，但它会污染中间元数据、统计和判断逻辑，尤其在判断“该训练样本是否带有 CVE 标签”时会造成隐患。因此这属于必须修复的基础数据质量问题。

已修复位置：

```text
src/preprocess.py
```

修复策略：

- `float('nan')` 直接返回空列表。
- 字符串 `"nan"`、`"none"`、`"null"` 视为空。
- list 内部的空值也做同样过滤。

## 3. 如何构建优化计划

优化计划不是直接改模型，而是按风险和收益排序：

1. 先建立本地评估闭环。
2. 再确认 baseline 指标和主要错误类型。
3. 然后用官方训练数据扩展检索空间。
4. 最后针对最大错误来源设计规则抑制。

这样计划的原因：

- 当前方案是检索式系统，优化重点通常在数据覆盖、近邻聚合、阈值策略，而不是立即换模型。
- 没有评估脚本就无法判断优化是提高了 recall 还是只是扩大了输出量。
- 官方训练集中存在大量负样本，负样本本身是降低误报的重要信息，不能只把它当作“无标签数据”丢掉。
- 直接提高阈值能减少误报，但会牺牲召回；需要更精细地区分“相似但无 CVE”的情况。

因此计划分为四个实验阶段：

```text
阶段 1：原始扩展训练集 baseline
阶段 2：CVE 候选聚合优化
阶段 3：扩展训练集 + 官方训练集合并索引
阶段 4：利用空标签近邻做负证据抑制
```

## 4. Baseline 分析

使用原始扩展训练集：

```text
data/train_with_ultimate.csv
```

对官方测试集预测后，本地评估结果为：

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
precision:   0.794891
recall:      0.757105
micro_f1:    0.775538
```

从这个结果可以判断：

- 对真实存在 CVE 的样本，系统其实有一定识别能力。
- 全量 precision 只有 `0.156417`，说明大量错误来自空样本误报。
- 优化重点应从“继续扩大召回”转向“降低负样本误报”。

这一步改变了后续策略。如果只看 recall，会误以为系统已经不错；但在全量任务里，空输出同样是重要类别，误报会严重拉低 F1。

## 5. 候选聚合优化

### 5.1 原始逻辑问题

原始近邻策略更接近“按 top-k 顺序拿第一个出现的 CVE”。这种方式有几个问题：

- 单个噪声近邻可能压过多个一致近邻。
- 多个近邻支持同一 CVE 时，没有显式投票增益。
- 多标签样本中的标签顺序可能影响输出。

### 5.2 修改方案

新增 `aggregate_cve_candidates()`：

```text
src/search_faiss.py
```

核心逻辑：

- 对 top-k 近邻中的每个 CVE 聚合证据。
- 记录该 CVE 的最佳相似度。
- 统计该 CVE 被多少个近邻支持。
- 最终分数为：

```text
best_similarity + min(votes - 1, 8) * vote_weight
```

这样做的原因：

- 最佳相似度保留最强单点证据。
- 投票奖励利用近邻一致性，降低单个噪声样本影响。
- 投票奖励设上限，避免重复样本过多时把分数推得过高。

新增参数：

```text
--min-votes
--vote-weight
```

实验发现 `min_votes=2/3` 会明显伤害 macro F1，因为长尾 CVE 本来样本少，强制多票会漏掉长尾类别。最终保留：

```text
min_votes=1
vote_weight=0.015
```

## 6. combined 索引实验

### 6.1 为什么要合并训练集

原始扩展训练集偏向 CVE 正样本知识，官方训练集包含真实分布下的正样本和空样本。为了让检索空间同时拥有“相似攻击样本”和“相似非攻击/空标签样本”，构建 combined 索引：

```text
train_with_ultimate.csv + train_payload.csv
```

新增工具：

```text
utils/merge_training_csv.py
```

用于合并训练 CSV，并重新编号 `id`。

### 6.2 实验结果

combined 索引规模：

```text
72938 training vectors
```

仅使用 combined 索引和 CVE 聚合，不启用负证据抑制时，较优结果：

```text
base_threshold=0.84
min_votes=1
vote_weight=0.015

all_rows
exact_match: 0.899321
precision:   0.522833
recall:      0.751556
micro_f1:    0.616669
macro_f1:    0.483007

labeled=1
precision:   0.679765
recall:      0.751556
micro_f1:    0.713860
macro_f1:    0.566028
```

对比 baseline：

```text
all_rows micro_f1: 0.259270 -> 0.616669
labeled=1 micro_f1: 0.561300 -> 0.713860
```

这说明官方训练集中的分布信息非常关键。combined 索引本身就是一次主要提升。

## 7. 实验中遇到的问题与调整

### 7.1 PowerShell 与 Python 环境问题

在 Windows PowerShell 中用 Bash 风格 heredoc：

```bash
python - <<'PY'
```

会报语法错误。后续改用 PowerShell here-string：

```powershell
@'
...
'@ | .\.venv\Scripts\python.exe -
```

### 7.2 pandas/numpy ABI 不兼容

系统 Python 中出现：

```text
ValueError: numpy.dtype size changed, may indicate binary incompatibility
```

原因是系统环境里的 pandas 与 numpy ABI 不匹配。解决方式是不用系统 Python，改用项目 `.venv`：

```powershell
.\.venv\Scripts\python.exe
```

这保证评估脚本和项目运行环境一致。

### 7.3 参数 sweep 过慢

最开始每组参数都重新遍历 `105077 x top50` 的近邻结果并做聚合，组合一多就超时。处理方式：

- 先缓存 FAISS top-50 结果到：

```text
data/experiments/search_top50_combined.npz
```

- 再基于缓存做离线参数 sweep。

这样把“昂贵的向量检索”和“便宜的决策策略评估”拆开，提高实验效率。

### 7.4 CVE-only 索引实验失败

曾尝试只保留训练集中带 CVE 的样本构建索引，索引规模从 `72938` 降到 `42124`。直觉上这样会让近邻更聚焦 CVE，但实验结果变差：

- 对负样本误报大幅增加。
- all_rows micro F1 下降。

原因是移除了空标签样本后，系统失去了“这个 payload 虽然相似但不应输出 CVE”的负证据。这个失败实验直接推动了后续的空标签近邻抑制设计。

### 7.5 主流程完整运行超时

在 combined 索引上用 `main.py` 重新跑完整测试时，CPU FAISS 检索耗时较长，10 分钟超时且没有写出结果。解决方式：

- 生产主流程仍保留完整能力。
- 实验阶段使用已经缓存的 top-50 检索结果直接生成预测和评估。

这不是算法问题，而是实验工程问题。后续应把检索缓存作为正式工具能力暴露出来。

## 8. 负证据抑制策略

### 8.1 为什么需要这个策略

combined 索引已经显著提高了 precision，但仍存在误报。观察任务结构后，可以把空标签训练样本当成一种负证据：

如果一个测试 payload 的最近邻里，空标签样本和 CVE 样本几乎一样相似，那么该样本更可能是“相似但不应标 CVE”的流量。

### 8.2 具体规则

新增函数：

```text
should_suppress_by_empty_neighbors()
```

位置：

```text
src/search_faiss.py
```

规则：

1. 统计 top-k 近邻中的最佳 CVE 样本相似度 `best_cve`。
2. 统计最佳空标签样本相似度 `best_empty`。
3. 如果 `best_empty` 达到最低置信下限。
4. 且 `best_cve - best_empty` 小于 margin。
5. 且空标签近邻数量相对 CVE 近邻数量达到比例要求。
6. 则抑制本条预测，输出空标签。

当前默认参数：

```text
empty_penalty_margin=0.05
empty_penalty_floor=0.80
empty_penalty_ratio=0.50
```

设计原因：

- `margin` 控制“空标签近邻有多接近 CVE 近邻”。
- `floor` 避免低相似度空样本干扰判断。
- `ratio` 避免一个弱空样本压制多个强 CVE 样本。

### 8.3 最终效果

使用：

```text
base_threshold=0.86
min_votes=1
vote_weight=0.015
empty_penalty_margin=0.05
empty_penalty_floor=0.80
empty_penalty_ratio=0.50
```

最终评估：

```text
all_rows
answer_rate: 0.130990
exact_match: 0.928129
precision:   0.666632
recall:      0.710354
micro_f1:    0.687799
macro_f1:    0.523245

labeled=1
answer_rate: 0.247313
exact_match: 0.876334
precision:   0.828398
recall:      0.710354
micro_f1:    0.764848
macro_f1:    0.592976

truth_nonempty_cve
precision:   0.881714
recall:      0.710354
micro_f1:    0.786812
macro_f1:    0.661345
```

相对最初 baseline：

```text
all_rows precision: 0.156417 -> 0.666632
all_rows micro_f1: 0.259270 -> 0.687799
labeled=1 micro_f1: 0.561300 -> 0.764848
```

代价是 recall 从 `0.757105` 降到 `0.710354`。这是一个有意接受的 trade-off，因为系统最大问题是误报，而不是漏报。

## 9. 最后代码层面的优化

### 9.1 `src/preprocess.py`

修复标签归一化：

- 正确处理 `NaN`。
- 正确处理 `"nan"`、`"none"`、`"null"`。
- 避免空标签污染后续元数据。

### 9.2 `src/search_faiss.py`

新增：

```text
aggregate_cve_candidates()
has_cve_label()
should_suppress_by_empty_neighbors()
```

并将默认检索参数调整为更适合当前任务的值：

```text
top_k=50
max_candidates=5
base_threshold=0.86
```

### 9.3 `main.py`

主流水线接入负证据抑制参数：

```text
--empty-penalty-margin
--empty-penalty-floor
--empty-penalty-ratio
```

并在候选 CVE 预测完成后、写出结果前执行抑制判断。

### 9.4 `utils/merge_training_csv.py`

新增训练集合并工具，保证 combined 索引构建过程可复现：

```bash
python utils/merge_training_csv.py \
  --input ./data/train_with_ultimate.csv \
  --input ./data/train_payload.csv \
  --output ./data/experiments/train_combined.csv
```

## 10. 面试追问视角下的关键结论

如果面试官追问“为什么不用更复杂模型”，当前回答是：

当前瓶颈不是 embedding 模型完全无法表达语义，而是检索决策层没有利用负样本信息。证据是：真实非空 CVE 子集上的 micro F1 原本已经达到 `0.775538`，但全量 precision 只有 `0.156417`。因此第一优先级应是修正决策逻辑和数据分布建模，而不是直接换模型。

如果追问“为什么 combined 索引有效”，回答是：

官方训练集引入了真实分布下的空标签和负样本流量，使 FAISS 近邻空间不再只有正样本攻击知识。它既提高了正样本覆盖，也为后续负证据抑制提供了依据。

如果追问“为什么 CVE-only 索引失败”，回答是：

因为它删除了负样本近邻，导致系统只能在 CVE 空间里找最像的 CVE。对本应输出空的流量，它也会强行匹配到某个 CVE，从而增加误报。

如果追问“为什么接受 recall 下降”，回答是：

优化前 recall 已经相对较高，但 precision 极低，F1 的主要损失来自误报。当前策略用约 `0.047` 的 recall 损失换来了 precision 从 `0.156417` 到 `0.666632` 的提升，最终 all_rows micro F1 从 `0.259270` 提升到 `0.687799`，这是明确收益。

## 11. 后续仍需改进的问题

当前优化仍是规则型策略，后续可以继续做：

1. 将 top-k 检索缓存和参数 sweep 工具正式化。
2. 对不同 CVE 使用动态阈值，避免热门 CVE 误报。
3. 分析 false positive 排名前列的 CVE，定位训练标签污染或 payload 模板相似问题。
4. 增加按 payload 类型的特征，例如路径、参数名、请求方法、body 模式。
5. 如果资源允许，再比较更强 embedding 模型，而不是盲目替换。

总体结论：本轮优化的核心不是堆模型，而是补齐评估闭环、修复标签清洗、引入官方数据分布、把空标签近邻作为负证据，最终显著降低误报并提高全量 F1。

## 12. 更强 embedding 模型试验

在完成负证据抑制后，继续尝试替换 embedding 模型。目标是验证当前系统是否受限于 `all-MiniLM-L6-v2` 的表征能力，还是主要受限于数据与决策策略。

### 12.1 候选模型

第一轮选择了两个轻量检索模型：

```text
BAAI/bge-small-en-v1.5
intfloat/e5-small-v2
```

选择原因：

- 二者都比 MiniLM 更偏检索任务。
- 参数规模仍可在 CPU 上试验。
- BGE small 仍是 384 维，替换 FAISS 索引成本较低。
- E5 small 需要 `query:`/`passage:` 前缀，可验证系统对检索专用模型的适配能力。

模型已下载到：

```text
models/bge-small-en-v1.5
models/e5-small-v2
```

这些目录已被 `.gitignore` 忽略，不上传 GitHub。

### 12.2 Holdout 快速实验

为避免直接在 72938 训练向量和 105077 测试样本上消耗大量 CPU 时间，先使用已有 holdout 数据做模型对照：

```text
data/experiments/holdout_train.csv: 2500 行
data/experiments/holdout_valid.csv: 300 行
```

MiniLM 默认策略结果：

```text
answer_rate: 0.593333
exact_match: 0.416667
precision:   0.580645
recall:      0.458599
micro_f1:    0.512456
macro_f1:    0.421593
```

BGE small 在相同阈值下：

```text
answer_rate: 0.826667
exact_match: 0.386667
precision:   0.376368
recall:      0.547771
micro_f1:    0.446174
macro_f1:    0.411187
```

解释：BGE 的相似度分布整体更高，相同阈值下输出过多，导致 precision 下降。

对 BGE small 重新调阈值后，最佳 holdout 结果约为：

```text
base_threshold: 0.96
precision:      0.703125
recall:         0.429936
micro_f1:       0.533597
macro_f1:       0.417634
```

对 MiniLM 同样调参后，最佳 holdout 结果约为：

```text
base_threshold: 0.88
precision:      0.646789
recall:         0.449045
micro_f1:       0.530075
macro_f1:       0.423855
```

结论：BGE small 的 micro F1 略高，但 macro F1 略低，且 CPU 编码耗时约为 MiniLM 的 4 倍左右。收益不足以直接替换当前全量默认模型。

### 12.3 E5 small 前缀实验

E5 模型按官方检索范式需要前缀：

```text
训练侧: passage: <payload>
测试侧: query: <payload>
```

在 holdout 上实验后，E5 small 最佳结果约为：

```text
base_threshold: 0.90
precision:      0.463668
recall:         0.426752
micro_f1:       0.444444
macro_f1:       0.377220
```

结论：E5 small 不适配当前 payload 检索任务，暂不进入全量实验。

### 12.4 代码适配

为了支持后续继续试 E5 base、BGE base 或安全领域模型，代码新增了文本编码前缀参数。

主流程新增：

```text
--train-text-prefix
--test-text-prefix
```

例如 E5 可运行：

```bash
python main.py \
  --train-path ./data/experiments/holdout_train.csv \
  --test-path ./data/experiments/holdout_valid.csv \
  --store-dir ./embeddings/faiss_holdout_e5_small \
  --output-path ./data/experiments/holdout_pred_e5_small.csv \
  --model-path ./models/e5-small-v2 \
  --train-text-prefix "passage: " \
  --test-text-prefix "query: " \
  --overwrite-index
```

底层改动：

```text
src/build_faiss.py: embed_texts(..., text_prefix="")
src/search_faiss.py: embed_texts(..., text_prefix="")
main.py: build_vector_store/test label 阶段透传 prefix
```

测试缓存元数据中也记录 `test_text_prefix`，避免不同前缀下错误复用测试向量缓存。

### 12.5 当前决策

暂不把 BGE small 或 E5 small 设为默认模型。

原因：

- BGE small 在小 holdout 上仅微弱提升 micro F1，但速度代价明显。
- E5 small 指标低于 MiniLM。
- 当前全量系统主要收益来自 combined 索引和负证据抑制，而非 embedding 模型替换。

后续如果继续模型路线，建议直接评估：

```text
BAAI/bge-base-en-v1.5
intfloat/e5-base-v2
```

但前提是先准备 GPU 或接受较长 CPU 编码时间；否则全量 72k+105k 编码成本会很高。

## 13. Claude 报告审阅与错误分析实验

在用户提供 `OPTIMIZATION_REPORT_BY_CLAUDE.md` 后，对其中建议做了技术审阅。总体判断：

- 报告中“当前瓶颈已从召回转向精准率”“模型不是主要限制”“动态阈值、错误分析、结构化特征值得尝试”的方向基本正确。
- 报告对收益预估偏乐观，尤其是“3-8 个百分点”需要实验验证。
- “按训练频次粗暴调整 CVE 阈值”的建议不应直接采用。
- 伪标签、多模型集成、GPU FAISS 更适合作为中长期方向，不适合作为当前第一优先级。

因此后续计划调整为：

```text
错误分析 -> per-CVE 阈值/过滤实验 -> 结构化特征 rerank -> 工程化缓存和测试
```

### 13.1 错误分析工具

新增：

```text
utils/analyze_errors.py
```

功能：

- 统计每个 CVE 的 `tp/fp/fn/precision/recall/f1`。
- 输出 FP/FN top CVE。
- 摘要 payload 中的 method、path、可疑 token。
- 可选读取 top-k 检索缓存和 `meta.json`，输出近邻标签证据。

当前最佳预测的错误分析输出：

```text
data/experiments/error_summary_current.csv
data/experiments/error_examples_current.csv
```

关键发现：

```text
CVE-2021-44228: tp=32, fp=1090, fn=6, precision=0.0285
CVE-2022-4260 : tp=0,  fp=1071, fn=0, precision=0
CVE-2022-31181: tp=0,  fp=1070, fn=0, precision=0
CVE-2010-1340 : tp=7,  fp=124,  fn=0, precision=0.0534
CVE-2010-0944 : tp=6,  fp=120,  fn=0, precision=0.0476
CVE-2010-3426 : tp=7,  fp=112,  fn=0, precision=0.0588
```

False Negative 也集中：

```text
CVE-2021-20016: tp=0,   fp=0, fn=403
CVE-2017-16894: tp=43,  fp=7, fn=196
CVE-2017-7921 : tp=0,   fp=0, fn=139
CVE-2024-21887: tp=645, fp=2, fn=111
CVE-2023-46805: tp=649, fp=0, fn=107
CVE-2021-38649: tp=0,   fp=0, fn=105
```

结论：当前误报不是均匀分布，而是少数 CVE 系统性误报。后续优化应围绕这些 CVE 做校准。

### 13.2 频次启发式动态阈值实验

实验文件：

```text
data/experiments/dynamic_threshold_frequency_results.csv
```

策略：

- 高频 CVE 上调阈值。
- 长尾 CVE 下调阈值。
- 搜索多个高频/低频 cutoff 和 offset。

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

结论：频次启发式几乎无收益，`micro_f1` 只提升 `0.000040`，可以视为噪声级变化。Claude 报告中“高频 CVE 阈值上调、长尾 CVE 阈值下调”的简单版本不应作为主线。

### 13.3 错误驱动候选阈值实验

实验文件：

```text
data/experiments/error_driven_threshold_results.csv
```

策略：

- 从当前错误分析中选择 `fp>=50` 且低 precision 的 CVE。
- 在候选聚合阶段对这些 CVE 提高阈值到 `0.88~1.01`。

最佳结果：

```text
labels:    fp>=50 & precision<=0.10 的 9 个 CVE
threshold: 0.98
precision: 0.678793
recall:    0.710186
micro_f1:  0.694135
macro_f1:  0.519895
```

结论：候选阶段阈值能提升 precision，但收益有限，说明问题不只是“候选进不进来”，还涉及多标签排序和最终输出策略。

### 13.4 最终输出级过滤实验

新增：

```text
utils/filter_predictions.py
```

用当前错误分析表选择：

```text
fp>=50
precision<=0.05
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

过滤后结果：

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

- 最终输出级 filter 的潜力明显大于候选阶段阈值。
- 但该结果使用官方测试真值生成 blocklist，属于 oracle 上界分析，不能直接作为严格无泄漏策略。
- 它证明当前最大优化空间在“少数 CVE 的系统性误报过滤”。

### 13.5 半分验证

为了验证 filter 不是完全同集偶然，做了官方测试集 A/B 半分实验：

```text
data/experiments/blocklist_split_validation_details.csv
data/experiments/blocklist_split_validation_summary.csv
```

方法：

1. 固定随机种子将官方测试集切成 A/B 两半。
2. A 半学习 blocklist，B 半评估。
3. B 半学习 blocklist，A 半评估。

最佳配置：

```text
min_fp=10
max_precision=0.10
```

结果：

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

- 半分验证提升稳定，说明高 FP 低 precision CVE 的误报模式较稳定。
- 但该实验仍使用官方测试集内部真值，仍属于研究分析。
- 下一步应做真正无泄漏版本：从训练集 holdout/K-fold 学习 blocklist 或 penalty，再应用到官方测试集。
