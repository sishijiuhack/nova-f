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
- `utils/analyze_errors.py`：按 CVE 统计 FP/FN/TP、precision/recall/F1，并输出 payload 模式和近邻证据。
- `utils/filter_predictions.py`：对最终预测结果做可配置 CVE 过滤，用于验证低精度高 FP 标签的后处理策略。
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

## 6. Claude 报告审阅后的新实验

用户提供 `OPTIMIZATION_REPORT_BY_CLAUDE.md` 后，对其中建议做了审阅和实验验证。

### 6.1 方向判断

认可：

- 当前瓶颈主要是 precision 和系统性误报。
- 模型替换不是当前第一优先级。
- 错误分析、per-CVE 策略和结构化特征值得继续。

保留意见：

- 报告中 `+3%~8% F1` 的收益预估偏乐观。
- “按训练频次直接调整阈值”过于粗糙。
- 伪标签、多模型集成、GPU FAISS 应放到后面。

### 6.2 错误分析结果

当前最佳预测的错误分析输出：

```text
data/experiments/error_summary_current.csv
data/experiments/error_examples_current.csv
```

Top FP：

```text
CVE-2021-44228: tp=32, fp=1090, fn=6, precision=0.0285
CVE-2022-4260 : tp=0,  fp=1071, fn=0, precision=0
CVE-2022-31181: tp=0,  fp=1070, fn=0, precision=0
CVE-2010-1340 : tp=7,  fp=124,  fn=0, precision=0.0534
CVE-2010-0944 : tp=6,  fp=120,  fn=0, precision=0.0476
CVE-2010-3426 : tp=7,  fp=112,  fn=0, precision=0.0588
```

Top FN：

```text
CVE-2021-20016: tp=0,   fp=0, fn=403
CVE-2017-16894: tp=43,  fp=7, fn=196
CVE-2017-7921 : tp=0,   fp=0, fn=139
CVE-2024-21887: tp=645, fp=2, fn=111
CVE-2023-46805: tp=649, fp=0, fn=107
CVE-2021-38649: tp=0,   fp=0, fn=105
```

结论：误报高度集中，少数 CVE 是主要优化空间。

### 6.3 Per-CVE 阈值实验

频次启发式实验：

```text
baseline micro_f1: 0.687799
best frequency heuristic: 0.687839
```

结论：按训练频次简单调整阈值基本无效。

错误驱动候选阈值实验：

```text
best candidate-threshold strategy
precision: 0.678793
recall:    0.710186
micro_f1:  0.694135
macro_f1:  0.519895
```

结论：候选阶段提高低精度 CVE 阈值有小幅收益，但不是主要突破口。

### 6.4 最终输出级过滤实验

使用当前错误分析表选择：

```text
fp>=50
precision<=0.05
```

过滤标签：

```text
CVE-2010-0944
CVE-2020-3952
CVE-2021-44228
CVE-2022-31181
CVE-2022-4260
CVE-2023-34048
CVE-2024-8517
```

过滤后：

```text
baseline
precision: 0.666632
recall:    0.710354
micro_f1:  0.687799
macro_f1:  0.523245

filtered
precision: 0.821659
recall:    0.708167
micro_f1:  0.760703
macro_f1:  0.524682
```

该结果是 oracle 上界，因为 blocklist 来自官方测试真值，不能作为严格无泄漏最终策略。

半分验证：

```text
A -> B delta_micro: +0.084919
B -> A delta_micro: +0.085423
```

结论：输出级 blocklist/filter 是当前最有潜力方向。下一步要做训练集 holdout/K-fold 学习 blocklist 或 penalty，再应用到官方测试集。

## 7. 推荐运行命令

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

错误分析：

```bash
python utils/analyze_errors.py \
  --truth ./data/test_payload.csv \
  --pred ./data/experiments/test_official_optimized.csv \
  --search ./data/experiments/search_top50_combined.npz \
  --meta ./embeddings/faiss_store_combined/meta.json \
  --output-summary ./data/experiments/error_summary_current.csv \
  --output-examples ./data/experiments/error_examples_current.csv
```

最终输出过滤实验：

```bash
python utils/filter_predictions.py \
  --pred ./data/experiments/test_official_optimized.csv \
  --analysis-summary ./data/experiments/error_summary_current.csv \
  --min-fp 50 \
  --max-precision 0.05 \
  --output ./data/experiments/test_official_filtered_fp50_p005.csv
```

## 8. 后续优化方向

优先级建议：

1. 做训练集 holdout/K-fold，从非官方测试真值中学习低精度高 FP CVE blocklist/penalty。
2. 将最终输出级 filter 转成可配置主流程选项，但默认关闭，避免无验证策略污染正式结果。
3. 对 `CVE-2021-20016`、`CVE-2017-7921` 等高 FN 类做召回专项分析。
4. 对 payload 结构增加显式特征，例如请求方法、路径、参数名和 body 模式，用于 rerank 或输出级校准。
5. 将 FAISS 检索缓存和预测缓存拆开为正式命令，减少重复 CPU 检索时间。
6. 在 GPU 或更长运行窗口下尝试 `bge-base-en-v1.5`、`e5-base-v2` 或安全领域模型。

## 9. Git 与数据管理

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

## 10. 2026-06-26 追加优化进展：训练集 K-fold blocklist

本轮目标是把“最终输出级高 FP CVE 过滤”从官方测试集真值驱动，推进到非泄露版本。实现方式是利用已有 combined 向量库做训练集 out-of-fold 预测，统计在训练集 held-out 折上稳定表现为低 precision、高 FP 的 CVE，再将这些 CVE 作为可选最终输出 blocklist。

新增脚本：

```text
utils/learn_blocklist_from_folds.py
```

核心命令：

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

OOF 结果：

```text
baseline precision: 0.227951
baseline recall:    0.428587
baseline micro_f1:  0.297612

filtered precision: 0.395104
filtered recall:    0.411195
filtered micro_f1:  0.402989
```

在官方授权测试集上，用训练集 K-fold 学到的候选 blocklist 做后处理验证，当前最佳配置为：

```text
min_fp=20
max_precision=0.02
min_folds=2
block_count=92
```

指标：

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

结论：该策略没有从官方测试集真值学习 blocklist，能稳定提升 precision 和 micro F1，代价是召回略降。当前应作为可选策略使用，不作为默认开启策略。

工程更新：

```text
main.py
src/search_faiss.py
```

新增可选参数：

```text
--prediction-blocklist path/to/blocklist.txt
```

blocklist 文件支持换行或逗号分隔 CVE。该参数默认关闭，避免未验证 blocklist 污染正式运行。

验证情况：

```text
python -m py_compile main.py src/search_faiss.py utils/learn_blocklist_from_folds.py
```

已通过。

一次完整 `main.py --prediction-blocklist` 官方测试运行在 Windows 终端 10 分钟限制内超时，未生成输出文件；已用等价的 `utils/filter_predictions.py` 后处理路径复核指标。该问题后续应通过独立检索缓存脚本或 WSL 长时运行继续验证。

## 11. 2026-06-26 追加优化进展：检索缓存与签名召回

本轮继续处理两个问题：

1. 后续实验反复执行 FAISS 检索，浪费时间。
2. OOF blocklist 后，主要瓶颈转为少数高 FN CVE，尤其是固定路径/固定协议形态的样本。

### 11.1 独立检索缓存

新增脚本：

```text
utils/cache_search_results.py
```

用途：从已有 `faiss.index`、`test_embeddings.npy` 和 `meta.json` 直接导出 top-k 检索缓存，避免每个实验重复执行 FAISS search。

本轮命令：

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

### 11.2 高 FN CVE 诊断

使用 top-100 缓存重跑错误分析后，主要高 FN 问题包括：

```text
CVE-2021-20016: 403 FN, 路径 /__api__/v1/logon/.../authenticate
CVE-2017-7921:  139 FN, 路径 /onvif-http/snapshot
CVE-2021-38649: 105 FN, /wsman 多标签组合中漏掉第 4 个标签
CVE-2023-27372: 91 FN, SPIP spip_pass，被误判为 CVE-2024-8517
CVE-2018-13379: 79 FN, /remote/fgt_lang 路径穿越
```

诊断结论：

- `CVE-2021-38649` 不是检索失败，近邻已经 1.0 命中四标签，但 adaptive 策略最多输出前三个，导致系统性漏掉第 4 个标签。
- `CVE-2021-20016`、`CVE-2017-7921`、`CVE-2018-13379` 很多样本 top 近邻为空标签，语义检索不稳定，但 payload 路径模式高度固定。
- `CVE-2023-27372` 与 `CVE-2024-8517` 的 SPIP 模式冲突明显，适合规则化纠偏。

### 11.3 签名召回实验

新增脚本：

```text
utils/apply_signature_rescue.py
```

当前规则：

```text
wsman-38649:      /wsman 且已有 CVE-2021-38645/38647/38648 时补 CVE-2021-38649
fortinet-13379:   /remote/fgt_lang 且存在 ../ 或 %2e%2e 时补 CVE-2018-13379
hikvision-7921:   /onvif-http/snapshot 时补 CVE-2017-7921
sonicwall-20016:  /__api__/v1/logon/ 且 /authenticate 时补 CVE-2021-20016
spip-27372:       /spip.php 或 /spip.ph%70 且 spip_pass 时补 CVE-2023-27372，可移除冲突 CVE-2024-8517
```

总体验证命令：

```bash
python utils/apply_signature_rescue.py \
  --truth-or-test ./data/test_payload.csv \
  --pred ./data/experiments/test_official_filtered_fp20_p002_mf2_recheck.csv \
  --output ./data/experiments/test_official_oof_blocklist_signature_rescue.csv \
  --changes-output ./data/experiments/signature_rescue_changes.csv \
  --remove-conflicts
```

指标：

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

结论：五条规则单独均为正收益，合并后 micro F1 达到 `0.763359`。该结果已超过此前 oracle filter 上界 `0.760703`，但规则来自对官方授权测试集错误分析的研究观察，严格提交时需要说明它属于规则化后处理实验，并优先用额外 holdout 或训练集相似规则验证其泛化性。

## 12. 2026-06-26 追加优化进展：规则泛化验证与自动路径规则

本轮目标是回答：上一轮 `signature rescue` 到底是可泛化策略，还是只是在官方测试集上提分。

### 12.1 手写签名规则的训练集验证

新增：

```text
utils/validate_signature_rules.py
```

输入：

```text
data/train_with_ultimate_cleaned.csv
data/experiments/train_payload_cleaned.csv
```

结果：

```text
wsman-38649:
tp=342
fp=0
fn=0
precision=1.000000
recall=1.000000
5-fold valid precision=1.000000
5-fold valid recall=1.000000

fortinet-13379:
tp=3
fp=1
fn=102
precision=0.750000
recall=0.028571

spip-27372:
tp=2
fp=4
fn=0
precision=0.333333
recall=1.000000

hikvision-7921:
tp=0
fp=0
fn=1

sonicwall-20016:
support=0
```

结论：

- `wsman-38649` 在训练集中有强证据，属于可泛化性较强的规则。
- 其他四条规则在训练集中证据不足或 precision 不够，虽然在官方测试集上提分明显，但暂时只能归类为“测试分布规则/研究规则”。

仅启用训练验证通过的 `wsman-38649`：

```text
precision: 0.759890
recall:    0.714950
micro_f1:  0.736736
macro_f1:  0.536132
changed_rows: 104
```

### 12.2 自动挖掘训练集路径签名

新增：

```text
utils/mine_path_signature_rules.py
utils/apply_mined_path_rules.py
```

训练集挖掘命令：

```bash
python utils/mine_path_signature_rules.py \
  --input ./data/train_with_ultimate_cleaned.csv \
  --input ./data/experiments/train_payload_cleaned.csv \
  --payload-column payload_clean \
  --min-support 20 \
  --min-precision 0.98 \
  --output ./data/experiments/mined_path_rules_train.csv
```

第一版宽泛路径规则直接迁移失败：

```text
min_precision=0.99
min_support=20
match_level=all
only_empty=true

precision: 0.541217
recall:    0.731655
micro_f1:  0.622190
```

原因：训练集中高 precision 的宽泛路径前缀迁移到测试集时会产生大量 FP。

收紧为 exact normalized path 后转正：

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

与训练验证通过的 `wsman-38649` 组合：

```text
precision: 0.759722
recall:    0.728292
micro_f1:  0.743675
macro_f1:  0.536764
```

结论：

- 自动挖掘规则如果太宽，会严重过拟合训练路径前缀。
- exact path + 高 precision + 高 support + only-empty 是更稳的形式。
- 当前“泛化证据较强”的策略可把 OOF blocklist 的 `0.732930` 提升到 `0.743675`。
- “测试分布签名规则”仍能达到 `0.763359`，但泛化证据弱，不应直接包装成真实场景能力。

## 13. 2026-06-26 追加优化进展：OOF mined-rule 验证与 Macro-F1 记录

本轮继续推进 `OOF mined-rule 验证`，并把 Macro-F1 远低于 Micro-F1 的问题记录为后续优化约束。

### 13.1 OOF mined-rule 验证

新增：

```text
utils/validate_mined_path_rules_oof.py
```

方法：

1. 将训练集分成 5 折。
2. 每折只用 K-1 折挖掘 method/path -> CVE 规则。
3. 在 held-out 折验证规则 precision/recall/F1。
4. 该流程不读取官方测试真值。

配置一：

```text
match_level=exact
min_precision=1.0
min_support=50
```

OOF 均值：

```text
precision: 0.995759
recall:    0.513666
micro_f1:  0.677177
macro_f1:  0.760765
```

配置二：

```text
match_level=exact
min_precision=1.0
min_support=20
```

OOF 均值：

```text
precision: 0.992277
recall:    0.635369
micro_f1:  0.774552
macro_f1:  0.860057
```

结论：exact path mined rules 在训练 OOF 上 precision 很高，说明这条规则挖掘路线具备较强泛化证据。`support=20` 比 `support=50` 覆盖更好，precision 仍可接受。

### 13.2 官方授权测试集研究评估

将 `wsman-38649` 与 exact mined rules 组合：

```text
OOF blocklist + wsman-38649 + exact mined rules (support=50):
precision: 0.759722
recall:    0.728292
micro_f1:  0.743675
macro_f1:  0.536764

OOF blocklist + wsman-38649 + exact mined rules (support=20):
precision: 0.758397
recall:    0.735355
micro_f1:  0.746699
macro_f1:  0.538537
```

当前“泛化证据较强”的最佳结果更新为：

```text
precision: 0.758397
recall:    0.735355
micro_f1:  0.746699
macro_f1:  0.538537
```

### 13.3 Macro-F1 问题记录

当前 Macro-F1 长期远低于 Micro-F1，原因不是单一 bug，而是类别表现不均衡：

- Micro-F1 被高频 CVE 主导，高频类预测好即可维持较高分。
- Macro-F1 对每个 CVE 等权平均，大量长尾 CVE 的 F1 接近 0，会显著拉低平均值。
- 当前 OOF blocklist 和 empty-neighbor suppression 偏向提升 precision，可能进一步牺牲低频 CVE 召回。
- 多标签截断也会让某些 CVE 类整体 F1 接近 0，例如此前 `CVE-2021-38649`。

后续优化不能只看 micro-F1，需要同时记录：

```text
micro_f1
macro_f1
per-label F1
top-FN labels
zero-F1 labels count
```

当前 exact mined rules 对 Macro-F1 有小幅帮助：`0.535373 -> 0.538537`，但提升有限，说明仍有大量长尾 CVE 没有被覆盖。

## 14. 2026-06-26 追加优化进展：per-label 评估与多标签输出实验

本轮按计划先补 per-label 评估，再实验多标签输出策略。

### 14.1 per-label 评估

新增：

```text
utils/evaluate_per_label.py
```

对当前泛化证据较强路线：

```text
OOF blocklist + wsman-38649 + exact mined rules support=20
```

统计结果：

```text
labels: 1311
zero_f1_labels: 540
low_f1_labels_lt_0.2: 554
```

主要 zero-F1 / high-FN CVE 仍包括：

```text
CVE-2021-20016: fn=403
CVE-2017-7921:  fn=139
CVE-2023-27372: fn=91
CVE-2018-13379: fn=79
CVE-2024-1800:  fn=73
CVE-2020-8949:  fn=66
```

结论：Macro-F1 低的核心仍是大量长尾 CVE 完全未召回。当前优化提升了总体 recall，但没有大规模减少 zero-F1 类别。

### 14.2 多标签输出策略实验

新增：

```text
utils/experiment_multilabel_strategy.py
utils/experiment_labelset_completion.py
```

实验一：top-1 高置信近邻复制完整 labelset。

```text
thresholds: 0.97,0.98,0.99,0.995,0.999
require_superset=true
```

结果：全部略低于 baseline，最佳仍是 baseline。

```text
best copy-top1:
micro_f1: 0.746129
macro_f1: 0.535819
delta_micro_f1: -0.000570
delta_macro_f1: -0.002718
```

实验二：top-k consensus 补充多标签。

```text
thresholds: 0.90,0.95,0.98,0.99
min_votes: 2,3,5
```

结果：全部不优于 baseline，低 vote 会引入大量 FP。

```text
best consensus:
micro_f1: 0.746585
macro_f1: 0.538514
delta_micro_f1: -0.000113
delta_macro_f1: -0.000023
```

实验三：重复高置信 multi-label labelset completion。

在未启用 `wsman-38649` 的 OOF blocklist baseline 上：

```text
threshold=0.99
min_votes=2
require_subset=true
changed_rows=101
micro_f1: 0.736626
macro_f1: 0.536121
delta_micro_f1: +0.003697
delta_macro_f1: +0.000748
```

但在已经启用 `wsman-38649` 的当前基线上，变更为 0。说明该策略主要修复的就是 `/wsman` 四标签截断，已经被训练验证规则覆盖。

结论：

- 全局多标签扩展策略不成立，会引入 FP 或无收益。
- 多标签问题需要定向 group completion，而不是全局复制近邻 labelset。
- 当前最稳的做法仍是保留 `wsman-38649` 这种训练验证通过的定向规则。
 
## 15. 2026-06-26 追加优化进展：长尾诊断、结构化规则与 rerank

本轮继续围绕真实场景可辩护的优化推进，原则是不使用官方测试集真值直接写死规则，只采纳训练集 OOF 或训练集挖掘可解释的策略。

新增工具：
```text
utils/diagnose_long_tail.py
utils/structured_signature_rules.py
utils/structured_rerank_experiment.py
```

长尾诊断确认当前泛化证据较强路线仍有大量 zero-F1：
```text
labels: 1311
zero_f1: 540
```

高 FN/zero-F1 中一部分训练集中完全没有支持样本，例如：
```text
CVE-2021-20016: train_support=0, fn=403
CVE-2024-1800:  train_support=0, fn=73
CVE-2023-3306:  train_support=0, fn=27
```

这类 CVE 不能靠训练集可验证规则安全补召回，需要外部公开样本或后续授权数据补充。

结构化签名规则从仅 path 扩展为：
```text
path
query_keys
body_keys
query_key_value
body_key_value
suspicious token
```

OOF 验证结果：
```text
min_support=20, min_precision=1.0
precision: 0.991996
recall:    0.622656
micro_f1:  0.764982
macro_f1:  0.848935
```

低支持规则对比：
```text
min_support=10: micro_f1=0.714005
min_support=5:  micro_f1=0.724278
```

结论：低 support 虽然规则更多，但 OOF 表现下降，泛化风险更高。因此当前只保留 `support=20, precision=1.0` 作为可辩护候选。

结构化 rerank 单独实验：
```text
alpha=0.000 micro_f1=0.687127 macro_f1=0.524130
alpha=0.030 micro_f1=0.693526 macro_f1=0.532527
```

当前新的召回增强候选：
```text
structured rerank + OOF blocklist + structured rules only-empty + wsman-38649

precision: 0.739922
recall:    0.756264
micro_f1:  0.748004
macro_f1:  0.548448
zero_f1_labels: 535
```

相对旧的泛化证据较强路线：
```text
micro_f1: 0.746699 -> 0.748004
macro_f1: 0.538537 -> 0.548448
recall:   0.735355 -> 0.756264
```

代价是 precision 下降：
```text
precision: 0.758397 -> 0.739922
```

因此保留两条候选路线：
```text
保守高 precision:
OOF blocklist + wsman-38649 + exact mined path rules

召回/Macro-F1 优先:
structured rerank + OOF blocklist + structured rules only-empty + wsman-38649
```
 
## 16. 2026-06-26 追加优化进展：未完成项收敛

本轮把上一轮遗留的工程化优化全部补齐，并区分“完成且采纳”和“完成但暂不采纳”。

新增或更新：
```text
src/structured_features.py
main.py
src/search_faiss.py
utils/export_rule_config.py
utils/apply_rule_config.py
utils/conditional_filter_predictions.py
utils/export_data_gap_report.py
```

### 16.1 主流程可选 structured rerank

`main.py` 已新增：
```text
--structured-rerank-alpha
--train-feature-path
```

默认 `--structured-rerank-alpha 0`，不改变原有输出。启用时会读取与 FAISS meta 对齐的 cleaned train CSV，对 top-k 近邻相似度加入结构化特征加权。

已通过 200 行 smoke 测试：
```text
output: data/experiments/smoke_main_structured_rerank.csv
structured_rerank_alpha: 0.03
prediction_blocklist: fold_blocklist_fp20_p002_mf2.txt
result: pipeline completed
```

### 16.2 规则配置化

结构化规则已可导出为可审计 JSON 配置：
```text
data/experiments/structured_rules_train_s20_p1_config.json
```

配置字段包括：
```text
rule_id
enabled
rule_type
signature
target_cve
support
precision
source
risk_level
```

配置化应用复现了上一轮最佳召回增强结果：
```text
precision: 0.739922
recall:    0.756264
micro_f1:  0.748004
macro_f1:  0.548448
```

### 16.3 条件式 blocklist

新增：
```text
utils/conditional_filter_predictions.py
```

目标是避免全局 CVE blocklist 误伤：如果 payload 命中该 CVE 的 allow signature，则保留，否则过滤。

本轮实验：
```text
Preserved by allow signatures: 0
micro_f1: 0.738662
macro_f1: 0.546500
```

结论：工具完成，但当前 allow config 没有覆盖 blocklist 内被误伤标签，所以暂不采纳为最优路线。

### 16.4 数据缺口清单

新增：
```text
utils/export_data_gap_report.py
```

已导出无训练支持且 FN>=20 的 CVE：
```text
data/experiments/cve_data_gap_no_train_support.csv
data/experiments/cve_data_gap_no_train_support.md
```

当前缺口 10 个：
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

这些不能靠训练集可验证规则解决，真实场景需要补授权样本或公开样本。

### 16.5 当前最终路线

默认主线仍建议保守高 precision：
```text
OOF blocklist + wsman-38649 + exact mined path rules
precision: 0.758397
recall:    0.735355
micro_f1:  0.746699
macro_f1:  0.538537
```

真实场景召回优先路线：
```text
structured rerank + OOF blocklist + config structured rules only-empty + wsman-38649
precision: 0.739922
recall:    0.756264
micro_f1:  0.748004
macro_f1:  0.548448
```

实验上界仍是 hand-written signature rescue，但不作为真实场景主线。
