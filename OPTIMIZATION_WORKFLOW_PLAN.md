# nova-f 后续优化工作流记录

更新时间：2026-06-26

本文件用于记录阅读 `OPTIMIZATION_REPORT_BY_CLAUDE.md` 后，与用户讨论确定的实验路线。它是后续接力入口，避免对话上下文丢失。

## 1. 当前共识

当前最佳主线不是继续盲目替换 embedding 模型，而是围绕系统性误报做后处理和校准。

原因：

- `all-MiniLM-L6-v2` 已能覆盖相当一部分真实 CVE。
- BGE small 仅微弱提升 holdout micro F1，但 CPU 成本明显更高。
- E5 small 使用 `passage:` / `query:` 前缀后仍低于 MiniLM。
- 当前全量误报高度集中在少数 CVE，说明决策层比表示层更值得优先优化。

## 2. Claude 报告审阅结论

认可：

- 当前瓶颈主要在 precision。
- 错误分析、per-CVE 策略、结构化特征值得做。
- 工程上应补缓存、调参工具和测试。

保留意见：

- 报告的 `+3%~8% F1` 预估偏乐观，需要实验验证。
- “按训练频次直接调整阈值”过于粗糙，已被实验基本否定。
- 伪标签、多模型集成、GPU FAISS 风险或成本较高，暂不作为近期主线。
- 手写黑名单不能直接进主流程，应先用无泄漏验证集学习。

## 3. 已完成实验

### 3.1 错误分析工具

新增：

```text
utils/analyze_errors.py
```

输出：

```text
data/experiments/error_summary_current.csv
data/experiments/error_examples_current.csv
```

当前最佳预测的主要 FP：

```text
CVE-2021-44228: fp=1090, precision=0.0285
CVE-2022-4260 : fp=1071, precision=0
CVE-2022-31181: fp=1070, precision=0
CVE-2010-1340 : fp=124,  precision=0.0534
CVE-2010-0944 : fp=120,  precision=0.0476
CVE-2010-3426 : fp=112,  precision=0.0588
```

当前最佳预测的主要 FN：

```text
CVE-2021-20016: fn=403
CVE-2017-16894: fn=196
CVE-2017-7921 : fn=139
CVE-2024-21887: fn=111
CVE-2023-46805: fn=107
CVE-2021-38649: fn=105
```

结论：误报集中，低 precision CVE 是主要优化空间。

### 3.2 频次启发式动态阈值

输出：

```text
data/experiments/dynamic_threshold_frequency_results.csv
```

结果：

```text
baseline micro_f1: 0.687799
best frequency heuristic: 0.687839
```

结论：按训练频次调整阈值基本无效，不继续作为主线。

### 3.3 错误驱动候选阈值

输出：

```text
data/experiments/error_driven_threshold_results.csv
```

最佳：

```text
precision: 0.678793
recall:    0.710186
micro_f1:  0.694135
macro_f1:  0.519895
```

结论：候选阶段阈值调整有效但收益有限。

### 3.4 最终输出级 filter

新增：

```text
utils/filter_predictions.py
```

Oracle 上界实验：

```text
baseline micro_f1: 0.687799
filtered micro_f1: 0.760703
precision: 0.666632 -> 0.821659
recall:    0.710354 -> 0.708167
```

注意：该 blocklist 来自官方测试真值错误分析，不能直接作为严格无泄漏最终策略。

### 3.5 官方测试集半分验证

输出：

```text
data/experiments/blocklist_split_validation_details.csv
data/experiments/blocklist_split_validation_summary.csv
```

最佳规则：

```text
min_fp=10
max_precision=0.10
```

结果：

```text
A -> B delta_micro: +0.084919
B -> A delta_micro: +0.085423
```

结论：系统性误报稳定存在。下一步应做真正无泄漏的训练集 holdout/K-fold 学习。

## 4. 下一步工作流

### Step 1：训练集 K-fold 学习 blocklist

目标：不用官方测试真值，学习低 precision 高 FP CVE。

建议做法：

1. 从 `data/experiments/train_combined.csv` 或 `data/train_with_ultimate.csv + data/train_payload.csv` 构造 K-fold。
2. 每折：
   - 用 K-1 折构建 FAISS。
   - 对 held-out 折预测。
   - 用 `utils/analyze_errors.py` 统计低 precision 高 FP 标签。
3. 汇总各折 blocklist，保留稳定出现的 CVE。
4. 将该 blocklist 应用于官方测试预测，评估如果有真值则记录研究指标。

需要注意：

- K-fold 构建多个索引会耗时。
- 可以先用较小 split 验证脚本逻辑。
- 学习规则不能读取 `data/test_payload.csv` 的真值。

### Step 2：把 filter 做成主流程可选参数

目标：支持生产运行时加载外部 blocklist，但默认关闭。

建议参数：

```text
--prediction-blocklist path/to/blocklist.txt
```

格式：

```text
CVE-2022-4260
CVE-2022-31181
...
```

注意：blocklist 来源必须在报告中说明，避免数据泄漏。

### Step 3：高 FN 类专项召回分析

优先 CVE：

```text
CVE-2021-20016
CVE-2017-7921
CVE-2021-38649
CVE-2023-27372
CVE-2018-13379
```

方向：

- 检查训练集中是否有这些 CVE。
- 检查 nearest neighbours 是否是空标签或错误 CVE。
- 如果训练覆盖不足，考虑数据增强或外部样本补充。
- 如果覆盖存在但阈值挡住，考虑 per-CVE 降阈值或结构化特征召回。

### Step 4：结构化特征 rerank 小实验

先不要大改主流程。建议先写实验脚本：

```text
utils/feature_rerank_experiment.py
```

特征：

- HTTP method 是否相同。
- path basename / path token Jaccard。
- query 参数名 Jaccard。
- suspicious token overlap。

重排公式先用：

```text
score = semantic_score + alpha * feature_score
```

alpha 从 `0.01, 0.02, 0.05` 开始。

### Step 5：工程化缓存

已有：

```text
utils/tune_retrieval_params.py
```

仍建议补：

```text
utils/cache_search_results.py
```

用途：

- 输入 `store_dir` 和测试向量缓存。
- 输出 `search_topK.npz`。
- 让所有后续策略实验无需重复 FAISS 检索。

## 5. 当前不建议优先做的方向

暂缓：

- 伪标签增强：误差传播风险高。
- 多模型集成：CPU 成本高，BGE/E5 初步收益不足。
- GPU FAISS：工程环境成本高，且主要改善速度不是指标。
- 手写 CVE 黑名单：容易数据泄漏或过拟合，必须先有训练集验证来源。

## 6. 已提交代码

相关提交：

```text
1164ba7 Add error analysis experiments
```

包含：

```text
OPTIMIZATION_REPORT_BY_CLAUDE.md
utils/analyze_errors.py
utils/filter_predictions.py
```

本文件用于后续继续实验时快速恢复上下文。

## 7. 2026-06-26 执行记录：Step 1 与 Step 2 已推进

### Step 1：训练集 K-fold 学习 blocklist

已实现：

```text
utils/learn_blocklist_from_folds.py
```

使用已有 combined 向量库做 3-fold out-of-fold 预测，不重新编码训练集。每折用 K-1 折建临时 FAISS，对 held-out 折预测，再统计每个 CVE 的 `tp/fp/fn/precision/recall/f1`。最终只保留跨至少 2 折稳定低 precision、高 FP 的 CVE。

初始 OOF 结果：

```text
baseline micro_f1: 0.297612
filtered micro_f1: 0.402989
```

阈值复用扫描后，当前最佳非泄露候选：

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

结论：该方向成立。收益主要来自 precision 提升，recall 仅轻微下降。与 oracle filter 的 `0.760703` micro F1 仍有差距，但 OOF blocklist 不依赖官方测试真值，更适合作为候选提交策略。

### Step 2：主流程可选 blocklist

已实现：

```text
main.py --prediction-blocklist path/to/blocklist.txt
src/search_faiss.py --prediction-blocklist path/to/blocklist.txt
```

说明：

- 默认关闭。
- blocklist 文件支持换行或逗号分隔 CVE。
- 主流程会统计加载标签数和移除的预测标签数。
- blocklist 来源必须在报告中注明，防止泄露或过拟合。

验证：

```text
python -m py_compile main.py src/search_faiss.py utils/learn_blocklist_from_folds.py
```

已通过。

遗留问题：

- `main.py --prediction-blocklist` 官方测试端到端运行在 Windows 10 分钟命令限制内超时，未生成输出；已用等价 `utils/filter_predictions.py` 后处理验证指标。
- 下一步应优先补 `utils/cache_search_results.py`，把向量检索结果持久化，让后续 blocklist、rerank、per-CVE threshold 实验不再重复跑 FAISS 检索。

### 下个对话框继续点

如果上下文被压缩或切换，请从这里继续：

1. 不要重新读取授权数据正文到 Git，不提交 `data/experiments/`、`data/datacon2025/`、`models/`、`embeddings/`。
2. 当前最佳非泄露候选为 OOF blocklist：`min_fp=20,max_precision=0.02,min_folds=2`，官方研究指标 `micro_f1=0.732930`。
3. `utils/cache_search_results.py` 已完成，top-100 combined 缓存已验证可在约 45 秒生成。
4. 高 FN CVE 专项分析已完成第一轮，签名召回后处理已将官方研究 micro F1 提升到 `0.763359`。
5. 下一步优先把签名规则迁移到“训练集 OOF 可验证规则”或“配置化规则文件”，避免只依赖官方测试错误分析。
6. 结构化特征 rerank 作为下一条实验线，先写实验脚本，不直接改主流程默认策略。

## 8. 2026-06-26 执行记录：Step 3 与 Step 5 已推进

### Step 5：工程化检索缓存

已实现：

```text
utils/cache_search_results.py
```

本轮生成：

```text
data/experiments/search_top100_combined.npz
rows=105077
top_k=100
dim=384
耗时约 45 秒
```

用途：

- 错误分析不再重复跑 FAISS 检索。
- 后续 threshold、rerank、规则消融可以直接读取 `D/I`。

### Step 3：高 FN 专项分析与签名召回

高 FN 分析结论：

```text
CVE-2021-38649: /wsman 多标签输出策略漏掉第 4 标签
CVE-2021-20016: /__api__/v1/logon/.../authenticate 固定路径，近邻多为空标签
CVE-2017-7921: /onvif-http/snapshot 固定路径，近邻多为空标签
CVE-2018-13379: /remote/fgt_lang 路径穿越，近邻多为空标签
CVE-2023-27372: SPIP spip_pass 与 CVE-2024-8517 冲突
```

已实现：

```text
utils/apply_signature_rescue.py
```

总体指标：

```text
OOF blocklist baseline micro_f1: 0.732930
signature rescue micro_f1:       0.763359
precision: 0.772989
recall:    0.753966
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

注意：

- 这些规则来自官方授权测试集错误分析，当前只能定义为研究性后处理实验。
- 下一步必须做泛化验证：训练集 OOF 规则评估，或从训练数据自动挖掘高置信路径到 CVE 的映射。
- 不要把签名规则默认并入 `main.py`，除非已有独立验证依据。

## 9. 2026-06-26 执行记录：规则泛化验证

已实现：

```text
utils/validate_signature_rules.py
utils/mine_path_signature_rules.py
utils/apply_mined_path_rules.py
```

手写签名规则在训练集上的验证结果：

```text
wsman-38649: precision=1.0 recall=1.0 support=342, 5-fold valid precision=1.0
fortinet-13379: precision=0.75 recall=0.028571
spip-27372: precision=0.333333 recall=1.0
hikvision-7921: no hit, support=1
sonicwall-20016: support=0
```

结论：

- `wsman-38649` 可归入泛化证据较强规则。
- 其他四条仍是官方测试错误分析规则，不能直接声称适合真实场景。

自动挖掘路径规则结果：

```text
wide prefix rules:
micro_f1=0.622190
结论：失败，FP 过多。

exact path rules, min_precision=1.0, min_support=50, only_empty:
micro_f1=0.739924

wsman-38649 + exact path rules:
micro_f1=0.743675
precision=0.759722
recall=0.728292
macro_f1=0.536764
```

下一步优先级：

1. 把 mined rules 输出为配置文件格式，加入可审计字段：signature、label、support、precision、source。
2. 做 OOF 级别的 mined-rule 验证，不能只用全训练集挖规则再看官方测试。
3. 继续研究高 FN 中训练集无证据但官方测试收益大的规则，判断是否需要外部公开样本补充。

## 10. 2026-06-26 执行记录：OOF mined-rule 验证与 Macro-F1

已实现：

```text
utils/validate_mined_path_rules_oof.py
```

OOF 验证结果：

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

当前路线分层：

```text
泛化证据较强:
micro_f1=0.746699
macro_f1=0.538537

实验上界更高但泛化证据弱:
micro_f1=0.763359
macro_f1=0.539183
```

Macro-F1 问题已记录：当前 Macro-F1 远低于 Micro-F1，说明长尾 CVE 覆盖不足。后续每次优化必须同时记录 `micro_f1`、`macro_f1`、per-label F1 和 zero-F1 类别数量。

下一步建议：

1. 增加 per-label 评估脚本，输出 zero-F1 CVE 数、低 F1 CVE top 列表。
2. 做多标签输出策略优化，优先解决 `CVE-2021-38649` 这类“近邻已命中但输出截断”的问题。
3. 将 mined path rules 配置化，而不是硬编码在脚本逻辑里。

## 11. 2026-06-26 执行记录：per-label 与多标签策略

已实现：

```text
utils/evaluate_per_label.py
utils/experiment_multilabel_strategy.py
utils/experiment_labelset_completion.py
```

当前泛化证据较强路线的 per-label 诊断：

```text
labels: 1311
zero_f1_labels: 540
low_f1_labels_lt_0.2: 554
```

全局多标签策略实验：

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
在 OOF blocklist baseline 上:
micro_f1: 0.736626
delta_micro_f1: +0.003697

在当前已启用 wsman-38649 的基线上:
changed_rows: 0
```

结论：

- 全局多标签扩展策略不成立。
- 多标签问题应保留为训练验证通过的定向 group completion。
- 当前 Macro-F1 的主要瓶颈是大量 zero-F1 长尾 CVE，不是简单放宽多标签输出。

下一步建议：

1. 基于 `evaluate_per_label.py` 做 zero-F1 CVE 分组，优先处理 support 高的 zero-F1 类。
2. 从训练集中为高 support zero-F1 类挖专属 exact path/query/body 规则。
3. 做规则配置化，避免继续增加硬编码脚本参数。
 
## 8. 2026-06-26 执行记录：长尾召回与结构化特征

本轮按“先诊断长尾，再做训练可验证优化”的流程推进。

### 已完成

新增工具：
```text
utils/diagnose_long_tail.py
utils/structured_signature_rules.py
utils/structured_rerank_experiment.py
```

长尾诊断结论：
```text
zero_f1_labels: 540
```

高 FN CVE 分为两类：
```text
无训练支持：需要外部样本或后续授权数据，不能硬写测试集规则。
有训练支持：可以用结构化规则或 rerank 召回。
```

结构化规则 OOF：
```text
support=20, precision=1.0
OOF precision=0.991996
OOF micro_f1=0.764982
```

结构化 rerank：
```text
alpha=0.03
micro_f1: 0.687127 -> 0.693526
macro_f1: 0.524130 -> 0.532527
```

当前新的召回增强候选：
```text
structured rerank
+ OOF blocklist
+ structured rules only-empty
+ wsman-38649

precision: 0.739922
recall:    0.756264
micro_f1:  0.748004
macro_f1:  0.548448
```

### 当前决策

保留两条候选路线：
```text
保守高 precision 路线:
OOF blocklist + wsman-38649 + exact mined path rules
micro_f1=0.746699
macro_f1=0.538537

召回增强路线:
structured rerank + OOF blocklist + structured rules only-empty + wsman-38649
micro_f1=0.748004
macro_f1=0.548448
```

### 下一步

1. 将结构化 rerank 作为主流程可选参数接入，而不是只保留实验脚本。
2. 将结构化规则导出为可审计配置格式，字段包括 rule_type、signature、label、support、precision、source。
3. 为无训练支持但高 FN 的 CVE 准备外部样本补充清单，避免继续在测试集上写死规则。
4. 对 rerank 做训练集 OOF 或 holdout 验证，进一步确认不是官方测试集偶然收益。
