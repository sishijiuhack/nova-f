# Datacon2025

互联网威胁分析赛道-漏洞攻击流量识别

## 安装环境

```bash
./setup_install.sh
source ./.venv/bin/activate
```

解压示例数据集，也可以使用自己的数据集，注意`csv`的格式需要匹配

```bash
tar -xzvf ./data/train.tar.gz
```

## 框架

> 项目整体遵循“数据清洗 → 向量索引构建 → 本地相似度检索 → 自适应标签输出”的流水线架构

1. **数据预处理**

    - `preprocess.py` 提供 `clean_payload_text`、`preprocess_dataframe` 等函数，对 HTTP 报文按统一规则去除冗余头、标准化空白、整理字段。
    - 训练集、测试集都通过 `main.py` 的 `preprocess_training_data` / `preprocess_test_data` 入口生成带 `payload_clean` 列的 CSV，确保输入一致性。
    - CVE 标签用 `normalize_cve_labels` 解析字符串/列表、多种分隔符，统一为去重升序的 `CVE-XXXX` 形式。
2. **向量化与索引**
    - 采用本地 `SentenceTransformer`（默认 `all-MiniLM-L6-v2`，可定制 `--model-path` / `--device`）批量编码 payload 文本。
    - `build_faiss.py` 负责读取清洗后的训练集，生成 `train_embeddings.npy`、`faiss.index`、`meta.json`。索引使用 FAISS（`IndexFlatIP`），L2 归一化向量以支持内积相似度。
    - 元数据记录 ID、归一化标签列表、模型名称、时间戳等，供后续检索使用；`main.py` 的 `build_vector_store` 封装了这一流程。
3. **离线检索与预测**
    - `search_faiss.py` 读取索引及元数据，按需加载/缓存测试集向量（`test_embeddings.npy`），避免重复编码。
    - 检索阶段调用 `faiss.Index.search`，可配置 `--top-k`、`--max-candidates`、批量大小等参数，输出候选列表（CVE + 相似度）。
    - `adaptive_predict` 依据多层阈值（基础分、高置信/中置信、分差限制）决定最终返回 0~3 个标签，实现 precision/recall 权衡。
    - 结果写入 `id,cve_labels` CSV，并输出候选数量、相似度统计、预测数量分布等诊断信息。
4. **主流程集成**
    - `main.py` 串联上述步骤，提供 `--overwrite-clean`、`--overwrite-index`、`--reuse-cache` 等开关，支持一次性完成“清洗 → 向量化 → 检索 → 结果导出”。
    - 全程使用 `logging` 输出阶段性进度、统计指标，便于调参或部署到 ML pipeline。
    - 依赖精简为 `pandas`、`numpy`、`tqdm`、`faiss-cpu`、`sentence-transformers`、`LangChain` 相关包等必需库，满足本地和离线运行需求。

## 运行方法

```bash
python main.py \
--train-path ./data/train_payload.csv \
--test-path ./data/target_payload.csv \
--store-dir ./embeddings/faiss_store \
--output-path ./ans/target_labeled.csv \
--reuse-cache
```
