# datacon2025

## 安装环境

```bash
./setup_install.sh
source ./.venv/bin/activate
```

注意将自己的data数据集放在`data/`文件夹下，并修改路径

## 框架

- 对训练集和测试集进行解码操作，获得

## 目前的进展

```bash
# 预处理，两个文件都需要，训练集和测试集
python preprocess.py \ 
--input-path ../data/test_with_ultimate.csv \ 
--output-path ../data/test_with_ultimate_cleaned.csv

# 构建faiss
python build_faiss.py \
--input-path ../data/test_with_ultimate_cleaned.csv \
--store-dir ./embeddings/faiss_store

# 检索向量
python search_faiss.py \
--test-path ../data/test_payload_cleaned.csv \
--reuse-cache
```
