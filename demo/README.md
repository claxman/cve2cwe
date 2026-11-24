# Demo

A laptop page for one CVE description. The model file is a 4-bit copy. Every number in the main README comes from the bf16 checkpoint.

The model file is `demo/models/e2-seed1-merged.Q4_K_M.gguf`. It is not in git. Copy it from the export on the training machine, or download the public copy named in the main README. The `.BF16-mmproj.gguf` file is not used.

```
brew install llama.cpp
llama-server -m demo/models/e2-seed1-merged.Q4_K_M.gguf --reasoning off --port 8080 --temp 0 -c 4096 --alias candidate-e2-seed1
python -m cve2cwe demo
```

`--reasoning off` is the flag for this llama.cpp (1.0.0) that turns thinking off. The page reads `http://127.0.0.1:8080/v1` unless you pass `--base-url`.
