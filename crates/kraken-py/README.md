# kraken-workbench

Python bindings for [KRAKEN](https://github.com/Adam-AtlasSoftware/kraken), the AI-assisted
reverse-engineering workbench. Import name: `kraken`.

```python
import kraken

proj = kraken.open("my-project")
for fn in proj.functions("init"):
    print(fn.name, fn.decompile().text)
```

Text taken from the analysed binary is hostile input; see the security note in the docs
(`docs/python.md` in the repository).
