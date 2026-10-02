# 文書サイトの build と公開

local build は[文書依存](../../tools/requirements-docs.txt)を入れ、repo root で行う。

```sh
python3 -m pip install -r tools/requirements-docs.txt
python3 tools/gen_user_reference.py --check
mkdocs build --strict
```

`.github/workflows/pages.yml` は PR で site を build する。公開は利用者が repo の Settings → Pages → Source を GitHub Actions に設定し、Actions variable `ROUTELOOM_PAGES_ENABLED=true` を設定した後の main push で行う。公開 URL は `mkdocs.yml` の `site_url` と repo に合わせる。この PR は Pages 設定を操作しない。有効化前は公開済みと案内しない。

Doxygen HTML/XML は別の Documentation checks workflow の `routeloom-api-reference` artifact に保存する。Markdown の API/Kconfig reference は通常の site に含まれる。生成した表は手編集せず、header・Kconfig・dispatch を直して再生成する。
