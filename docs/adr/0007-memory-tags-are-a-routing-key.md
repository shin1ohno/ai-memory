# ADR 0007: memory-v2 の `tags` は routing キー — 落とさない、落ちたら見える

**Status**: Accepted (2026-08-17)

## Context

memory-v2 の `tags` は「メタデータ」ではなく**列挙のための routing キー**です。TODO
パイプライン（`docs/todo-management.md`）は `browse(filters={"tags": "todo"})` で work / personal
の TODO を列挙し、それが唯一の enumeration 経路です。したがって tag を 1 つ失うことは、その
TODO を恒久的に見えなくすることと同義で、実際に「fact が 6 週間浮上しなかった」事例が
`docs/todo-management.md` に記録されています。

2026-08-17 の一連の調査で、tag が**成功したように見える操作で静かに失われる経路**が 5 つ見つかりました。
いずれも「書き込みは成功し、id も返る」ため、呼び出し側が列挙して初めて間違いに気づきます。

1. `remember_fact` の `content_hash` 完全一致 dedup が、呼び出し側の `tags` を破棄していた。
   無タグの "X" が既にある状態で `remember("X", tags=["todo"])` すると noop が返り、その TODO は
   列挙不能のまま残る。リトライしても同じ dedup を踏むので恒久的。
2. knowledge の再 ingest が tags を落としていた。`_ingest_chunks` は `tags or []` を stamp して
   旧版 chunk を supersede するので、同じ `(dataset, doc_key)` を tags 無しで再 ingest すると
   **タグ付き doc がタグ無し doc に置き換わる**。`server.remember(type='knowledge')` は
   `doc_key=content_hash(content)` なので、同一内容の再保存がまさにこれ。
3. `recall` は tag filter を受け付けるのに、返す hit から `tags` を落としていた（projection が
   backend と server の 2 箇所で key を列挙しており、片方だけ直しても無言で落ちる構造）。
4. `browse` は total を返さず cursor も offset も無いため、200 件マッチする store と
   ちょうど `limit` 件しかない store が区別できない。列挙が tail を静かに失う。
5. `_filter_clause` は allowlist を持たず、未知キー・大文字小文字違いをそのまま term クエリに
   していた。typo が「0 件」に化け、「そのキーは無い」と「そのデータは無い」が区別できない。

（1）と（2）は memory-work / ai-memory の両 store に効く経路で、keeper（自宅ラボ CT 119 のみに
deploy）を通らないため、これまでの keeper 側の議論では捕まりませんでした。

## Decision

### 1. 省略と空リストを区別する

`tags=None`（省略）と `tags=[]`（明示的なクリア）は別の意味とします。

| 呼び出し | 挙動 |
|---|---|
| `ingest_document(..., tags=None)` | supersede される版の tags を**継承** |
| `ingest_document(..., tags=[])` | tags を**クリア** |
| `ingest_document(..., tags=[...])` | その値を使う |

`revise` が既に「旧 doc の tags を引き継ぐ」を実装済みで、再 ingest だけが食い違っていたので、
これは新しい方針の導入ではなく既存挙動への整合です。MCP ツール層も `tags or []` をやめて
`None` をそのまま透過させます（`or []` は省略をクリアに変換してしまう）。

### 2. in-place の tags union を不変条件の明示的な例外とする

keeper の不変条件（`memory-keeper/reconcile.py`）は「supersede semantics only（in-place で
content を書かない）。in-place で変わるのは `superseded_by/at` / `reconcile_status` /
`use_count` / `last_used_at` のみ」です。dedup NOOP で tag を適用するには、既存 doc の tags を
in-place で足す必要があります。

**tags の union に限り、この不変条件の例外とします。** 根拠は union の代数的性質です:

- **monotone**: 決して tag を削除しない（routing キーが消えない）
- **idempotent**: 再実行が無害（retry / at-least-once 配信に耐える）
- **commutative**: 2 つの writer が競合しても、どちらの tag も失われない

`bump_use_counts` が recall ごとに同じ doc へ `_update_by_query` を投げるため version conflict は
例外ではなく日常です。したがって union は `retry_on_conflict` 付きで発行します（retry を落とすと、
まさにこの ADR が消そうとしている「静かな tag 消失」に戻る）。

content の in-place 書き換えは引き続き禁止です。例外は「加算しかしないメタデータ」に限ります。

### 3. 落ちたことが見える形で返す

- `browse` は `{"items", "total", "truncated", "total_is_lower_bound"}` を返します。ES は同じ
  レスポンスに件数を載せているので**追加ラウンドトリップは 0**。cursor が無い設計のまま
  「これは全体か、途中か」を呼び出し側が判定できるようにするのが目的です。`total` は
  `track_total_hits` の上限（既定 10000）を超えると下限値になるので、その旨をフラグで返します。
- `recall` の hit に `tags` を含めます。あわせて server 側の projection を key 列挙から
  「`memory_type`→`type` の rename のみ」の透過形に変えます。**同じ shape を 2 箇所で手書きすること
  自体が今回の drift の原因**なので、片方を消します。
- `_filter_clause` は mapping（`_common_props` + `_INDEX_DEFS`）から導出した allowlist で検証し、
  未知キー・date フィールド・`content`（analyzed text）・`embedding`（vector）を `QueryError` で
  拒否します。allowlist を**導出**にするのは、mapping にフィールドを足したときに手書きリストが
  黙って古くなるのを防ぐためです。エラーメッセージには「では何が使えるか」を必ず含めます。

## Consequences

- `browse` の戻り値が list から envelope に変わります。呼び出し側は repo 内では
  `memory-mcp/server.py` の 1 箇所のみ（skill / docs は MCP ツール経由）。
- 未知の filter キーは今後エラーになります。repo 内の既存呼び出し 5 箇所はすべて `tags` のみを
  渡しているので影響はありません（退役 v1 サーバの `user_id` は別実装の `_filter_clause`）。
- `remember` の noop 応答に、tag を足した場合のみ `tags_added` が増えます。
- date による絞り込みは「未対応」が明示されました。必要になった時点で range shape を設計します
  （`browse` の docstring が謳っていた「period フィルタ」は実装が無かったので、文言を実態に
  合わせました）。

## 未決（この ADR の範囲外）

- ~~**keeper の merge 規則**~~ → **ADR 0008 で決定**（tags/entities は union、provenance は
  `user-stated` の一方向 ratchet のみ、near-dup は pointer ではなく merged doc）。
- **NOOP の穴**: reconcile の NOOP は incoming の重複 doc を supersede せず live に残します。
  dedup セマンティクスそのものの変更なので別判断。
