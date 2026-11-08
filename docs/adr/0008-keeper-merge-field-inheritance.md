# ADR 0008: keeper の merge — 派生 doc が何をどちらから継承するか

**Status**: Accepted (2026-08-17)

## Context

ADR 0007 が memory-v2 の `tags` を「列挙のための routing キー」と位置づけ、MCP サーバ側の
tag 消失経路を塞ぎました。その未決事項として残したのが keeper（`files/memory-keeper/`）の merge 規則です。

keeper は fact を 2 箇所で畳みます。

1. `reconcile.py` の UPDATE verdict — judge が「この 2 つは 1 つにまとめられる」と判断したとき、
   merged doc を index して両方を supersede する。
2. `consolidate.py` の near-dup pass — cosine > 0.95 のペアを見つけたとき、**古い方に
   `superseded_by` を書くだけ**で、新 doc は作らない。

どちらも tag を失っていました。1 は target 側の tags のみを引き継ぐので、`tags:["todo"]` の
incoming を無タグ doc に畳むと merged doc は無タグになります。2 は何も引き継がないので、古い方が
タグ付きだった場合そのタグは supersede の裏に取り残されます。

**支配的なのは 2 です。** judge prompt は「純粋な言い換えは NOOP を優先」と指示し、NOOP は
`_mark_reconciled` だけで supersede しません。つまり重複は reconcile を生き延びて near-dup pass に
到達し、そこで何も引き継がれずに消えます。当初案は 1 を丁寧に直し 2 を「skip して log に落とす」で
済ませようとしていましたが、log-only 経路は誰も読んでいません（`memory-keeper-health.sh` が出す
gauge は `raw_backlog` と `stats_age_seconds` の 2 本だけで、`superseded_total` /
`guard_violations` / `errors` を読む alert rule は存在せず、report 行は `reports[:20]` で切られ
stderr → journald へ流れて回転していく）。静かなデータ欠損を静かな運用欠損に置き換えるだけなので採りません。

同じ block には provenance の問題もあります。1 は target の provenance を採るため、incoming が
`user-stated` だと merged doc が `tool-output` に格下げされます。`user-stated` は store の他の場所では
一方向 ratchet として実装されています（`identity.authorize_supersede` は非対話 grant による
user-stated doc の supersede を拒否し、server は対話 revise で user-stated を再 stamp する）。
keeper の merge だけがそれを黙って巻き戻せる唯一の穴でした。

`keeper` は自宅ラボ CT 119（`pve/lxc-es-memory.rb`、`keeper-claude.env` が非空のとき稼働）にのみ
deploy されており、`memory-work`（sh1-cloud）には存在しません。したがって本 ADR の影響範囲は
個人 store 側です。コードは共通なので、将来 work 側に keeper を置いたときにも同じ規則が効きます。

## Decision

派生 doc（2 つの doc から作られる doc）の継承規則を `merge_rules.py` の純関数 1 箇所に集約します。
inline に書かれていたことが、2 経路で規則が食い違い、かつ live ES 無しでは 1 行も assert できない
状態を生んでいました。

### tags / entities は union

`union_tags` はソート済みの和集合を返します。tag は routing キーなので、**片側を選ぶ規則はどちらを
選んでも routing キーを失い得る一方、union だけは失いません**。union は monotone・idempotent・
commutative で、replay と競合に強い形でもあります（ADR 0007 の in-place union と同じ論拠）。
ソートするのは格納される keyword 配列を安定させ、assertion が list 順で揺れないようにするため。

### provenance は `user-stated` の一方向 ratchet のみ

どちらか一方が `user-stated` ならその側の `(agent, session_id, source_class)` を継承し、
それ以外は `b`（= 呼び出し側では target / survivor）が勝ちます。後者は**従来挙動とバイト等価**です。

`tool-output` / `reflection` / `auto-capture` / `migration` / `promoted` の 5 つに順位を付けることは
**しません**。これらは authz 上等価なので、順位付けは `provenance.agent` を移し替えて cleanup 権限を
別の service account へ動かすだけで、セキュリティ上の利得がありません。

この規則で失われる能力が 1 つあります: user-stated が絡む merge の後、元 doc を書いた service
account はその merged doc を forget できなくなります。**これは正しい方向の変化です** — matrix は
`(source_class, agent)` の 1 組で判定するので、その権限を残すことは「機械がユーザー発言由来の内容を
削除できる」と数学的に同じです。対話 forget は従来どおり可能で、元 doc は supersede 済みとして
chain に残ります（recall からは既に除外される）。

なお keeper は ES basic auth で書き込む信頼 writer なので、この判定を自分が受けることはありません。
効くのは「後から誰が触れるか」であり、しかもこの deployment では proxy の enforcement が env 未設定で
不活性です。したがって本項は defense-in-depth であって、**live な権限昇格の修正ではありません**。

### near-dup は pointer ではなく merged doc を作る

cosine > 0.95 なら 2 つの本文は構造上ほぼ同一なので、合成は不要で survivor の content をそのまま
採ります。**vector は呼び出し側の `vmap` に既にある**ので、embedding 呼び出しも judge 呼び出しも
増えません。増えるのは index 1 回と update 1 回（2 doc を supersede するので）だけです。

これで (a) 敗者の tags が生き残り、(b) `derived_from` に両 id が入って audit chain が繋がり、
(c) phase 3 が本来の目的どおり重複を「除去」して収束します（毎晩 skip して再計算し続ける形にならない）。
`reconcile_status` は `"reconciled"` にします（`"raw"` にすると不要な judge 呼び出しを買う）。

### use_count は 0、`last_used_at` は書かない

`es_backend.revise`（サーバ側の同型操作: 旧 doc を supersede し新 doc を index して derived_from を
記録）が `use_count: 0` かつ `last_used_at` 無しなので、それに揃えます。従来の UPDATE 経路は
`last_used_at = now` を書いていましたが、これは起きていない参照イベントを主張するものです。
キーを書かなければ `scoring.composite` は `provenance.written_at` にフォールバックし、それは
`now` なので **freshness は従来と同一**です。

### promotion は tags を継承しない

episode → fact promotion で根拠 episode の tags を引き継ぐことは**しません**。理由 3 つ:

- 根拠 episode は tags を保持し続け、phase 1 は `promoted_to` を持つ episode を削除しないので、
  **何も列挙不能になっていません**（= ADR 0007 の目的に資さない）。
- episode 側は高カーディナリティの語彙です。retro skill は session ごとに一意な retro-key を
  tags に入れるため、それを durable な fact index に持ち込むと以後の merge で伝播します。
- promotion は `refresh="wait_for"` の直後に同一 run の phase 3 に入り、promoted fact は
  `written_at = now` なので常に newer 側になります。つまり tags を持たせると、既存 fact を
  supersede する側に高カーディナリティ tag を載せる**新しい消失経路**を作ります。

provenance も変更しません（`agent: "memory-keeper"` / `source_class: "promoted"` は意味のある分類）。
ただし 4 キーの shape は揃えます — promotion だけが `session_id` を欠いており、mapping が宣言する
キーが 1 経路だけ欠落する状態だったためです。

## Consequences

- near-dup 1 ペアあたりのコストが update 1 回から index 1 回 + update 2 回になります。Voyage と
  judge の呼び出しは増えません。`superseded_total` は 1 ペアで 2 加算になります（supersede した
  doc 数として数える）。
- keeper に初めてテストが入ります（`test_merge_rules.py`）。純関数への assertion に加えて
  **クエリ body への assertion** を含めます: 純関数だけ直して `_source` に `tags` を足し忘れると
  union が `[]` と行われて fix が無言で無効化されるためで、実際にその状態を再現すると 2 assertion が
  落ちます。
- `identity.authorize_supersede` を keeper のテストから本物として import します。authz matrix を
  keeper 側へ複製しません（`es_client.content_hash` に drift test 無しの verbatim port が既に 1 つ
  あり、2 つ目をセキュリティ規則で作るのは避けます）。

## 未決（この ADR の範囲外）

- **NOOP の穴**: reconcile の NOOP は incoming の重複 doc を supersede せず live に残すため、
  重複が near-dup pass まで生き残ります。本 ADR は「生き残った重複が tag を失わない」ようにしただけで、
  「重複をどこで消すか」という dedup セマンティクスは変えていません。
- **phase 1 が promoted episode を恒久保持**する件（コメントは「promote 済みは落として安全」と
  読める一方、コードは `must_not exists promoted_to` で保持している）。episode index が無限成長します。
- **`eval/eval_reconcile.py` が deploy 済みコードを検証していない**件（存在しないパスと存在しない
  callable を参照し、常に内蔵 judge へ fallback する）。
- **stats の `superseded_total` / `guard_violations` / `errors` を読む alert が無い**件。
