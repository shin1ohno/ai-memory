"""The in-code index definitions must match es-indices-v2/*.json.

es_backend.py builds these so the server can bootstrap a fresh cluster, and only a
comment kept the two in step. The module cannot be imported here without its
runtime clients, so only the assignments and builders that form the mappings are
compiled from its source.
"""
import ast
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mappings():
    source = ROOT / "memory-mcp/es_backend.py"
    tree = ast.parse(source.read_text())
    names = {"_ANALYSIS", "_INDEX_DEFS"}
    functions = {"_common_props", "_content_index_def"}
    selected = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            selected.append(node)
        elif isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id in names for t in node.targets
        ):
            selected.append(node)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id in names:
            selected.append(node)
    namespace = {
        "EMBEDDING_DIMS": 1024,
        "FACT_INDEX": "memory-fact",
        "KNOWLEDGE_INDEX": "memory-knowledge",
        "EPISODE_INDEX": "memory-episode",
        "STATS_INDEX": "memory-stats",
    }
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["_INDEX_DEFS"]


class IndexMappings(unittest.TestCase):
    # A truncated diff would hide the field that drifted.
    maxDiff = None

    def test_four_index_mappings(self):
        actual = mappings()
        self.assertEqual(len(actual), 4)
        for name, definition in actual.items():
            with self.subTest(index=name):
                expected = json.loads((ROOT / f"es-indices-v2/{name}.json").read_text())
                self.assertEqual(definition["mappings"], expected["mappings"], name)


if __name__ == "__main__":
    unittest.main()
