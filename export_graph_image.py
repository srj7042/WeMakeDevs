"""
Export the FalkorDB 'oracle_incidents' graph as rendered images (PNG + SVG).

Renders one overview of the whole graph (hierarchical `dot` layout) plus one
readable subgraph per incident (packed `neato` layout). Reads only over the
existing read-only client and shells out to Graphviz. Requires `brew install
graphviz`.

Usage: .venv/bin/python export_graph_image.py [out_dir]
"""

import os
import sys
from subprocess import run

from client import OracleIncidentsClient

GRAPH_NAME = "oracle_incidents"

STYLE = {
    "Incident": ("#fecdd3", "#e11d48", "doubleoctagon"),
    "Alert": ("#fef3c7", "#d97706", "diamond"),
    "Service": ("#ccfbf1", "#0d9488", "box"),
    "Package": ("#ede9fe", "#7c3aed", "component"),
    "Vulnerability": ("#fee2e2", "#b91c1c", "octagon"),
    "Deployment": ("#dbeafe", "#2563eb", "folder"),
    "Evidence": ("#f1f5f9", "#64748b", "note"),
    "Team": ("#e0f2fe", "#0284c7", "ellipse"),
    "Action": ("#fef9c3", "#ca8a04", "hexagon"),
}
DEFAULT_STYLE = ("#f5f5f5", "#525252", "ellipse")

# $id: incident to expand around. Everything the investigation touches hangs off it.
INCIDENT_NODES = """
MATCH (i:Incident {id: $id})
OPTIONAL MATCH (i)-[:HAS_ALERT]->(a:Alert)-[:OBSERVED_ON]->(s:Service)
OPTIONAL MATCH (i)-[:RECOMMENDS]->(act:Action)
OPTIONAL MATCH (ev:Evidence)-[:SUPPORTS]->(i)
OPTIONAL MATCH (s)-[:DEPENDS_ON*0..3]->(down:Service)
OPTIONAL MATCH (down)-[:USES]->(p:Package)-[:HAS_VULNERABILITY]->(v:Vulnerability)
OPTIONAL MATCH (down)-[:DEPLOYED_IN]->(dep:Deployment)
OPTIONAL MATCH (down)-[:OWNED_BY]->(t:Team)
RETURN DISTINCT id(i), id(a), id(s), id(act), id(ev), id(down), id(p), id(v), id(dep), id(t)
"""
NODES_BY_ID = "MATCH (n) WHERE id(n) IN $ids RETURN id(n), labels(n), properties(n)"
EDGES_BY_ID = (
    "MATCH (a)-[r]->(b) WHERE id(a) IN $ids AND id(b) IN $ids "
    "RETURN id(a), id(b), type(r)"
)


def label_of(props: dict) -> str:
    """Pick the most descriptive human label out of a node's properties."""
    parts = [
        props.get("name"),
        props.get("title"),
        props.get("id") or props.get("cve_id"),
    ]
    parts = [p for p in parts if p]
    return " · ".join(str(p) for p in parts[:2]) or "?"


def esc(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def build_dot(title: str, nodes, edges) -> str:
    lines = [
        f"digraph {GRAPH_NAME} {{",
        '  graph [rankdir=LR, splines=true, nodesep=0.35, ranksep=0.9, bgcolor="white",',
        '         fontname="Helvetica", fontsize=22, pad=0.4,',
        f'         label="{esc(title)}", labelloc=t];',
        '  node  [style="filled,rounded", fontname="Helvetica", fontsize=11, margin=0.13];',
        '  edge  [fontname="Helvetica", fontsize=9, color="#94a3b8", fontcolor="#475569", arrowsize=0.7];',
    ]
    for node in nodes:
        kind = node["labels"][0] if node["labels"] else "?"
        fill, border, shape = STYLE.get(kind, DEFAULT_STYLE)
        lines.append(
            f'  n{node["id"]} [label="{esc(label_of(node["props"]))}", '
            f'fillcolor="{fill}", color="{border}", shape={shape}, penwidth=1.6];'
        )
    for src, dst, rel in edges:
        lines.append(f'  n{src} -> n{dst} [label="{esc(rel)}"];')
    lines.append("}")
    return "\n".join(lines)


def render(name: str, title: str, nodes, edges, out_dir: str, dpi: int) -> list:
    dot_path = os.path.join(out_dir, f"{name}.dot")
    with open(dot_path, "w") as fh:
        fh.write(build_dot(title, nodes, edges))

    paths = [dot_path]
    for fmt in ("png", "svg"):
        path = os.path.join(out_dir, f"{name}.{fmt}")
        run(["dot", f"-T{fmt}", dot_path, "-o", path, f"-Gdpi={dpi}"], check=True)
        paths.append(path)
    print(f"{name}: {len(nodes)} nodes / {len(edges)} relationships")
    for path in paths:
        print(f"  {path}  ({os.path.getsize(path) / 1024:.1f} KB)")
    return paths


def main() -> None:
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "graph_export"
    os.makedirs(out_dir, exist_ok=True)
    client = OracleIncidentsClient()

    def nodes_for(ids):
        return [
            {"id": r[0], "labels": r[1], "props": r[2]}
            for r in client.read_query(NODES_BY_ID, params={"ids": sorted(ids)}).result_set
        ]

    def edges_for(ids):
        return client.read_query(EDGES_BY_ID, params={"ids": sorted(ids)}).result_set

    all_ids = {r[0] for r in client.read_query("MATCH (n) RETURN id(n)").result_set}
    render(
        GRAPH_NAME,
        f"ImpactGraph — FalkorDB '{GRAPH_NAME}' (full graph)",
        nodes_for(all_ids),
        edges_for(all_ids),
        out_dir,
        dpi=96,
    )

    incidents = client.read_query(
        "MATCH (i:Incident) RETURN i.id, i.title ORDER BY i.id"
    ).result_set
    for incident_id, incident_title in incidents:
        rows = client.read_query(INCIDENT_NODES, params={"id": incident_id}).result_set
        ids = {value for row in rows for value in row if value is not None}
        render(
            incident_id.lower(),
            f"{incident_id} — {incident_title}",
            nodes_for(ids),
            edges_for(ids),
            out_dir,
            dpi=130,
        )

    client.close()


if __name__ == "__main__":
    main()
