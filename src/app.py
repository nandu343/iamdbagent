import os
import streamlit as st
from neo4j import GraphDatabase
from src.analyzer import find_zombie_permissions, find_shadow_admin_paths
import json
import networkx as nx
from pyvis.network import Network
import tempfile
import streamlit.components.v1 as components


def get_driver():
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    user = os.getenv("NEO4J_USER", "neo4j")
    password = os.getenv("NEO4J_PASS", "password")
    return GraphDatabase.driver(uri, auth=(user, password))


def main():
    st.title("IAMDBAgent — MVP Dashboard")

    st.sidebar.header("Connection")
    uri = st.sidebar.text_input("Neo4j URI", value=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    user = st.sidebar.text_input("Neo4j User", value=os.getenv("NEO4J_USER", "neo4j"))
    password = st.sidebar.text_input("Neo4j Pass", value=os.getenv("NEO4J_PASS", "password"), type="password")

    if st.sidebar.button("Refresh"):
        st.rerun()

    st.header("High-Risk Findings")
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        with driver.session() as session:
            findings = find_zombie_permissions(driver, days=90)
            shadow = find_shadow_admin_paths(driver, max_hops=6)
        driver.close()

        st.subheader("Zombie Permissions (unused > 90 days)")
        st.write(f"Found {len(findings)} zombie permissions")
        st.json(findings)

        st.subheader("Shadow Admin Paths")
        st.write(f"Found {len(shadow)} potential transitive admin paths")
        # Build a pyvis graph from shadow paths
        net = Network(height="600px", width="100%", notebook=False)
        g = nx.DiGraph()
        for s in shadow:
            path = s.get("path", [])
            # create nodes and edges
            prev_id = None
            for idx, node in enumerate(path):
                node_id = f"{s.get('user')}_{idx}_{'_'.join(node.get('labels', []))}"
                label = ",".join(node.get("labels", [])) + "\n" + (node.get("props", {}).get("name", ""))
                if not g.has_node(node_id):
                    g.add_node(node_id, label=label)
                if prev_id:
                    g.add_edge(prev_id, node_id)
                prev_id = node_id

        # load into pyvis
        for n, data in g.nodes(data=True):
            net.add_node(n, label=data.get("label"))
        for a, b in g.edges():
            net.add_edge(a, b)

        # generate HTML and embed
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
        net.show(tmp.name)
        with open(tmp.name, "r", encoding="utf-8") as f:
            html = f.read()
        components.html(html, height=650)

    except Exception as e:
        st.error(f"Error connecting to Neo4j: {e}")


if __name__ == "__main__":
    main()
