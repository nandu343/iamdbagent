import os
import streamlit as st
import pandas as pd
from src.analyzer import analyze


def main():
    st.title("IAMDBAgent — High Risk Identities")

    st.sidebar.header("Connection / Analysis")
    uri = st.sidebar.text_input("Neo4j URI", value=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
    user = st.sidebar.text_input("Neo4j User", value=os.getenv("NEO4J_USER", "neo4j"))
    password = st.sidebar.text_input("Neo4j Pass", value=os.getenv("NEO4J_PASS", "password"), type="password")
    model = st.sidebar.text_input("LLM model (ollama)", value="llama2")

    if st.sidebar.button("Run Analysis"):
        with st.spinner("Running analysis..."):
            result = analyze(uri, user, password, days=90, model=model)
            st.session_state["analysis_result"] = result
    else:
        result = st.session_state.get("analysis_result")

    if not result:
        st.info("No analysis results yet. Click 'Run Analysis' in the sidebar.")
        return

    # If result contains valid findings
    findings = result.get("findings") if isinstance(result, dict) else None
    if not findings:
        st.error("No findings found in analysis result. Check raw output: see `result`.")
        st.write(result)
        return

    # Build table
    rows = []
    for f in findings:
        rows.append({
            "action": f.get("action"),
            "resource": f.get("resource"),
            "roles": ",".join(f.get("roles", [])) if f.get("roles") else "",
            "risk": f.get("risk"),
            "risk_score": f.get("risk_score"),
            "mitre": f.get("mitre_technique"),
        })
    df = pd.DataFrame(rows)
    st.subheader("High Risk Findings")
    st.dataframe(df)

    # Sidebar: select a finding and show before/after
    st.sidebar.subheader("Before vs After")
    idx = st.sidebar.number_input("Select finding index", min_value=0, max_value=max(0, len(rows)-1), value=0)
    sel = findings[idx]
    before = sel.get("risk_score")
    after = sel.get("risk_score_after")
    st.sidebar.markdown(f"**Action:** {sel.get('action')}\n\n**Resource:** {sel.get('resource')}")
    st.sidebar.markdown(f"**Before Risk Score:** {before}")
    st.sidebar.markdown(f"**After Risk Score (estimated):** {after if after is not None else 'N/A'}")


if __name__ == "__main__":
    main()
