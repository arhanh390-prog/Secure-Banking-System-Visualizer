# app.py
import streamlit as st
import pandas as pd
import time
import random
import io
from datetime import datetime
import pydeck as pdk
import plotly.express as px
import plotly.graph_objects as go
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# ----------------------------
# Page config
# ----------------------------
st.set_page_config(page_title="Secure Banking Visualizer (Advanced)", layout="wide", page_icon="🏦")

st.title("🏦 Secure Banking System Visualizer — Advanced")
st.markdown("Interactive demo: network, encryption, threat simulation, RBAC, and global comparisons.")

# ----------------------------
# Sidebar navigation
# ----------------------------
section = st.sidebar.selectbox("Navigate", [
    "Overview",
    "Network & DR Simulation",
    "RBAC & Escalation",
    "Transaction Risk Scoring",
    "Threat Feed & SIEM",
    "Encryption & Digital Signature",
    "Global Branch Map",
    "Global Security Comparison",
    "Download / Docs"
])

# ----------------------------
# Helper utilities
# ----------------------------
def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def generate_transaction(id):
    # Simulated transaction with random features that influence risk
    locations = ["Mumbai", "Delhi", "Chennai", "Bengaluru", "London", "New York", "Dubai", "Singapore"]
    tx = {
        "tx_id": f"TX-{id:05d}",
        "timestamp": now(),
        "from_acc": f"IN{random.randint(10000000,99999999)}",
        "to_acc": f"IN{random.randint(10000000,99999999)}",
        "amount": round(random.uniform(100.0, 150000.0), 2),
        "origin": random.choice(locations),
        "destination": random.choice(locations),
        "failed_logins": random.randint(0,5),
        "device_known": random.choice([True, True, True, False])  # more likely known
    }
    # Risk score heuristic (simulated)
    score = 0
    if tx["amount"] > 50000: score += 40
    if tx["origin"] != tx["destination"]: score += 10
    if not tx["device_known"]: score += 20
    if tx["failed_logins"] > 1: score += 15
    # clamp
    tx["risk_score"] = min(100, score + random.randint(-5,10))
    tx["risk_level"] = "Low" if tx["risk_score"] < 30 else ("Medium" if tx["risk_score"] < 60 else "High")
    return tx

# ----------------------------
# Section: Overview
# ----------------------------
if section == "Overview":
    st.header("Overview & Learning Goals")
    st.markdown("""
    This advanced demo covers:
    - Visual network flow and DR failover simulation  
    - Role-Based Access Controls and escalation events  
    - Transaction risk scoring (AI-like heuristic)  
    - Live threat feed / SIEM mock with mitigation simulation  
    - Encryption (Fernet) + RSA digital signatures  
    - Global branch map with risk overlays  
    - Comparative charts of security capabilities across banks  
    """)
    st.info("Tip: Use the sidebar to jump between modules. All data shown is simulated for educational/demo purposes.")

# ----------------------------
# Section: Network & DR Simulation
# ----------------------------
elif section == "Network & DR Simulation":
    st.header("Network Topology & DR Failover Simulation")
    st.write("Simulate traffic from branches to core server. Trigger DR failover to see automatic backup routing.")
    col1, col2 = st.columns([2,1])

    with col1:
        # Create a small network graph using Plotly scatter + lines
        nodes = [
            {"id":"Customer","x":0,"y":0},
            {"id":"Branch_A","x":1,"y":1},
            {"id":"Branch_B","x":1,"y":-1},
            {"id":"Regional_DC","x":3,"y":0},
            {"id":"Core_Server","x":5,"y":0},
            {"id":"Encrypted_DB","x":7,"y":1},
            {"id":"DR_Site","x":7,"y":-1},
        ]
        edges = [("Customer","Branch_A"),("Customer","Branch_B"),("Branch_A","Regional_DC"),("Branch_B","Regional_DC"),
                 ("Regional_DC","Core_Server"),("Core_Server","Encrypted_DB"),("Regional_DC","DR_Site")]
        # build scatter
        node_x = [n["x"] for n in nodes]
        node_y = [n["y"] for n in nodes]
        node_text = [n["id"] for n in nodes]
        fig = go.Figure()
        # edges
        for e in edges:
            a = next(n for n in nodes if n["id"]==e[0])
            b = next(n for n in nodes if n["id"]==e[1])
            fig.add_trace(go.Scatter(x=[a["x"], b["x"]], y=[a["y"], b["y"]],
                                     mode="lines", line=dict(color="lightgray"), hoverinfo="none"))
        # nodes
        fig.add_trace(go.Scatter(x=node_x, y=node_y, mode="markers+text", text=node_text,
                                 marker=dict(size=30, color=["lightblue","lightgreen","lightgreen","orange","gold","lightgray","pink"]),
                                 textposition="top center"))
        fig.update_layout(showlegend=False, xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                          yaxis=dict(showgrid=False, zeroline=False, showticklabels=False), height=450)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Control Panel")
        failover = st.button("🔴 Simulate Core Server Outage / Trigger DR Failover")
        if failover:
            status = st.empty()
            status.info("Core Server status: DOWN — activating Disaster Recovery (DR) site...")
            for i in range(4):
                status.text(f"Failover in progress... step {i+1}/4")
                time.sleep(0.6)
            status.success("Failover complete — traffic routed to DR site. Core restored in 15 minutes (simulated).")
            st.balloons()
        else:
            st.write("Core Server status: ✅ UP (click button to simulate outage)")
            st.write("DR site: Standby (replication every 5 minutes).")

    st.markdown("---")
    st.markdown("**Notes:** Encrypted channels (TLS/VPN) exist on each link. Failover ensures business continuity.")

# ----------------------------
# Section: RBAC & Escalation
# ----------------------------
elif section == "RBAC & Escalation":
    st.header("Role-Based Access Control (RBAC) & Access Escalation Demo")
    st.write("Choose role and attempt operations. Watch logs for escalation and audits.")
    role = st.selectbox("Pick a role:", ["Customer", "Teller (Employee)", "Branch Manager", "Admin / Security Officer"])
    action = st.selectbox("Attempt action:", [
        "View own account details",
        "View a customer's KYC (other branch)",
        "Approve high-value transfer",
        "View system audit logs"
    ])
    st.write("🔐 Access decision:")

    # Simple RBAC rules (simulated)
    allowed = False
    reason = ""
    if role == "Customer":
        if action == "View own account details":
            allowed = True
        else:
            allowed = False
            reason = "Customers cannot view KYC or system logs."
    elif role == "Teller (Employee)":
        if action in ["View own account details", "Approve high-value transfer"]:
            allowed = False
            reason = "Teller can't approve high-value transfers -- manager approval required."
        else:
            # view branch-level KYC allowed, but not other branches
            allowed = (action == "View a customer's KYC (other branch)")
            if allowed:
                allowed = False
                reason = "Access denied: cross-branch restriction."
    elif role == "Branch Manager":
        if action in ["View own account details", "Approve high-value transfer", "View a customer's KYC (other branch)"]:
            allowed = True
        else:
            allowed = False
            reason = "Managers can't view system-wide audit logs."
    elif role == "Admin / Security Officer":
        allowed = True

    if allowed:
        st.success(f"✔️ Access GRANTED for `{role}` to `{action}`.")
    else:
        st.error(f"❌ Access DENIED. {reason or 'Policy does not allow this action.'}")
        st.warning("An access denial generates an audit entry and may trigger an escalation review.")

    # Mock audit log viewer
    st.markdown("### Audit Log (simulated)")
    log_space = st.empty()
    logs = [
        f"{now()} | INFO | User=emp_254 | Action=LOGIN | Outcome=SUCCESS",
        f"{now()} | WARN | User=emp_254 | Action=ACCESS_KYC | Outcome=DENIED | Reason=Cross-branch",
        f"{now()} | INFO | User=admin_01 | Action=VIEW_AUDIT | Outcome=SUCCESS"
    ]
    log_space.text("\n".join(logs))

# ----------------------------
# Section: Transaction Risk Scoring
# ----------------------------
elif section == "Transaction Risk Scoring":
    st.header("Transaction Stream & AI-Style Risk Scoring (Simulated)")
    col1, col2 = st.columns([2,1])
    with col1:
        num = st.slider("Number of simulated transactions to generate", 5, 200, 30)
        simulate_btn = st.button("Generate Transactions & Scores")
        if simulate_btn:
            txs = [generate_transaction(i+1) for i in range(num)]
            df = pd.DataFrame(txs)
            st.dataframe(df[["tx_id","timestamp","amount","origin","destination","failed_logins","device_known","risk_score","risk_level"]])
            # Plot distribution of risk scores
            fig = px.histogram(df, x="risk_score", nbins=10, title="Risk Score Distribution")
            st.plotly_chart(fig, use_container_width=True)
            # Show top risky transactions
            st.subheader("Top 10 High-Risk Transactions")
            st.table(df.sort_values("risk_score", ascending=False).head(10)[["tx_id","amount","origin","destination","risk_score","risk_level"]])
    with col2:
        st.metric("Avg Risk Score (simulated)", value="—")
        st.markdown("**Risk heuristics used (simulated educational model):**\n- Large amounts (>₹50k) add risk\n- Unknown device/location mismatch add risk\n- Failed logins add risk\n- Random noise to simulate ML model variance")

# ----------------------------
# Section: Threat Feed & SIEM
# ----------------------------
elif section == "Threat Feed & SIEM":
    st.header("Live Threat Feed (Simulated) & SIEM Dashboard")
    st.write("Generate a feed of alerts. Each alert has severity and suggested mitigation.")

    alerts_container = st.container()
    controls = st.columns([1,1,1])
    with controls[0]:
        gen_count = st.number_input("Number of alerts to generate", min_value=1, max_value=50, value=5)
    with controls[1]:
        severity_bias = st.selectbox("Bias towards severity", ["Balanced","More High", "More Low"])
    with controls[2]:
        gen_btn = st.button("Generate Alerts")

    def gen_alert(i):
        sev_choice = random.choices(["Low","Medium","High"], weights=(5,3,1))[0]
        if severity_bias == "More High":
            sev_choice = random.choices(["Low","Medium","High"], weights=(3,3,4))[0]
        elif severity_bias == "More Low":
            sev_choice = random.choices(["Low","Medium","High"], weights=(6,3,1))[0]
        alerts = {
            "id": f"A-{random.randint(10000,99999)}",
            "time": now(),
            "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
            "event": random.choice(["Failed Login","Suspicious Transfer","Anomalous Login Location","Malware Detected","Unusual API Usage"]),
            "severity": sev_choice
        }
        # Suggested mitigation
        if alerts["severity"] == "High":
            alerts["mitigation"] = "Block IP, force password reset, escalate to SOC"
        elif alerts["severity"] == "Medium":
            alerts["mitigation"] = "Require re-authentication, monitor for 1h"
        else:
            alerts["mitigation"] = "Log and monitor"
        return alerts

    if gen_btn:
        df_alerts = []
        for i in range(int(gen_count)):
            a = gen_alert(i)
            df_alerts.append(a)
        df_alerts = pd.DataFrame(df_alerts)
        # show alert list
        st.subheader("Alerts")
        st.table(df_alerts)
        # summary metrics
        counts = df_alerts["severity"].value_counts().to_dict()
        st.metric("Total Alerts", value=len(df_alerts))
        st.write("Severity counts:", counts)
        # show timeline
        fig = px.timeline(df_alerts, x_start="time", x_end="time", y="severity", color="severity")
        st.plotly_chart(fig, use_container_width=True)
        # mitigation simulation
        st.markdown("### Mitigation Simulation")
        for idx, row in df_alerts.iterrows():
            st.write(f"- [{row['severity']}] {row['event']} from {row['source_ip']} — Suggested: {row['mitigation']}")
            if row["severity"] == "High":
                if st.button(f"🛑 Mitigate {row['id']}", key=f"mit_{idx}"):
                    st.success(f"Mitigation applied for {row['id']}: {row['mitigation']}")
    else:
        st.info("Generate alerts to populate the SIEM table and simulate mitigation steps.")

# ----------------------------
# Section: Encryption & Digital Signature
# ----------------------------
elif section == "Encryption & Digital Signature":
    st.header("Encryption Demo (Fernet) & RSA Digital Signature Demo")
    st.write("Encrypt files/text with a symmetric key and sign messages with RSA keys.")

    st.subheader("1) Symmetric Encryption (Fernet)")
    text = st.text_area("Text to encrypt (sensitive info)", "Employee Salary: ₹80,000; PAN: ABCD1234E")
    if st.button("Encrypt Text"):
        key = Fernet.generate_key()
        f = Fernet(key)
        token = f.encrypt(text.encode())
        st.code(f"Key (keep secret): {key.decode()}")
        st.code(f"Encrypted (token): {token.decode()}")
        if st.button("Decrypt Text"):
            dec = f.decrypt(token).decode()
            st.success(f"Decrypted: {dec}")

    st.markdown("---")
    st.subheader("2) RSA Digital Signature")
    st.write("Generate an RSA keypair, sign a message, and verify it.")

    if "rsa_private" not in st.session_state:
        # generate one-time per session RSA keys
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        st.session_state.rsa_private = private_key
        st.session_state.rsa_public = public_key

    message = st.text_input("Message to sign", "Approve transfer of ₹100,000 to IN12345678")
    sign_btn = st.button("Sign Message")
    if sign_btn:
        private_key = st.session_state.rsa_private
        signature = private_key.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        st.session_state.last_signature = signature
        st.success("Message signed (signature in memory).")
        # show public key PEM for verification use
        pub_pem = st.session_state.rsa_public.public_bytes(encoding=serialization.Encoding.PEM,
                                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
        st.code(pub_pem.decode())

    if st.button("Verify Signature"):
        if "last_signature" not in st.session_state:
            st.error("No signature found. Sign first.")
        else:
            try:
                st.session_state.rsa_public.verify(
                    st.session_state.last_signature,
                    message.encode(),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                st.success("Signature verified: message is authentic and untampered.")
            except Exception as e:
                st.error(f"Verification failed: {e}")

# ----------------------------
# Section: Global Branch Map
# ----------------------------
elif section == "Global Branch Map":
    st.header("Global Bank Branch Map (Interactive)")
    st.write("Branches, HQs and DR sites with risk overlay (simulated). Hover for details.")

    # demo data with risk levels
    map_data = pd.DataFrame([
        {"lat":19.0760,"lon":72.8777,"name":"Mumbai (HQ)","type":"HQ","risk":"Low","branches":120},
        {"lat":28.6139,"lon":77.2090,"name":"Delhi Branch","type":"Branch","risk":"Medium","branches":45},
        {"lat":13.0827,"lon":80.2707,"name":"Chennai Branch","type":"Branch","risk":"Low","branches":30},
        {"lat":12.9716,"lon":77.5946,"name":"Bengaluru Branch","type":"Branch","risk":"Low","branches":50},
        {"lat":40.7128,"lon":-74.0060,"name":"New York (Partner)","type":"Partner","risk":"High","branches":10},
        {"lat":51.5074,"lon":-0.1278,"name":"London (Partner)","type":"Partner","risk":"Medium","branches":8},
        {"lat":25.2048,"lon":55.2708,"name":"Dubai (Branch)","type":"Branch","risk":"Medium","branches":5},
        {"lat":1.3521,"lon":103.8198,"name":"Singapore (Branch)","type":"Branch","risk":"Low","branches":6}
    ])

    # color mapping
    def color_for_risk(r):
        return [0,200,0,160] if r=="Low" else ([255,165,0,160] if r=="Medium" else [255,0,0,160])

    map_data["color"] = map_data["risk"].apply(color_for_risk)

    layer = pdk.Layer(
        "ScatterplotLayer",
        data=map_data,
        get_position='[lon, lat]',
        get_radius=50000,
        get_color='color',
        pickable=True
    )

    tooltip = {"html": "<b>{name}</b><br/>Type: {type}<br/>Risk: {risk}<br/>Branches: {branches}", "style": {"color":"white"}}
    view_state = pdk.ViewState(latitude=20, longitude=10, zoom=1.7, pitch=0)
    deck = pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip=tooltip, map_style='mapbox://styles/mapbox/light-v9')
    st.pydeck_chart(deck)

# ----------------------------
# Section: Global Security Comparison
# ----------------------------
elif section == "Global Security Comparison":
    st.header("Global Security Comparison (Interactive Charts)")
    df = pd.DataFrame({
        "Feature": ["AI Fraud Detection","Zero-Trust","Quantum Encryption Pilots","Automated Cloud Audits","Biometric MFA"],
        "JPMorgan": [9,9,6,9,9],
        "SBI": [5,4,2,4,3],
        "HSBC": [8,7,5,8,8]
    })
    st.dataframe(df)
    fig = go.Figure()
    for bank in ["JPMorgan","SBI","HSBC"]:
        fig.add_trace(go.Bar(name=bank, x=df["Feature"], y=df[bank]))
    fig.update_layout(barmode='group', xaxis_tickangle=-45, height=450)
    st.plotly_chart(fig, use_container_width=True)
    st.markdown("**Scale:** 1 (low adoption) — 10 (full/advanced adoption). Values are illustrative for lecture comparison.")

# ----------------------------
# Section: Download / Docs
# ----------------------------
elif section == "Download / Docs":
    st.header("Download & Documentation")
    st.write("You can download simulated data and a short README for your presentation.")
    # create a sample README and a CSV of simulated transactions
    if st.button("Generate sample transactions CSV"):
        txs = [generate_transaction(i+1) for i in range(100)]
        df = pd.DataFrame(txs)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download transactions.csv", csv, file_name="simulated_transactions.csv", mime="text/csv")
    readme_text = """
Secure Banking System Visualizer
================================
This Streamlit app is a teaching/demo tool that simulates network topology, transaction risk scoring,
threat feeds, RBAC policies, encryption, and digital signatures for a banking environment.
All data is simulated and intended for educational use.
    """
    st.download_button("Download README", readme_text, file_name="README.txt")
    st.markdown("**Deployment Tips:** Include `requirements.txt` in your repo. Deploy on Streamlit Cloud (share.streamlit.io).")

# ----------------------------
# End
# ----------------------------
st.markdown("---")
st.caption("All content simulated for lecture/demo. Not production-grade — designed for education.")
