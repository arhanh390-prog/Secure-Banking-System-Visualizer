import streamlit as st
import pandas as pd
import time
import random
import io
import re
from datetime import datetime
import pydeck as pdk
import plotly.express as px
import plotly.graph_objects as go
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

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
    "RBAC, Insider Threat & DLP",
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

def generate_transaction(id, behavioral_anomaly=False):
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
        "device_known": random.choice([True, True, True, False]), # more likely known
        "behavioral_anomaly": behavioral_anomaly
    }
    # Risk score heuristic (simulated)
    score = 0
    if tx["amount"] > 50000: score += 40
    if tx["origin"] != tx["destination"]: score += 10
    if not tx["device_known"]: score += 20
    if tx["failed_logins"] > 1: score += 15
    
    # **NEW FEATURE from lecture notes**
    if tx["behavioral_anomaly"]: score += 25

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
    - **Network Topology:** Visualizing the Core Banking System (CBS) and branch connectivity (WAN/MPLS).
    - **Disaster Recovery:** Simulating a real-time failover from a Primary to a DR data center.
    - **Insider Threats:** Demonstrating Role-Based Access Control (RBAC) and Data Loss Prevention (DLP).
    - **AI-Driven Risk:** Simulating a fraud detection engine, now including behavioral biometrics.
    - **Live SIEM:** A mock Security Operations Center (SOC) dashboard, now detecting phishing attempts.
    - **Cryptography:** Hands-on demo of symmetric (Fernet) and asymmetric (RSA) encryption, with notes on the future Quantum Threat.
    - **Global Benchmarking:** Comparing Indian vs. Global bank security postures.
    """)
    st.info("Tip: Use the sidebar to jump between modules. All data shown is simulated for educational/demo purposes.")

# ----------------------------
# Section: Network & DR Simulation
# ----------------------------
elif section == "Network & DR Simulation":
    st.header("Network Topology & DR Failover Simulation")
    st.markdown("""
    This shows a simplified **Core Banking System (CBS)** architecture common in India.
    - **Branches** (in different cities) connect via a private, encrypted **Wide Area Network (WAN/MPLS)**, not the public internet.
    - They are secure "windows" into the central **Core Server (CBS)**, which holds all customer data.
    - The **DR Site** is a real-time, mirrored copy of the Core Server, ready to take over instantly if the primary fails.
    """)
    col1, col2 = st.columns([2,1])

    with col1:
        # Create a small network graph using Plotly scatter + lines
        nodes = [
            {"id":"Customer","x":0,"y":0},
            {"id":"Branch_A (Mumbai)","x":1,"y":1},
            {"id":"Branch_B (Kolkata)","x":1,"y":-1},
            {"id":"Regional_DC (WAN/MPLS)","x":3,"y":0},
            {"id":"Core_Server (CBS - Mumbai)","x":5,"y":0.5},
            {"id":"Encrypted_DB","x":7,"y":0.5},
            {"id":"DR_Site (CBS - Chennai)","x":5,"y":-1},
        ]
        edges = [("Customer","Branch_A (Mumbai)"),("Customer","Branch_B (Kolkata)"),("Branch_A (Mumbai)","Regional_DC (WAN/MPLS)"),("Branch_B (Kolkata)","Regional_DC (WAN/MPLS)"),
                 ("Regional_DC (WAN/MPLS)","Core_Server (CBS - Mumbai)"),("Core_Server (CBS - Mumbai)","Encrypted_DB"),
                 ("Regional_DC (WAN/MPLS)","DR_Site (CBS - Chennai)")] # DR Link
        
        fig = go.Figure()
        
        # Add edges
        for e in edges:
            a = next(n for n in nodes if n["id"]==e[0])
            b = next(n for n in nodes if n["id"]==e[1])
            line_style = dict(color="lightgray")
            if e == ("Regional_DC (WAN/MPLS)","DR_Site (CBS - Chennai)"):
                line_style = dict(color="red", dash="dot")
            fig.add_trace(go.Scatter(x=[a["x"], b["x"]], y=[a["y"], b["y"]],
                                     mode="lines", line=line_style, hoverinfo="none"))
        # Add nodes
        node_x = [n["x"] for n in nodes]
        node_y = [n["y"] for n in nodes]
        node_text = [n["id"] for n in nodes]
        fig.add_trace(go.Scatter(x=node_x, y=node_y, mode="markers+text", text=node_text,
                                 marker=dict(size=30, color=["lightblue","lightgreen","lightgreen","orange","gold","lightgray","pink"]),
                                 textposition="top center"))
        
        fig.update_layout(showlegend=False, xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                          yaxis=dict(showgrid=False, zeroline=False, showticklabels=False), height=450)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Control Panel")
        failover = st.button("🔴 Simulate Core Server Outage / Trigger DR Failover")
        
        if 'dr_active' not in st.session_state:
            st.session_state.dr_active = False

        if failover:
            st.session_state.dr_active = True
            status = st.empty()
            status.info("Core Server status: DOWN — activating Disaster Recovery (DR) site...")
            for i in range(4):
                status.info(f"Failover in progress... Rerouting WAN traffic... step {i+1}/4")
                time.sleep(0.6)
            status.success("Failover complete — All traffic routed to DR Site (Chennai). Business continuity maintained.")
            st.balloons()
        
        if st.session_state.dr_active:
             st.success("STATUS: Traffic actively routed to DR Site.")
        else:
             st.info("STATUS: Core Server (CBS - Mumbai) is UP. DR Site (Chennai) is on standby.")

    st.markdown("---")
    st.markdown("**Notes:** Encrypted channels (TLS/VPN) exist on each link. Failover ensures business continuity.")

# ----------------------------
# Section: RBAC, Insider Threat & DLP
# ----------------------------
elif section == "RBAC, Insider Threat & DLP":
    st.header("Role-Based Access Control (RBAC) & Insider Threat Demo")
    st.write("Choose role and attempt operations. Watch logs for escalation and audits.")
    
    role = st.selectbox("Pick a role:", ["Customer", "Teller (Employee)", "Branch Manager", "Admin / Security Officer", "HR Employee"])
    action = st.selectbox("Attempt action:", [
        "View own account details",
        "View a customer's KYC (other branch)",
        "Approve high-value transfer",
        "View system audit logs",
        "View another employee's salary"
    ])
    st.write("🔐 Access decision:")

    # Simple RBAC rules (simulated)
    allowed = False
    reason = ""
    if role == "Customer":
        if action == "View own account details": allowed = True
        else: reason = "Customers cannot view KYC, employee data, or system logs."
    elif role == "Teller (Employee)":
        if action == "Approve high-value transfer": reason = "Teller can't approve high-value transfers -- manager approval required."
        elif action == "View a customer's KYC (other branch)": reason = "Access denied: cross-branch restriction."
        elif action == "View system audit logs": reason = "Policy violation: Tellers cannot view system logs."
        elif action == "View another employee's salary": reason = "Critical Policy Violation: Tellers cannot access HR data."
    elif role == "Branch Manager":
        if action in ["Approve high-value transfer", "View a customer's KYC (other branch)"]: allowed = True
        elif action == "View system audit logs": reason = "Managers can't view system-wide audit logs."
        elif action == "View another employee's salary": reason = "Critical Policy Violation: Managers cannot access HR data."
    elif role == "Admin / Security Officer":
        if action == "View another employee's salary": reason = "Policy Violation: Security Officers cannot view salary data (Separation of Duties)."
        else: allowed = True
    elif role == "HR Employee":
         if action == "View another employee's salary": allowed = True
         else: reason = "HR can only view employee data, not customer or system logs."

    if allowed:
        st.success(f"✔️ Access GRANTED for `{role}` to `{action}`.")
    else:
        st.error(f"❌ Access DENIED. {reason or 'Policy does not allow this action.'}")
        st.warning("An access denial generates an audit entry and may trigger an escalation review.")

    st.markdown("---")
    
    # **NEW FEATURE from lecture notes**
    st.header("Data Loss Prevention (DLP) Simulation")
    st.markdown("Simulate an employee trying to send an email. The DLP system scans for sensitive keywords and PII.")
    
    dlp_col1, dlp_col2 = st.columns(2)
    with dlp_col1:
        st.text_input("From:", value=f"{role.lower().replace(' ','.')}@bank.in", disabled=True)
        dlp_to = st.text_input("To:", "example@gmail.com")
        dlp_body = st.text_area("Email Body:", "Hi, just sending the details you asked for. The customer's PAN is ABCDE1234F and their balance is 50,000 INR.")
    
    if st.button("Simulate Send Email"):
        # Simple DLP rules
        is_external = "gmail.com" in dlp_to or "yahoo.com" in dlp_to
        has_pii = "pan" in dlp_body.lower() or bool(re.search(r"[A-Z]{5}[0-9]{4}[A-Z]{1}", dlp_body))
        
        with dlp_col2:
            st.subheader("DLP Analysis Result")
            if is_external and has_pii and role in ["Teller (Employee)", "Branch Manager"]:
                st.error("🟥 **BLOCKED: DLP Policy Violation**")
                st.write(f"**Reason:** PII (PAN Card) detected in an email to an external domain (`{dlp_to}`).")
                st.write(f"**Action:** Email quarantined. Alert sent to Security Officer.")
            elif not has_pii:
                st.success("✅ **SENT: No PII Detected**")
                st.write("Email does not violate DLP policy.")
            elif not is_external:
                st.success("✅ **SENT: Internal Communication**")
                st.write(f"Email contains PII but is internal (`{dlp_to}`). Logged for audit.")
            else:
                st.success("✅ **SENT: Policy Compliant**")

# ----------------------------
# Section: Transaction Risk Scoring
# ----------------------------
elif section == "Transaction Risk Scoring":
    st.header("Transaction Stream & AI-Style Risk Scoring (Simulated)")
    
    col1, col2 = st.columns([3,1])
    
    with col1:
        num = st.slider("Number of simulated transactions to generate", 5, 200, 30)
        
        # **NEW FEATURE from lecture notes**
        st.markdown("**AI Model Inputs (Simulated):**")
        anomaly_check = st.checkbox("Simulate Behavioral Anomaly (e.g., unusual typing speed, mouse patterns)")
        
        simulate_btn = st.button("Generate Transactions & Scores")

    with col2:
        st.markdown("**Risk Heuristics:**")
        st.markdown("- Large amounts add risk\n- Unknown device add risk\n- Failed logins add risk\n- **Behavioral Anomaly adds +25 risk**")

    if simulate_btn:
        txs = []
        for i in range(num):
            # Pass the anomaly flag to the generator
            # Make it random for other transactions if the box is not checked
            is_anomaly = anomaly_check if i == 0 else (random.choice([True, False]) if anomaly_check else False)
            txs.append(generate_transaction(i+1, behavioral_anomaly=is_anomaly))

        df = pd.DataFrame(txs)
        
        st.dataframe(df[["tx_id","timestamp","amount","origin","failed_logins","device_known","behavioral_anomaly","risk_score","risk_level"]])
        
        # Plot distribution of risk scores
        fig = px.histogram(df, x="risk_score", nbins=20, title="Risk Score Distribution", color="risk_level",
                           color_discrete_map={"Low":"green", "Medium":"orange", "High":"red"})
        st.plotly_chart(fig, use_container_width=True)
        
        # Show top risky transactions
        st.subheader("Top High-Risk Transactions for Review")
        st.table(df.sort_values("risk_score", ascending=False).head(10)[["tx_id","amount","risk_score","risk_level", "behavioral_anomaly"]])


# ----------------------------
# Section: Threat Feed & SIEM
# ----------------------------
elif section == "Threat Feed & SIEM":
    st.header("Live Threat Feed (Simulated) & SIEM Dashboard")
    st.write("Generate a feed of alerts. Each alert has severity and suggested mitigation.")

    controls = st.columns([1,1,1])
    with controls[0]:
        gen_count = st.number_input("Number of alerts to generate", min_value=1, max_value=50, value=5)
    with controls[1]:
        severity_bias = st.selectbox("Bias towards severity", ["Balanced","More High", "More Low"])
    with controls[2]:
        gen_btn = st.button("Generate Alerts", type="primary")

    def gen_alert(i):
        sev_choice = random.choices(["Low","Medium","High"], weights=(5,3,1))[0]
        if severity_bias == "More High":
            sev_choice = random.choices(["Low","Medium","High"], weights=(3,3,4))[0]
        elif severity_bias == "More Low":
            sev_choice = random.choices(["Low","Medium","High"], weights=(6,3,1))[0]
        
        # **NEW FEATURE from lecture notes**
        events = ["Failed Login","Suspicious Transfer","Anomalous Login Location","Malware Detected","Unusual API Usage", "Phishing Attempt"]
        
        alert = {
            "id": f"A-{random.randint(10000,99999)}",
            "time": now(),
            "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}",
            "event": random.choice(events),
            "severity": sev_choice
        }
        
        # Suggested mitigation
        if alert["event"] == "Phishing Attempt":
            alert["severity"] = "High" # Phishing is always high
            alert["details"] = "User reported email from 'security@hdfc-support.net'"
            alert["mitigation"] = "Block domain. Scan user mailbox. Remind user to ONLY use the official 'hdfc.bank.in' domain."
        elif alert["severity"] == "High":
            alert["details"] = "High-value transfer to new beneficiary."
            alert["mitigation"] = "Block IP, force password reset, escalate to SOC"
        elif alert["severity"] == "Medium":
            alert["details"] = "Login from new city."
            alert["mitigation"] = "Require re-authentication, monitor for 1h"
        else:
            alert["details"] = "3 failed logins."
            alert["mitigation"] = "Log and monitor"
            
        return alert

    if gen_btn:
        df_alerts = pd.DataFrame([gen_alert(i) for i in range(int(gen_count))])
        
        # summary metrics
        counts = df_alerts["severity"].value_counts().reindex(["Low", "Medium", "High"]).fillna(0)
        m_col1, m_col2, m_col3 = st.columns(3)
        m_col1.metric("Total Alerts", value=len(df_alerts))
        m_col2.metric("High Severity", value=int(counts["High"]), delta_color="inverse")
        m_col3.metric("Medium Severity", value=int(counts["Medium"]), delta_color="inverse")

        # show alert list
        st.subheader("Alerts Triage Queue")
        st.dataframe(df_alerts[["id", "time", "severity", "event", "source_ip", "details", "mitigation"]])

        # mitigation simulation
        st.markdown("### Mitigation Simulation")
        for idx, row in df_alerts.iterrows():
            if row["severity"] == "High":
                st.error(f"**[{row['severity']}]** {row['event']} from {row['source_ip']} — **Suggested:** {row['mitigation']}")
                if st.button(f"🛑 Mitigate {row['id']}", key=f"mit_{idx}"):
                    st.success(f"Mitigation applied for {row['id']}: {row['mitigation']}")
            elif row["severity"] == "Medium":
                st.warning(f"**[{row['severity']}]** {row['event']} from {row['source_ip']} — **Suggested:** {row['mitigation']}")

# ----------------------------
# Section: Encryption & Digital Signature
# ----------------------------
elif section == "Encryption & Digital Signature":
    st.header("Encryption Demo (Fernet) & RSA Digital Signature Demo")
    st.write("Encrypt files/text with a symmetric key and sign messages with RSA keys.")

    st.subheader("1) Symmetric Encryption (Fernet)")
    st.markdown("Like a safe with **one key** to lock and unlock. Fast, great for encrypting data to store in a database.")
    text = st.text_area("Text to encrypt (sensitive info)", "Employee Salary: ₹80,000; PAN: ABCD1234E")
    
    if "fernet_key" not in st.session_state:
        st.session_state.fernet_key = Fernet.generate_key()
        st.session_state.fernet_token = None

    if st.button("Encrypt Text"):
        f = Fernet(st.session_state.fernet_key)
        st.session_state.fernet_token = f.encrypt(text.encode())
    
    st.code(f"Key (keep secret): {st.session_state.fernet_key.decode()}")
    
    if st.session_state.fernet_token:
        st.code(f"Encrypted (token): {st.session_state.fernet_token.decode()}")
        if st.button("Decrypt Text"):
            try:
                f = Fernet(st.session_state.fernet_key)
                dec = f.decrypt(st.session_state.fernet_token).decode()
                st.success(f"Decrypted: {dec}")
            except Exception as e:
                st.error(f"Decryption failed (e.g., wrong key): {e}")

    st.markdown("---")
    st.subheader("2) RSA Digital Signature (Asymmetric)")
    st.markdown("Like a wax seal. Uses **two keys** (Private to sign, Public to verify). Proves **Authenticity** (it's from you) and **Integrity** (it wasn't tampered with).")

    if "rsa_private" not in st.session_state:
        # generate one-time per session RSA keys
        with st.spinner("Generating 2048-bit RSA keypair..."):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            public_key = private_key.public_key()
            st.session_state.rsa_private = private_key
            st.session_state.rsa_public = public_key

    message = st.text_input("Message to sign", "Approve transfer of ₹100,000 to IN12345678")
    sign_btn = st.button("Sign Message (with Private Key)")
    
    if sign_btn:
        private_key = st.session_state.rsa_private
        signature = private_key.sign(
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA2Tungsten()
        )
        st.session_state.last_signature = signature
        st.session_state.last_message = message
        st.success("Message signed!")
        st.code(f"Signature (hex): {signature.hex()}")

    if st.button("Verify Signature (with Public Key)"):
        if "last_signature" not in st.session_state:
            st.error("No signature found. Sign first.")
        else:
            try:
                st.session_state.rsa_public.verify(
                    st.session_state.last_signature,
                    st.session_state.last_message.encode(), # Verify against the original message
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                st.success("✅ **SIGNATURE VERIFIED:** Message is authentic and untampered.")
                
                # **NEW FEATURE from lecture notes**
                st.warning("""
                ⚠️ **FUTURE THREAT (Lecture Note):**
                The RSA signature we just verified is secure today, but it can be broken by a future **Quantum Computer**. 
                Global banks are already piloting **Post-Quantum Cryptography (PQC)** to protect high-value data for the future.
                """)

            except Exception as e:
                st.error(f"❌ **VERIFICATION FAILED:** Signature is invalid or message was tampered with. {e}")

# ----------------------------
# Section: Global Branch Map
# ----------------------------
elif section == "Global Branch Map":
    st.header("Global Bank Branch Map (Interactive)")
    st.write("Branches, HQs and DR sites with risk overlay (simulated). Hover for details.")

    # demo data with risk levels
    map_data = pd.DataFrame([
        {"lat":19.0760,"lon":72.8777,"name":"Mumbai (HQ / CBS)","type":"HQ","risk":"Low","branches":120},
        {"lat":18.5204,"lon":73.8567,"name":"Pune (DR Site)","type":"DR Site","risk":"Low","branches":0},
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
    view_state = pdk.ViewState(latitude=20, longitude=30, zoom=1.7, pitch=20)
    deck = pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip=tooltip, map_style='mapbox://styles/mapbox/light-v9')
    st.pydeck_chart(deck)

# ----------------------------
# Section: Global Security Comparison
# ----------------------------
elif section == "Global Security Comparison":
    st.header("Global Security Comparison (Lecture Data)")
    st.markdown("Comparing (illustrative) adoption of next-gen security features.")

    # **UPDATED DATA from lecture notes**
    df = pd.DataFrame({
        "Feature": ["Strong 2FA (OTP/PIN)", "Next-Gen Biometrics (Behavioral/Voice)", "Post-Quantum Cryptography (PQC) Pilots", "Advanced AI Fraud Detection (UEBA)", "Breach & Attack Simulation (BAS)"],
        "Typical Indian Bank": [10, 4, 2, 6, 3],
        "Global Best Practice (e.g., JPMorgan)": [10, 8, 7, 9, 8],
    })
    
    st.markdown("### Feature Adoption Score (1-10)")
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        name='Typical Indian Bank',
        x=df["Feature"], y=df["Typical Indian Bank"],
        text=df["Typical Indian Bank"], textposition='auto'
    ))
    fig.add_trace(go.Bar(
        name='Global Best Practice',
        x=df["Feature"], y=df["Global Best Practice (e.g., JPMorgan)"],
        text=df["Global Best Practice (e.g., JPMorgan)"], textposition='auto'
    ))

    fig.update_layout(barmode='group', xaxis_tickangle=-25, height=500,
                      legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1))
    st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("""
    **Key Takeaways:**
    - **Baseline is Strong:** Indian banks are world-class at foundational security (like 2FA/OTP).
    - **Unique Strength:** India is a leader in fighting phishing with the new, mandatory **`.bank.in`** domain, a proactive step many countries have not taken.
    - **Future Frontiers:** Global leaders are investing heavily in *proactive* and *future-looking* tech:
        - **Behavioral Biometrics:** Authenticating you based on *how* you act, not just what you know.
        - **PQC:** Preparing for the quantum computing threat today.
        - **BAS:** Moving from periodic "Red Team" tests to continuous, automated 24/7 attack simulation.
    """)

# ----------------------------
# Section: Download / Docs
# ----------------------------
elif section == "Download / Docs":
    st.header("Download & Documentation")
    st.write("You can download simulated data and a short README for your presentation.")
    
    if st.button("Generate sample transactions CSV"):
        txs = [generate_transaction(i+1, random.choice([True,False])) for i in range(100)]
        df = pd.DataFrame(txs)
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download transactions.csv", csv, file_name="simulated_transactions.csv", mime="text/csv")
        
    readme_text = """
Secure Banking System Visualizer (Enhanced)
===========================================
This Streamlit app is a teaching/demo tool that simulates advanced cybersecurity concepts for a banking environment.

Modules:
- Network & DR: Simulates a Core Banking System (CBS) and WAN failover.
- RBAC & DLP: Demos Role-Based Access Control and a Data Loss Prevention (DLP) engine that blocks PII leaks.
- Risk Scoring: Simulates an AI fraud engine, including behavioral anomaly detection.
- SIEM: A mock threat feed that now detects phishing attempts and promotes the '.bank.in' mitigation.
- Encryption: Demos RSA signatures and includes a warning about the future quantum computing threat.
- Global Comparison: Benchmarks Indian vs. Global security feature adoption.

All data is simulated and intended for educational use.
    """
    st.download_button("Download README", readme_text, file_name="README.txt")
    st.markdown("**Deployment Tips:** Include `requirements.txt` in your repo. Deploy on Streamlit Cloud (share.streamlit.io).")

# ----------------------------
# End
# ----------------------------
st.sidebar.markdown("---")
st.sidebar.caption("All content simulated for lecture/demo. Not production-grade — designed for education.")
