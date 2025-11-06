import streamlit as st
import pandas as pd
import time
import random
import io
import re
import hashlib
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
st.markdown("An interactive demo of banking architecture, security layers, threat simulation, and risk management.")

# ----------------------------
# Sidebar navigation (NEW STORYLINE)
# ----------------------------
section = st.sidebar.selectbox("Navigate the Storyline", [
    "Overview",
    "🏦 Bank Architecture",
    "🔒 Security Layers",
    "🧠 Threat Simulation",
    "📊 Risk Dashboard",
    "🌎 Global Comparison",
    "🧾 Compliance & Data Privacy",
    "🚀 Future Banking Tech"
])

# ----------------------------
# Helper utilities
# ----------------------------
def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def generate_transaction(id, behavioral_anomaly=False):
    # (Existing helper function - unchanged)
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
        "device_known": random.choice([True, True, True, False]),
        "behavioral_anomaly": behavioral_anomaly
    }
    score = 0
    if tx["amount"] > 50000: score += 40
    if tx["origin"] != tx["destination"]: score += 10
    if not tx["device_known"]: score += 20
    if tx["failed_logins"] > 1: score += 15
    if tx["behavioral_anomaly"]: score += 25
    tx["risk_score"] = min(100, score + random.randint(-5,10))
    tx["risk_level"] = "Low" if tx["risk_score"] < 30 else ("Medium" if tx["risk_score"] < 60 else "High")
    return tx

# ----------------------------
# Section: Overview
# ----------------------------
if section == "Overview":
    st.header("Welcome to the Secure Banking Visualizer")
    st.markdown("""
    This application tells the story of modern cybersecurity in banking, broken down into interactive modules. 
    
    Use the sidebar to navigate through the storyline:
    - **🏦 Bank Architecture:** Understand the "nervous system" of a bank (Core Banking System) and its resilience (Disaster Recovery).
    - **🔒 Security Layers:** Explore the fundamental defenses like Access Control (RBAC), Multi-Factor Authentication (MFA), and Encryption.
    - **🧠 Threat Simulation:** Interactively launch a simulated attack (like Ransomware or Phishing) to see how it unfolds.
    - **📊 Risk Dashboard:** Become a SOC analyst. Monitor a live SIEM feed, a global attack map, and an AI-driven transaction risk engine.
    - **🌎 Global Comparison:** Benchmark Indian banks against global leaders in the adoption of advanced security technology.
    - **🧾 Compliance & Data Privacy:** See how banks protect PII (Personally Identifiable Information) using Data Loss Prevention (DLP) and Data Masking.
    - **🚀 Future Banking Tech:** Look ahead at what's next, from Quantum Cryptography to AI-powered defenses.
    """)
    st.info("All data is simulated for educational purposes. No real bank data is used.")

# ----------------------------
# Section: 🏦 Bank Architecture
# (Formerly Network & DR Simulation)
# ----------------------------
elif section == "🏦 Bank Architecture":
    st.header('The Bank\'s "Nervous System": CBS & DR')
    st.markdown("""
    This shows a simplified **Core Banking System (CBS)** architecture.
    - **Branches** connect via a private, encrypted **Wide Area Network (WAN/MPLS)**, forming a "VPN Tunnel".
    - The **Firewall** is the gatekeeper, inspecting all traffic before it reaches the central **Core Server (CBS)**.
    - The **DR Site** is a real-time, mirrored copy, ready to take over instantly if the primary fails.
    """)
    col1, col2 = st.columns([2,1])

    with col1:
        # Enhanced network graph
        nodes = [
            {"id":"Customer (Internet)","x":0,"y":0},
            {"id":"Branch_A (Mumbai)","x":2,"y":1.5},
            {"id":"Branch_B (Kolkata)","x":2,"y":-1.5},
            {"id":"Firewall / WAF","x":4,"y":0},
            {"id":"Core_Server (CBS - Mumbai)","x":6,"y":0.5},
            {"id":"Encrypted_DB","x":8,"y":0.5},
            {"id":"DR_Site (CBS - Chennai)","x":6,"y":-1.5},
        ]
        edges = [
            ("Customer (Internet)", "Firewall / WAF"),
            ("Branch_A (Mumbai)", "Firewall / WAF"),
            ("Branch_B (Kolkata)", "Firewall / WAF"),
            ("Firewall / WAF", "Core_Server (CBS - Mumbai)"),
            ("Core_Server (CBS - Mumbai)", "Encrypted_DB"),
            ("Firewall / WAF", "DR_Site (CBS - Chennai)") # DR Link
        ]
        
        fig = go.Figure()
        
        # Add edges
        for e in edges:
            a = next(n for n in nodes if n["id"]==e[0])
            b = next(n for n in nodes if n["id"]==e[1])
            line_style = dict(color="lightgray")
            label = "Encrypted TLS"
            if "Branch" in e[0]:
                line_style = dict(color="blue", dash="dot")
                label = "VPN Tunnel (AES-256)"
            if e == ("Firewall / WAF", "DR_Site (CBS - Chennai)"):
                line_style = dict(color="red", dash="dash")
                label = "Replication Link"
            
            fig.add_trace(go.Scatter(x=[a["x"], b["x"]], y=[a["y"], b["y"]],
                                     mode="lines", line=line_style, hoverinfo="text", text=label))
        # Add nodes
        node_x = [n["x"] for n in nodes]
        node_y = [n["y"] for n in nodes]
        node_text = [n["id"] for n in nodes]
        node_colors = ["lightblue","lightgreen","lightgreen","red","gold","lightgray","pink"]
        
        fig.add_trace(go.Scatter(x=node_x, y=node_y, mode="markers+text", text=node_text,
                                 marker=dict(size=35, color=node_colors, line=dict(width=2, color='Black')),
                                 textposition="top center"))
        
        fig.update_layout(title="Core Banking System (CBS) Architecture", showlegend=False, 
                          xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                          yaxis=dict(showgrid=False, zeroline=False, showticklabels=False), height=500)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Control Panel")
        failover = st.button("🔴 Simulate Core Server Outage")
        
        if 'dr_active' not in st.session_state:
            st.session_state.dr_active = False

        if failover:
            st.session_state.dr_active = True
            status_placeholder = st.empty()
            with st.spinner("Failover in progress..."):
                status_placeholder.info("Core Server status: DOWN — activating Disaster Recovery (DR) site...")
                time.sleep(1)
                status_placeholder.info("Rerouting WAN traffic to DR_Site (Chennai)...")
                time.sleep(1)
                status_placeholder.info("DR Site (Chennai) now active. Business continuity maintained.")
                time.sleep(0.5)
            status_placeholder.success("Failover complete! All traffic routed to DR Site.")
            st.balloons()
        
        if st.session_state.dr_active:
             st.success("STATUS: Traffic actively routed to DR Site.")
        else:
             st.info("STATUS: Core Server (CBS - Mumbai) is UP. DR Site (Chennai) is on standby.")
        
        st.subheader("Simulated Firewall Log")
        st.code(f"""
{now()} ALLOW 203.0.113.10 -> [Firewall] (Customer Login)
{now()} ALLOW 198.51.100.2 -> [Firewall] (Branch A VPN)
{now()} DENY  104.28.15.12  -> [Firewall] (Port Scan)
{now()} ALLOW 198.51.100.3 -> [Firewall] (Branch B VPN)
{now()} DENY  172.217.14.2 -> [Firewall] (SQL Injection)
        """)


# ----------------------------
# Section: 🔒 Security Layers
# (Formerly parts of RBAC and Encryption)
# ----------------------------
elif section == "🔒 Security Layers":
    st.header('The Bank\'s "Digital Fortress"')
    
    st.subheader("1. Access Control (Zero Trust Demo)")
    st.markdown("This demonstrates **Role-Based Access Control (RBAC)**. In a Zero Trust model, *every* action is verified, even from an employee.")
    
    # (Moved from old RBAC section)
    role = st.selectbox("Pick a role:", ["Customer", "Teller (Employee)", "Branch Manager", "Admin / Security Officer", "HR Employee"])
    action = st.selectbox("Attempt action:", [
        "View own account details",
        "View a customer's KYC (other branch)",
        "Approve high-value transfer",
        "View system audit logs",
        "View another employee's salary"
    ])

    # (RBAC Logic - unchanged)
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
        st.warning("An access denial is logged in the SIEM for review.")

    st.markdown("---")
    
    # (NEW Feature from user's list)
    st.subheader("2. Multi-Factor Authentication (MFA) Simulation")
    st.markdown("Simulating a secure login process.")

    mfa_cols = st.columns(3)
    with mfa_cols[0]:
        st.text_input("Username", "bank_manager_01")
        st.text_input("Password", "●●●●●●●●●●", type="password")
        if st.button("Login"):
            st.session_state.mfa_step = 1
        
    if 'mfa_step' in st.session_state:
        with mfa_cols[1]:
            if st.session_state.mfa_step >= 1:
                st.text_input("Enter OTP (Sent to 91+...99)", "123456")
                if st.button("Verify OTP"):
                    st.session_state.mfa_step = 2
        with mfa_cols[2]:
             if st.session_state.mfa_step == 2:
                st.success("✅ **Login Successful**")
                st.caption("Authenticated via Password + OTP")
                st.button("Logout", on_click=st.session_state.clear)

    st.markdown("---")

    # (NEW Feature from user's list - Crypto Lab)
    st.subheader("3. Cryptography Lab")
    crypto_cols = st.columns(3)
    with crypto_cols[0]:
        st.info("Hashing (One-Way)")
        st.markdown("Proves **Integrity**. Cannot be reversed. Used for storing passwords.")
        hash_input = st.text_input("Text to Hash", "MyPassword123", key="hash")
        st.code(f"SHA-256:\n{hashlib.sha256(hash_input.encode()).hexdigest()}")
        
    with crypto_cols[1]:
        st.info("Symmetric Encryption")
        st.markdown("Like a safe with **one key** to lock and unlock. Fast, for storing data.")
        # (Moved from old Encryption section)
        if "fernet_key" not in st.session_state:
            st.session_state.fernet_key = Fernet.generate_key()
        
        f = Fernet(st.session_state.fernet_key)
        token = f.encrypt(b"PAN: ABCDE1234F")
        st.code(f"Key: {st.session_state.fernet_key.decode()[:10]}...")
        st.code(f"Encrypted: {token.decode()[:20]}...")
        st.success(f"Decrypted: {f.decrypt(token).decode()}")

    with crypto_cols[2]:
        st.info("Asymmetric Encryption")
        st.markdown("Uses **two keys** (Public/Private). Proves **Authenticity**.")
        # (Moved from old Encryption section)
        if "rsa_private" not in st.session_state:
            st.session_state.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            st.session_state.rsa_public = st.session_state.rsa_private.public_key()
        
        st.code(f"Public Key: {st.session_state.rsa_public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()[:40]}...")
        st.code(f"Private Key: [KEPT SECRET]")
        st.success("Used for Digital Signatures!")


# ----------------------------
# Section: 🧠 Threat Simulation
# (NEW Section from user's list)
# ----------------------------
elif section == "🧠 Threat Simulation":
    st.header("Interactive Cyber Attack Simulation")
    st.markdown("See how common attacks unfold step-by-step. This demonstrates what the 'Risk Dashboard' is trying to detect.")

    attack_type = st.selectbox("Select an attack to simulate:", ["Phishing Attack", "Ransomware Attack"])
    
    if st.button(f"🚀 Launch Simulated {attack_type}"):
        st.subheader(f"Simulating: {attack_type}")
        
        if attack_type == "Phishing Attack":
            steps = [
                ("1. **Attack:** Attacker sends a fake 'Urgent Security Alert' email from 'security@hdfc-support.net'.", "info"),
                ("2. **Human Error:** Employee clicks the link, which leads to a fake login page.", "info"),
                ("3. **Theft:** Employee enters their username and password. Attacker steals the credentials.", "warning"),
                ("4. **Detection:** SIEM detects 'Anomalous Login Location' from attacker's IP. Account is flagged.", "error"),
                ("5. **Mitigation:** SOC team is alerted. Account is locked. Bank-wide alert sent to ignore the phishing email.", "success")
            ]
        
        elif attack_type == "Ransomware Attack":
            steps = [
                ("1. **Infection:** Employee downloads and runs a fake 'Invoice.zip' from an email.", "info"),
                ("2. **Execution:** Malware executes in memory, bypassing old antivirus.", "info"),
                ("3. **Lateral Movement:** Malware scans the network for connected file shares and databases.", "warning"),
                ("4. **Encryption:** Malware begins encrypting 'Customer_DB.bak' and 'Branch_Reports.xlsx'.", "error"),
                ("5. **Detection:** AI Anomaly Detector (UEBA) flags massive, abnormal file I/O. DLP flags encryption of PII.", "error"),
                ("6. **Mitigation:** Automated system severs the infected computer from the network. SOC team begins recovery from DR backups.", "success")
            ]
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for i, (text, level) in enumerate(steps):
            time.sleep(1.5)
            progress_bar.progress((i + 1) / len(steps))
            if level == "info":
                status_text.info(text)
            elif level == "warning":
                status_text.warning(text)
            elif level == "error":
                status_text.error(text)
            elif level == "success":
                status_text.success(text)
        
        st.success(f"{attack_type} simulation complete.")

# ----------------------------
# Section: 📊 Risk Dashboard
# (Formerly Transaction Risk & SIEM)
# ----------------------------
elif section == "📊 Risk Dashboard":
    st.header("Security Operations Center (SOC) Dashboard")
    st.markdown("This is a mock-up of a live SOC dashboard, combining a SIEM, an AI Fraud Engine, and a global threat map.")

    # (NEW Feature from user's list - Geolocation Attack Map)
    st.subheader("Live Geolocation Attack Map (Simulated)")
    st.markdown("Showing incoming threat signatures (e.g., port scans, SQLi attempts) in real-time.")
    
    # Generate random attack data
    attack_data = pd.DataFrame({
        "lat": [random.uniform(-50, 50) for _ in range(30)],
        "lon": [random.uniform(-120, 120) for _ in range(30)],
        "type": [random.choice(["SQLi", "Port Scan", "Brute Force"]) for _ in range(30)]
    })
    
    attack_layer = pdk.Layer(
        "ScatterplotLayer",
        data=attack_data,
        get_position='[lon, lat]',
        get_radius=200000,
        get_color='[255, 0, 0, 160]', # Red
        pickable=True
    )

    tooltip = {"html": "<b>Attack Signature</b><br/>Type: {type}", "style": {"color":"white"}}
    view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1, pitch=30)
    deck = pdk.Deck(layers=[attack_layer], initial_view_state=view_state, tooltip=tooltip, map_style='mapbox://styles/mapbox/dark-v9')
    st.pydeck_chart(deck)

    st.markdown("---")
    
    dash_cols = st.columns(2)
    
    with dash_cols[0]:
        # (Moved from old Transaction Risk Scoring section)
        st.subheader("AI Transaction Risk Engine")
        anomaly_check = st.checkbox("Simulate Behavioral Anomaly (e.g., unusual typing speed)")
        
        if st.button("Generate Transactions"):
            txs = []
            for i in range(20): # Generate 20 transactions
                is_anomaly = anomaly_check if i == 0 else (random.choice([True, False]) if anomaly_check else False)
                txs.append(generate_transaction(i+1, behavioral_anomaly=is_anomaly))
            
            df = pd.DataFrame(txs)
            
            # Show only high-risk ones
            st.dataframe(df[df["risk_level"] == "High"][["tx_id","amount","risk_score","behavioral_anomaly"]])
            
            # Plot distribution
            fig = px.histogram(df, x="risk_score", nbins=20, title="Risk Score Distribution", color="risk_level",
                               color_discrete_map={"Low":"green", "Medium":"orange", "High":"red"})
            st.plotly_chart(fig, use_container_width=True)

    with dash_cols[1]:
        # (Moved from old Threat Feed & SIEM section)
        st.subheader("Live SIEM Alert Feed")
        
        if st.button("Fetch New Alerts"):
            st.session_state.alerts = [gen_alert(i) for i in range(5)]
        
        if 'alerts' in st.session_state:
            for alert in st.session_state.alerts:
                if alert["severity"] == "High":
                    st.error(f"**[{alert['severity']}]** {alert['event']} from {alert['source_ip']}\n> {alert['mitigation']}")
                elif alert["severity"] == "Medium":
                    st.warning(f"**[{alert['severity']}]** {alert['event']} from {alert['source_ip']}\n> {alert['mitigation']}")
                else:
                    st.info(f"**[{alert['severity']}]** {alert['event']} from {alert['source_ip']}\n> {alert['mitigation']}")

    # (Helper function for SIEM)
    def gen_alert(i):
        events = ["Failed Login","Suspicious Transfer","Anomalous Login Location","Malware Detected","Phishing Attempt"]
        alert = {
            "id": f"A-{random.randint(10000,99999)}", "time": now(),
            "source_ip": f"{random.randint(1_223)}.{random.randint(0_255)}.{random.randint(0_255)}.{random.randint(0_255)}",
            "event": random.choice(events), "severity": random.choices(["Low","Medium","High"], weights=(5,3,2))[0]
        }
        if alert["event"] == "Phishing Attempt":
            alert["severity"] = "High"
            alert["mitigation"] = "Block domain. Remind user ONLY use official 'sbi.bank.in' domain."
        elif alert["severity"] == "High":
            alert["mitigation"] = "Block IP, force password reset, escalate to SOC"
        elif alert["severity"] == "Medium":
            alert["mitigation"] = "Require re-authentication, monitor for 1h"
        else:
            alert["mitigation"] = "Log and monitor"
        return alert

# ----------------------------
# Section: 🌎 Global Comparison
# (Formerly Global Security Comparison)
# ----------------------------
elif section == "🌎 Global Comparison":
    st.header("Global Security Posture Comparison")
    st.markdown("Comparing (illustrative) adoption of next-gen security features.")

    # (NEW, upgraded data from user's list)
    data = {
        "Feature": ["Encryption Standards", "MFA (Multi-Factor Auth)", "Cloud Infrastructure", "AI for Fraud Detection", "Zero Trust Framework", "Cybersecurity Budget (% of IT)"],
        "SBI (India)": ["AES-128, SSL", "OTP + PIN", "Partial Private Cloud", "Limited", "Partial", 7],
        "JPMorgan (US)": ["AES-256, Quantum R&D", "OTP + Biometric + Token", "Hybrid (AWS + Azure)", "Advanced ML", "Fully Implemented", 18],
        "DBS (Singapore)": ["AES-256, TLS 1.3", "Face + OTP", "Full Cloud-Native", "Deep Learning", "Fully Implemented", 18],
        "HSBC (UK)": ["AES-256, TLS 1.3", "OTP + Biometric", "Hybrid Cloud", "AI-driven AML", "In progress", 16],
    }
    df_compare = pd.DataFrame(data)
    
    st.subheader("Feature Comparison")
    st.dataframe(df_compare.set_index("Feature"))

    st.subheader("Cybersecurity Budget (% of IT spend)")
    # Prepare data for plotting (numeric only)
    plot_data = {
        "Bank": ["SBI (India)", "JPMorgan (US)", "DBS (Singapore)", "HSBC (UK)"],
        "Budget": [7, 18, 18, 16]
    }
    df_plot = pd.DataFrame(plot_data)
    
    fig = px.bar(df_plot, x="Bank", y="Budget", title="Cybersecurity Budget (% of IT Spend)",
                 color="Bank", text_auto=True)
    fig.update_layout(height=450)
    st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("""
    **Key Takeaways:**
    - **Baseline is Strong:** Indian banks are world-class at foundational security (like 2FA/OTP).
    - **Unique Strength:** India is a leader in fighting phishing with the new, mandatory **`.bank.in`** domain.
    - **Investment Gap:** Global leaders invest a significantly higher percentage of their IT budget into cybersecurity.
    - **Future Frontiers:** Global banks are more aggressively adopting Cloud-Native architecture, Zero Trust, and advanced AI, which enables faster, more scalable security.
    """)

# ----------------------------
# Section: 🧾 Compliance & Data Privacy
# (NEW Section, contains old DLP)
# ----------------------------
elif section == "🧾 Compliance & Data Privacy":
    st.header("Protecting Customer & Employee Data")
    st.markdown("How banks handle PII (Personally Identifiable Information) and comply with regulations.")

    comp_cols = st.columns(2)
    
    with comp_cols[0]:
        # (Moved from old RBAC section)
        st.subheader("1. Data Loss Prevention (DLP) Simulation")
        st.markdown("Simulate an employee trying to email sensitive data.")
        
        dlp_role = st.selectbox("Role", ["Teller (Employee)", "Branch Manager"], key="dlp_role")
        dlp_to = st.text_input("To:", "my-friend@gmail.com")
        dlp_body = st.text_area("Email Body:", "Hi, the customer's PAN is ABCDE1234F.")
        
        if st.button("Simulate Send Email"):
            is_external = "gmail.com" in dlp_to
            has_pii = "pan" in dlp_body.lower() or bool(re.search(r"[A-Z]{5}[0-9]{4}[A-Z]{1}", dlp_body))
            
            if is_external and has_pii:
                st.error("🟥 **BLOCKED: DLP Policy Violation**")
                st.write(f"**Reason:** PII (PAN Card) detected in an email to an external domain.")
                st.write(f"**Action:** Email quarantined. Alert sent to Security Officer.")
            else:
                st.success("✅ **SENT: Policy Compliant**")

    with comp_cols[1]:
        # (NEW Feature from user's list)
        st.subheader("2. Employee Data Masking")
        st.markdown("Protecting employee PII from unauthorized internal access.")
        
        # Sample employee data
        emp_data = {
            "Employee_ID": ["E1001", "E1002", "E1003"],
            "Name": ["Ramesh Kumar", "Priya Sharma", "Anil Gupta"],
            "Aadhaar": ["...9876", "...1234", "...5678"],
            "Salary_LPA": ["8.0", "12.5", "9.2"]
        }
        df_emp = pd.DataFrame(emp_data)
        
        st.markdown("**View as Teller (Masked):**")
        st.dataframe(df_emp.style.hide(subset=["Salary_LPA"], axis=1))
        
        st.markdown("**View as HR Employee (Unmasked):**")
        st.dataframe(df_emp)

    st.markdown("---")
    st.subheader("Key Regulatory Frameworks")
    st.markdown("""
    Banks don't just implement security for good practice; it's the law.
    - **RBI IT Framework (India):** Mandates strict controls on cybersecurity, data localization, and IT governance.
    - **GDPR (Europe):** Governs data protection and privacy for all individual citizens of the EU. Affects global banks.
    - **PCI DSS (Global):** Payment Card Industry Data Security Standard. Required for *any* entity that handles credit card data.
    - **ISO 27001 (Global):** The international standard for an Information Security Management System (ISMS).
    """)

# ----------------------------
# Section: 🚀 Future Banking Tech
# (NEW Section from user's list)
# ----------------------------
elif section == "🚀 Future Banking Tech":
    st.header("The Future of Banking Security")
    st.markdown("These are the next-generation technologies banks are actively researching and deploying.")
    
    st.warning("""
    ⚠️ **The Quantum Threat:**
    The RSA encryption we use today is secure because classical computers cannot factor large numbers quickly. 
    A future **Quantum Computer** *will* be able to break it, rendering most of our current encryption obsolete. 
    Banks are now in a race to become **"Quantum-Safe"**.
    """)
    
    f_cols = st.columns(3)
    
    with f_cols[0]:
        st.info("🧬 **Quantum-Safe Cryptography (PQC)**")
        st.markdown("New encryption algorithms (like CRYSTALS-Kyber) that are resistant to attacks from *both* classical and quantum computers. This is the future of data protection.")
        
    with f_cols[1]:
        st.info("🧠 **AI-Powered Behavioral Biometrics**")
        st.markdown("Moving beyond just passwords and OTPs. This technology authenticates you based on *how you act*—your typing speed, the angle you hold your phone, your mouse patterns. It can detect an imposter *even if they have your password*.")

    with f_cols[2]:
        st.info("🤖 **Autonomous Threat Hunting**")
        st.markdown("Using AI agents that don't just wait for alerts (like a SIEM), but *proactively* hunt for threats inside the network 24/7. They can find and neutralize threats *before* a human analyst even sees them.")

    with f_cols[0]:
        st.info("🪪 **Decentralized Identity (DID)**")
        st.markdown("Using blockchain, this would allow *you* to own your identity data, not the bank. You would grant the bank permission to verify specific facts (e.g., "Are you over 18?") without handing over your full ID.")

    with f_cols[1]:
        st.info("🔗 **Confidential Computing**")
        st.markdown("A new technology that encrypts data *while it is in use* (i.e., in the computer's memory/RAM). This protects data from even cloud providers or system administrators, enabling secure multi-party AI on sensitive data.")

    with f_cols[2]:
        st.info("🛡️ **Breach & Attack Simulation (BAS)**")
        st.markdown("Instead of periodic "Red Team" tests, this is an automated platform that *continuously* runs simulated attacks against the bank's live defenses 24/7 to find holes before real attackers do.")

# ----------------------------
# End
# ----------------------------
st.sidebar.markdown("---")
st.sidebar.caption("All content simulated for lecture/demo. Not production-grade — designed for education.")
