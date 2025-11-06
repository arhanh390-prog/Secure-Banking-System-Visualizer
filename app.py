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
import hashlib

# ----------------------------
# Page Config
# ----------------------------
st.set_page_config(page_title="Secure Banking Visualizer", layout="wide", page_icon="🏦")

# ----------------------------
# Helper Functions
# ----------------------------
def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

# (Helper function for SIEM)
def gen_alert(i):
    events = ["Failed Login","Suspicious Transfer","Anomalous Login Location","Malware Detected","Phishing Attempt"]
    alert = {
        "id": f"A-{random.randint(10000,99999)}", "time": now(),
        "source_ip": f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}",
        "event": random.choice(events), "severity": random.choices(["Low","Medium","High"], weights=(5,3,2))[0]
    }
    if alert["event"] == "Phishing Attempt":
        alert["mitigation"] = "Block domain. Remind user to ONLY use the official 'bank.in' domain."
    elif alert["severity"] == "High":
        alert["mitigation"] = "Block IP, force password reset, escalate to SOC"
    elif alert["severity"] == "Medium":
        alert["mitigation"] = "Require re-authentication, monitor for 1h"
    else:
        alert["mitigation"] = "Log and monitor"
    return alert

# (Helper function for Risk Scoring)
def generate_transaction(id, anomaly=False):
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
        "device_known": random.choice([True, True, True, False])
    }
    # Risk score heuristic
    score = 0
    if tx["amount"] > 50000: score += 40
    if tx["origin"] != "Mumbai": score += 10 # Assuming Mumbai is home base
    if not tx["device_known"]: score += 20
    if tx["failed_logins"] > 1: score += 15
    if anomaly: score += 25 # Behavioral anomaly bonus risk
    
    tx["risk_score"] = min(100, score + random.randint(-5,10))
    tx["risk_level"] = "Low" if tx["risk_score"] < 30 else ("Medium" if tx["risk_score"] < 60 else "High")
    
    if anomaly:
        tx["risk_level"] = f"High (Anomaly Detected)"
    return tx

# ----------------------------
# Main App Title
# ----------------------------
st.title("🏦 Secure Banking System Visualizer")
st.markdown("An interactive lecture demo for cybersecurity concepts in banking.")

# ----------------------------
# Sidebar Navigation (New Storyline)
# ----------------------------
st.sidebar.title("Lecture Modules")
section = st.sidebar.radio("Navigate the Storyline:", [
    "🏦 1. Bank Architecture",
    "🔒 2. Security Layers",
    "🧠 3. Threat Simulation",
    "📊 4. Risk Dashboard (SOC)",
    "🌎 5. Global Comparison",
    "🧾 6. Compliance & Data Privacy",
    "🚀 7. Future Banking Tech"
])
st.sidebar.markdown("---")
st.sidebar.info("All data is simulated for educational purposes.")


# ======================================================================================
# MODULE 1: BANK ARCHITECTURE
# ======================================================================================
if section == "🏦 1. Bank Architecture":
    st.header('The Bank\'s "Nervous System": CBS & DR')
    st.markdown("""
    This simulates the bank's core IT infrastructure. In India, banks run on a **Core Banking System (CBS)**, a central data center. 
    Branches are just secure "windows" into this central brain, connected via private, encrypted networks (not the public internet).
    """)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Network Topology (Simplified)")
        # Create a network graph using Plotly
        nodes = [
            {"id":"Customer (Web/Mobile)","x":0,"y":0},
            {"id":"Branch A (Mumbai)","x":1,"y":1},
            {"id":"Branch B (Delhi)","x":1,"y":-1},
            {"id":"Primary DC (Mumbai)","x":3,"y":0, "color": "green"},
            {"id":"Core Banking System (CBS)","x":5,"y":0, "color": "green"},
            {"id":"Encrypted Database","x":7,"y":0, "color": "green"},
            {"id":"DR Site (Chennai)","x":3,"y":-2, "color": "orange"},
        ]
        edges = [
            ("Customer (Web/Mobile)","Primary DC (Mumbai)"),
            ("Branch A (Mumbai)","Primary DC (Mumbai)"),
            ("Branch B (Delhi)","Primary DC (Mumbai)"),
            ("Primary DC (Mumbai)","Core Banking System (CBS)"),
            ("Core Banking System (CBS)","Encrypted Database"),
            # DR Links (dashed)
            ("Branch A (Mumbai)","DR Site (Chennai)"),
            ("Branch B (Delhi)","DR Site (Chennai)"),
            ("Customer (Web/Mobile)","DR Site (Chennai)"),
        ]
        
        fig = go.Figure()
        
        # Add edges
        for e in edges:
            n1 = next(n for n in nodes if n["id"] == e[0])
            n2 = next(n for n in nodes if n["id"] == e[1])
            style = dict(color="lightgray")
            if e[1] == "DR Site (Chennai)":
                style = dict(color="orange", dash="dot")
            fig.add_trace(go.Scatter(x=[n1["x"], n2["x"]], y=[n1["y"], n2["y"]],
                                     mode="lines", line=style, hoverinfo="none"))

        # Add nodes
        fig.add_trace(go.Scatter(
            x=[n["x"] for n in nodes], 
            y=[n["y"] for n in nodes],
            text=[n["id"] for n in nodes],
            mode="markers+text",
            textposition="top center",
            marker=dict(
                size=30, 
                color=[n.get("color", "lightblue") for n in nodes],
                line=dict(width=2, color='DarkSlateGrey')
            ),
            hovertext=[n["id"] for n in nodes],
            hoverinfo="text"
        ))
        
        fig.update_layout(
            showlegend=False,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=450,
            title="Simplified CBS Network"
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Disaster Recovery (DR) Simulation")
        st.write("Simulate a primary data center outage. All traffic must failover to the DR site.")
        
        failover = st.button("🔴 Simulate Primary DC Outage")
        
        if failover:
            status = st.empty()
            status.error("CRITICAL: Primary DC (Mumbai) is DOWN!")
            time.sleep(1)
            status.warning("FAILOVER INITIATED: Rerouting all traffic to DR Site (Chennai)...")
            
            # Redraw graph with DR active
            nodes[3]["color"] = "red" # Primary DC
            nodes[6]["color"] = "green" # DR Site
            fig.data[1].marker.color = [n.get("color", "lightblue") for n in nodes]
            
            with col1:
                st.plotly_chart(fig, use_container_width=True)

            for i in range(4):
                status.warning(f"Rerouting... (Step {i+1}/4)")
                time.sleep(0.5)
            
            status.success("✅ FAILOVER COMPLETE. Bank is 100% operational on DR Site (Chennai).")
            st.balloons()
        else:
            st.info("System Status: ✅ All systems normal. Primary DC (Mumbai) is active.")

# ======================================================================================
# MODULE 2: SECURITY LAYERS
# ======================================================================================
elif section == "🔒 2. Security Layers":
    st.header('The Bank\'s "Digital Fortress"')
    st.markdown("A bank is protected by multiple layers of security. If one fails, another catches the attacker.")
    
    tab1, tab2, tab3 = st.tabs(["🔐 MFA Simulation", "🛡️ RBAC (Access Control)", "🔑 Cryptography Lab"])

    with tab1:
        st.subheader("Multi-Factor Authentication (MFA) Simulation")
        st.write("Simulate a secure login process. All three factors must be valid.")
        
        st.text_input("Username", "bank_manager_01")
        st.text_input("Password", "●●●●●●●●●●●●", type="password")
        st.text_input("Enter 6-digit OTP", "123456")
        
        st.image("https://placehold.co/300x150/f0f0f0/000000?text=Simulated+Fingerprint+Scan\n(Biometric+Factor)", 
                 caption="Biometric data is simulated as 'scanned'.")

        if st.button("Attempt Login"):
            with st.spinner("Verifying all factors..."):
                time.sleep(1)
                st.success("✅ Access Granted! (Password + OTP + Biometric Verified)")

    with tab2:
        st.subheader("Role-Based Access Control (RBAC)")
        st.write("Demonstrates the **Principle of Least Privilege**. Users can *only* access what their role requires.")
        
        role = st.selectbox("Pick a role:", ["Customer", "Teller (Employee)", "Branch Manager", "Admin / Security Officer", "HR Employee"])
        action = st.selectbox("Attempt action:", [
            "View own account details",
            "Approve high-value transfer (₹50,00,000)",
            "View customer KYC (Other Branch)",
            "View system audit logs",
            "View employee salary records"
        ])
        
        st.markdown("---")
        
        # RBAC Logic
        allowed = False
        reason = ""
        
        if role == "Customer":
            if action == "View own account details": allowed = True
            else: reason = "Customers can only view their own data."
        
        elif role == "Teller (Employee)":
            if action == "View own account details": allowed = True
            elif action == "Approve high-value transfer (₹50,00,000)": reason = "Tellers cannot approve high-value transfers. Requires Manager."
            elif action == "View customer KYC (Other Branch)": reason = "Tellers are restricted to their own branch's customers."
            else: reason = "Tellers cannot access system logs or HR records."

        elif role == "Branch Manager":
            if action in ["View own account details", "Approve high-value transfer (₹50,00,000)", "View customer KYC (Other Branch)"]: allowed = True
            else: reason = "Managers cannot access system-wide logs or HR records."

        elif role == "Admin / Security Officer":
            if action == "View system audit logs": allowed = True
            else: reason = "Admins can see logs, but are blocked from customer/HR data (Separation of Duties)."
            
        elif role == "HR Employee":
            if action == "View employee salary records": allowed = True
            else: reason = "HR can see employee data, but not customer data or system logs (Separation of Duties)."

        if allowed:
            st.success(f"✔️ Access GRANTED for `{role}` to `{action}`.")
        else:
            st.error(f"❌ Access DENIED for `{role}`. Reason: {reason}")
            st.warning("This 'Access DENIED' event is logged and sent to the SIEM for review.")

    with tab3:
        st.subheader("Cryptography Lab: Hashing vs. Encryption")
        st.write("Compare the three core cryptographic functions.")
        
        user_text = st.text_input("Enter text to transform:", "MyS3cretP@ssw0rd")
        
        if user_text:
            col1, col2 = st.columns(2)
            with col1:
                st.info("Hashing (e.g., SHA-256)")
                st.write("**Purpose:** Verify integrity (prove data hasn't changed).")
                st.write("**Key Feature:** It's a one-way street. You CANNOT un-hash it.")
                
                hash_val = hashlib.sha256(user_text.encode()).hexdigest()
                st.code(hash_val, language=None)
                st.caption("Used to store passwords. We store the hash, not the password.")

            with col2:
                st.success("Symmetric Encryption (e.g., Fernet)")
                st.write("**Purpose:** Keep data confidential (hide data).")
                st.write("**Key Feature:** Uses *one* secret key to encrypt and decrypt.")

                key = Fernet.generate_key()
                f = Fernet(key)
                token = f.encrypt(user_text.encode())
                
                st.code(f"Secret Key: {key.decode()}", language=None)
                st.code(f"Encrypted: {token.decode()}", language=None)
                st.caption("Used for data-at-rest (files in a database).")
                
            st.markdown("---")
            st.subheader("Asymmetric Encryption (e.g., RSA Digital Signature)")
            st.write("**Purpose:** Prove authenticity and non-repudiation (prove *who* sent it).")
            st.write("**Key Feature:** Uses *two* keys: a **Private Key** (to sign) and a **Public Key** (to verify).")
            
            with st.spinner("Generating RSA 2048-bit keypair..."):
                if "rsa_private" not in st.session_state:
                    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                    st.session_state.rsa_private = private_key
                    st.session_state.rsa_public = private_key.public_key()
            
            st.code("RSA Keypair generated and stored in session.", language=None)
            
            if st.button("Sign and Verify Message"):
                message = f"I approve this transaction: {user_text}".encode()
                private_key = st.session_state.rsa_private
                public_key = st.session_state.rsa_public

                # Sign
                signature = private_key.sign(
                    message,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
                st.success("Message Signed with PRIVATE Key.")
                
                # Verify
                try:
                    public_key.verify(
                        signature,
                        message,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )
                    st.success("✅ Signature Verified with PUBLIC Key. The message is authentic.")
                    st.warning("⚠️ **Future Threat:** This RSA signature is secure today, but can be broken by a Quantum Computer. Banks are now piloting Post-Quantum Cryptography (PQC).")
                except Exception as e:
                    st.error(f"Verification FAILED: {e}")

# ======================================================================================
# MODULE 3: THREAT SIMULATION
# ======================================================================================
elif section == "🧠 3. Threat Simulation":
    st.header("Interactive Cyber Attack Simulation")
    st.write("Simulate common attacks to see how they work and how banks respond.")

    attack_type = st.selectbox("Choose Attack Scenario:", ["Ransomware Attack", "Phishing & Credential Theft"])

    if "simulation_log" not in st.session_state:
        st.session_state.simulation_log = []

    if st.button(f"🚀 Simulate {attack_type}"):
        st.session_state.simulation_log = []
        log_placeholder = st.empty()
        
        if attack_type == "Ransomware Attack":
            steps = [
                (st.info, "1. INFECTION: Employee opens a malicious email attachment (e.g., 'UrgentInvoice.zip')."),
                (st.info, "2. EXECUTION: Malware runs silently in the background."),
                (st.info, "3. NETWORK SPREAD: Malware uses vulnerability to spread to other workstations and servers."),
                (st.warning, "4. ENCRYPTION: Malware begins encrypting critical files on a file server..."),
                (st.error, "5. RANSOM NOTE: Files are now locked! A ransom note 'Files Encrypted.pay 50 Bitcoin.txt' is found."),
                (st.success, "6. RESPONSE (Automated): SIEM detects rapid file encryption!"),
                (st.success, "7. RESPONSE (Containment): Infected machines are automatically isolated from the network."),
                (st.success, "8. RESPONSE (Recovery): Files are restored from secure, off-site backups. No ransom paid.")
            ]
        
        else: # Phishing
            steps = [
                (st.info, "1. INBOUND: Attacker sends a fake email from 'alerts@hdfc-support.net' to an employee."),
                (st.info, "2. BAIT: Email says 'Your account is locked. Please verify your identity' with a link."),
                (st.info, "3. FAKE SITE: Employee clicks link, goes to a fake login page that *looks* real."),
                (st.warning, "4. THEFT: Employee enters their username and password. Attacker steals credentials!"),
                (st.error, "5. BREACH: Attacker now has a valid login. Tries to access internal systems..."),
                (st.success, "6. RESPONSE (MFA): Attacker's login attempt triggers an MFA prompt (OTP/Biometric)."),
                (st.success, "7. RESPONSE (Block): Attacker doesn't have the 2nd factor. Login fails."),
                (st.success, "8. RESPONSE (SOC): Employee reports phishing. SOC team blocks the domain and alerts all staff to use the real 'hdfc.bank.in' domain.")
            ]
        
        current_log = []
        for func, text in steps:
            time.sleep(1.2)
            current_log.append((func, text))
            log_placeholder.empty() # Clear previous
            with log_placeholder.container():
                for f, t in current_log:
                    f(t) # Redraw all previous logs
            st.session_state.simulation_log = current_log # Save state
            
    # Always display the log from session state, so it persists
    if st.session_state.simulation_log:
        st.markdown("--- \n **Simulation Log:**")
        for func, text in st.session_state.simulation_log:
            func(text)

# ======================================================================================
# MODULE 4: RISK DASHBOARD (SOC)
# ======================================================================================
elif section == "📊 4. Risk Dashboard (SOC)":
    st.header("Security Operations Center (SOC) Dashboard")
    st.write("A simulated view of what a security analyst sees: live transactions, alerts, and threat maps.")

    tab1, tab2, tab3 = st.tabs(["📈 Transaction Risk Scoring", "🚨 Live SIEM Alert Feed", "🗺️ Geolocation Attack Map"])
    
    with tab1:
        st.subheader("Live Transaction Risk Scoring")
        behavior_anomaly = st.checkbox("Simulate Behavioral Anomaly (e.g., unusual typing speed)")
        
        num_tx = st.slider("Number of transactions to simulate", 5, 50, 10)
        
        if st.button("Generate Transactions"):
            txs = [generate_transaction(i+1, anomaly=behavior_anomaly) for i in range(num_tx)]
            df_tx = pd.DataFrame(txs)
            
            st.dataframe(df_tx[["tx_id","amount","origin","destination","risk_score","risk_level"]])
            
            if behavior_anomaly:
                st.warning("Behavioral anomaly detected! Risk scores for new transactions were increased.")

            # Plot distribution of risk scores
            fig = px.histogram(df_tx, x="risk_score", nbins=10, title="Risk Score Distribution", color="risk_level",
                               color_discrete_map={"Low":"green", "Medium":"orange", "High":"red"})
            st.plotly_chart(fig, use_container_width=True)

    with tab2:
        st.subheader("Live SIEM Alert Feed")
        if st.button("Refresh Alert Feed"):
            alerts = [gen_alert(i) for i in range(10)]
            df_alerts = pd.DataFrame(alerts)
            
            # Color-code the table
            def color_severity(val):
                color = 'green' if val == 'Low' else ('orange' if val == 'Medium' else 'red')
                return f'color: {color}; font-weight: bold;'
            
            st.dataframe(df_alerts.style.applymap(color_severity, subset=['severity']))
            
            st.subheader("Mitigation Actions")
            for _, row in df_alerts[df_alerts["severity"] == "High"].iterrows():
                st.error(f"**High Alert {row['id']}**: {row['event']} from {row['source_ip']}")
                if st.button(f"Mitigate {row['id']}", key=row['id']):
                    st.success(f"Actioned: {row['mitigation']}")

    with tab3:
        st.subheader("Geolocation Attack Map")
        st.write("Simulated live attack origins (e.g., brute-force login attempts).")
        
        # Simulated attack data
        attack_data = pd.DataFrame({
            "lat": [34.0522, 51.5074, 55.7558, 35.6895, 39.9042, 19.0760, -33.8688],
            "lon": [-118.2437, -0.1278, 37.6173, 139.6917, 116.4074, 72.8777, 151.2093],
            "name": ["Los Angeles", "London", "Moscow", "Tokyo", "Beijing", "Mumbai", "Sydney"],
            "attacks": [random.randint(5, 50) for _ in range(7)]
        })

        layer = pdk.Layer(
            "ScatterplotLayer",
            data=attack_data,
            get_position='[lon, lat]',
            get_radius='attacks * 10000',
            get_color='[255, 0, 0, 160]', # Red
            pickable=True
        )

        tooltip = {"html": "<b>{name}</b><br/>Detected Attacks: {attacks}", "style": {"color":"white"}}
        view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1.5, pitch=50)
        
        deck = pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip=tooltip, map_style='mapbox://styles/mapbox/dark-v9')
        st.pydeck_chart(deck)

# ======================================================================================
# MODULE 5: GLOBAL COMPARISON
# ======================================================================================
elif section == "🌎 5. Global Comparison":
    st.header("Global Security Benchmarking")
    st.write("How Indian banks stack up against global leaders. (Data is illustrative for lecture).")

    # New detailed data from lecture notes
    data = {
        "Feature": [
            "AI for Fraud Detection", "Multi-Factor Auth (MFA)", "Zero Trust Framework",
            "Encryption Standards", "Cloud Infrastructure", "Threat Intelligence",
            "Data Backup & DR Sites", "Cybersecurity Budget (% of IT)"
        ],
        "SBI (India)": [5, 6, 4, 7, 3, 5, 7, 7],
        "JPMorgan (US)": [9, 9, 9, 9, 8, 9, 9, 18],
        "DBS (Singapore)": [8, 8, 9, 8, 9, 8, 8, 18],
        "HSBC (UK)": [8, 8, 7, 8, 7, 9, 8, 16]
    }
    df_comp = pd.DataFrame(data)
    
    st.markdown("### Feature Adoption Score (1-10, except Budget)")
    st.dataframe(df_comp)
    
    st.markdown("### Comparison Chart")
    
    # Melt dataframe for Plotly
    df_melted = df_comp.melt(id_vars='Feature', var_name='Bank', value_name='Score')
    
    fig = px.bar(
        df_melted, 
        x="Feature", 
        y="Score", 
        color="Bank", 
        barmode="group",
        title="Global Security Capability Comparison"
    )
    fig.update_layout(xaxis_tickangle=-45, height=500)
    st.plotly_chart(fig, use_container_width=True)
    
    st.info("""
    **Key Takeaway:** While Indian banks have strong fundamentals (like DR and MFA), global leaders are investing more heavily in
    AI-driven threat detection, Zero Trust, and are already piloting next-gen tech like Quantum-Safe Encryption.
    """)

# ======================================================================================
# MODULE 6: COMPLIANCE & DATA PRIVACY
# ======================================================================================
elif section == "🧾 6. Compliance & Data Privacy":
    st.header("Compliance & Data Privacy Controls")
    st.write("How banks protect sensitive PII (Personally Identifiable Information) and comply with regulations (e.g., RBI IT Framework, DPDP Act).")

    tab1, tab2 = st.tabs(["🕵️ Data Loss Prevention (DLP) Demo", "🎭 Data Masking Demo"])

    with tab1:
        st.subheader("Data Loss Prevention (DLP) Simulation")
        st.write("DLP systems scan outbound data to prevent leaks. Simulate an employee trying to email sensitive data.")
        
        email_to = st.text_input("To:", "my-personal-email@gmail.com")
        email_body = st.text_area("Email Body:", "Here is the customer list you asked for.\n\nCustomer: Rohan Sharma, PAN: ABCDE1234F\nCustomer: Priya Singh, PAN: GHIJK5678L")
        
        if st.button("Attempt to Send Email"):
            if "gmail.com" in email_to and "PAN:" in email_body:
                st.error("❌ **BLOCKED (DLP POLICY VIOLATION)**")
                st.error("Reason: Detected PII (PAN Card) being sent to an external domain. This incident has been logged and reported to Security.")
            else:
                st.success("✅ Email Sent. (No sensitive data detected).")

    with tab2:
        st.subheader("Data Masking for Employee Privacy")
        st.write("Bank employees (e.g., in a call center) should not see full PII. Data is 'masked' in their applications.")
        
        # Sample raw data (what's in the secure DB)
        raw_data = {
            "CustomerID": ["CUST-1001", "CUST-1002", "CUST-1003"],
            "Full Name": ["Rohan Varma", "Priya Singh", "Amit Patel"],
            "Mobile": ["+919876543210", "+919123456789", "+919988776655"],
            "Aadhaar": ["1234 5678 9012", "9876 5432 1098", "5678 1234 9012"],
            "Balance (INR)": [150200, 75000, 320000]
        }
        df_raw = pd.DataFrame(raw_data)
        
        st.markdown("#### 1. Raw Data (In Secure Database)")
        st.dataframe(df_raw)
        
        # Masked data (what the call center agent sees)
        df_masked = df_raw.copy()
        df_masked["Mobile"] = df_masked["Mobile"].apply(lambda x: "******" + x[-4:])
        df_masked["Aadhaar"] = df_masked["Aadhaar"].apply(lambda x: "XXXX XXXX " + x[-4:])
        
        st.markdown("#### 2. Masked Data (View for Call Center Agent)")
        st.info("Note: Mobile and Aadhaar numbers are masked to protect customer PII.")
        st.dataframe(df_masked, column_config={
            "Balance (INR)": None # This column is hidden from the agent view
        })


# ======================================================================================
# MODULE 7: FUTURE BANKING TECH
# ======================================================================================
elif section == "🚀 7. Future Banking Tech":
    st.header("The Future of Banking Security")
    st.write("A look at the next-generation technologies banks are actively researching and deploying.")

    st.subheader("1. Quantum-Safe Cryptography (PQC)")
    st.markdown("""
    - **The Threat:** A future Quantum Computer will be able to break today's encryption (like RSA, used for signatures).
    - **The Solution (PQC):** A new generation of math problems that are secure *even* against quantum computers.
    - **Status:** Global banks (JPMorgan, HSBC) are already piloting PQC to protect high-value transactions and internal data. This is moving from sci-fi to reality.
    """)

    st.subheader("2. AI-Powered Behavioral Biometrics")
    st.markdown("""
    - **Today's Biometrics:** What you *are* (fingerprint, face).
    - **Future Biometrics:** How you *behave*.
    - **The Concept:** The bank's AI builds a profile of your unique digital "fingerprint":
        - How fast you type your password.
        - The angle you hold your phone.
        - The way you move your mouse.
    - **Status:** If an attacker steals your password, they can't mimic your *behavior*. The AI will detect the anomaly and block the login. This provides *continuous authentication* instead of a single login check.
    """)

    st.subheader("3. Decentralized Identity (DID)")
    st.markdown(
        """
        - **The Problem:** You have to give your sensitive data (Aadhaar, PAN) to every bank, app, and website, creating many points of failure.
        - **The Solution (DID):** Using blockchain, this would allow *you* to own your identity data, not the bank. You would grant the bank permission to verify specific facts (e.g., "Are you over 18?") without handing over your full ID.
        - **Status:** Early research phase, but has huge implications for privacy and security.
        """
    )
    
    st.subheader("4. Breach & Attack Simulation (BAS)")
    st.markdown(
        """
        - **The Problem:** "Red Team" tests are periodic (e.g., once a quarter). Attackers work 24/7.
        - **The Solution (BAS):** An automated platform that *continuously* runs simulated attacks against the bank's live defenses 24/7 to find holes before real attackers do.
        - **Status:** Being adopted by large, mature security organizations to replace/augment traditional penetration testing.
        """
    )


st.caption("All content simulated for lecture/demo. Not production-grade — designed for education.")
