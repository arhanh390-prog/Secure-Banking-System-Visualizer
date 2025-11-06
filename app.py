import streamlit as st
import graphviz
import time
import random
from cryptography.fernet import Fernet
import pandas as pd
import pydeck as pdk

# ----------------------------
# PAGE CONFIGURATION
# ----------------------------
st.set_page_config(page_title="Secure Banking System Visualizer", layout="wide", page_icon="🏦")

st.title("🏦 Secure Banking System Visualizer")
st.markdown("""
This interactive Streamlit app demonstrates how **modern banking systems work securely** —  
from customer transactions to encrypted data storage, with global comparisons and real-time threat monitoring.
""")

# ----------------------------
# SIDEBAR NAVIGATION
# ----------------------------
menu = st.sidebar.radio(
    "🧭 Navigate through modules:",
    [
        "🏗️ Bank Network Structure",
        "🔐 Data Security Layers",
        "🧑‍💻 Role-Based Access Simulation",
        "🧩 Encryption Demo",
        "🌍 Global Security Comparison",
        "🚨 Threat Detection & Monitoring",
        "🗺️ Global Bank Branch Map"
    ]
)

# ----------------------------
# 1️⃣ BANK STRUCTURE VISUALIZATION
# ----------------------------
if menu == "🏗️ Bank Network Structure":
    st.header("🏗️ Bank Network Structure (Example: State Bank of India)")

    st.write("This diagram shows how customer data flows securely across different layers of the bank’s network.")

    graph = graphviz.Digraph()
    graph.attr(rankdir="LR", size="8,5")

    graph.node("A", "Customer", shape="ellipse", style="filled", color="lightblue")
    graph.node("B", "Bank Branch\n(Local Network)", shape="box", style="filled", color="lightgreen")
    graph.node("C", "Regional Data Center", shape="box", style="filled", color="orange")
    graph.node("D", "Core Banking Server", shape="box", style="filled", color="lightyellow")
    graph.node("E", "Encrypted Database", shape="cylinder", style="filled", color="lightgray")
    graph.node("F", "Disaster Recovery Site", shape="box", style="filled", color="pink")

    graph.edges(["AB", "BC", "CD", "DE"])
    graph.edge("C", "F", label="Backup Sync")

    st.graphviz_chart(graph)

    st.success("🔐 Each communication link uses TLS/SSL encryption and VPN tunneling to ensure secure data flow between branches.")

# ----------------------------
# 2️⃣ DATA SECURITY LAYERS
# ----------------------------
elif menu == "🔐 Data Security Layers":
    st.header("🔐 Data Security Layers in Banking Systems")

    st.markdown("""
    **Banks use multiple layers of defense to protect sensitive data:**

    - **🔒 Encryption:** AES-256 and RSA-2048 for securing data at rest and in transit.  
    - **👩‍💻 Role-Based Access Control (RBAC):** Employees only access data relevant to their roles.  
    - **🚨 Intrusion Detection Systems (IDS):** Monitors and blocks unauthorized activity.  
    - **🧾 Audit Logging:** Tracks all access attempts for accountability.  
    - **🧠 AI-driven Anomaly Detection:** Identifies suspicious transactions in real time.  
    """)

# ----------------------------
# 3️⃣ ROLE-BASED ACCESS SIMULATION
# ----------------------------
elif menu == "🧑‍💻 Role-Based Access Simulation":
    st.header("🧑‍💻 Role-Based Access Simulation")

    role = st.selectbox("Select a user role:", ["Customer", "Employee", "Admin"])

    if role == "Customer":
        st.info("🧍 Customer can view account balance, transfer funds, or download statements.")
        st.code("Allowed Access: Account info, transactions, e-statements")
    elif role == "Employee":
        st.warning("👩‍💼 Employee can access customer info relevant to their branch only.")
        st.code("Allowed Access: Customer KYC data (branch only), transaction processing")
    elif role == "Admin":
        st.success("👨‍💻 Admin can access system logs, server monitoring, and encryption settings.")
        st.code("Allowed Access: All system data (monitored via audit logs)")

    st.markdown("🔐 **Access is controlled by RBAC (Role-Based Access Control)** to prevent unauthorized viewing of sensitive data.")

# ----------------------------
# 4️⃣ ENCRYPTION DEMO
# ----------------------------
elif menu == "🧩 Encryption Demo":
    st.header("🧩 Encryption and Decryption Demo")

    st.write("This simulates how banks encrypt sensitive information (e.g., employee data, customer PINs).")

    message = st.text_input("Enter confidential data to encrypt:", "Employee Salary = ₹80,000")

    if st.button("🔐 Encrypt Data"):
        key = Fernet.generate_key()
        cipher = Fernet(key)
        encrypted = cipher.encrypt(message.encode())
        st.text_area("Encrypted Output:", encrypted.decode(), height=100)

        if st.button("🔓 Decrypt Data"):
            decrypted = cipher.decrypt(encrypted).decode()
            st.text_area("Decrypted Output:", decrypted, height=100)
            st.success("✅ Successfully decrypted the original message!")

# ----------------------------
# 5️⃣ GLOBAL SECURITY COMPARISON
# ----------------------------
elif menu == "🌍 Global Security Comparison":
    st.header("🌍 Indian vs International Banking Security Comparison")

    df = pd.DataFrame({
        "Feature": [
            "AI Fraud Detection",
            "Zero-Trust Model",
            "Quantum Encryption",
            "Automated Cloud Audits",
            "Biometric Authentication"
        ],
        "JPMorgan (USA)": ["✅ Advanced", "✅ Fully Implemented", "🧪 Testing", "✅ Continuous", "✅ Face & Voice"],
        "SBI (India)": ["🟡 Basic", "🟡 Partial", "❌ Not Yet", "🟡 Manual", "🟡 Fingerprint Only"]
    })

    st.table(df)

    st.info("💡 Global banks are ahead in automation, AI-based monitoring, and zero-trust models — areas Indian banks are steadily adopting.")

# ----------------------------
# 6️⃣ THREAT DETECTION & MONITORING
# ----------------------------
elif menu == "🚨 Threat Detection & Monitoring":
    st.header("🚨 Real-Time Threat Detection & Monitoring")

    st.write("""
    Banks monitor millions of transactions per day.  
    AI systems flag suspicious behavior such as:
    - Unusual login locations  
    - Sudden high-value transfers  
    - Multiple failed password attempts  
    """)

    progress = st.progress(0)
    for i in range(100):
        time.sleep(0.02)
        progress.progress(i + 1)
    st.success("✅ Threat scan complete – no anomalies detected.")

    st.image("https://upload.wikimedia.org/wikipedia/commons/3/3a/Cyber_Security_Traffic_Analysis.png", 
             caption="AI-driven Security Monitoring Dashboard", use_container_width=True)

# ----------------------------
# 7️⃣ GLOBAL BRANCH MAP
# ----------------------------
elif menu == "🗺️ Global Bank Branch Map":
    st.header("🗺️ Global Bank Network Map (Demo Data)")

    data = pd.DataFrame({
        "lat": [19.0760, 28.6139, 40.7128, 51.5074],
        "lon": [72.8777, 77.2090, -74.0060, -0.1278],
        "city": ["Mumbai (India HQ)", "Delhi Branch", "New York (JPMorgan)", "London (HSBC)"]
    })

    st.pydeck_chart(pdk.Deck(
        map_style="mapbox://styles/mapbox/light-v9",
        initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1.5, pitch=30),
        layers=[
            pdk.Layer(
                "ScatterplotLayer",
                data=data,
                get_position=["lon", "lat"],
                get_color="[200, 30, 0, 160]",
                get_radius=800000,
            ),
        ],
    ))

    st.write("🔹 This shows how banks operate global branch networks, interconnected through secure VPNs and encrypted cloud infrastructure.")

# ----------------------------
# END OF APP
# ----------------------------
st.markdown("---")
st.caption("Developed for Cybersecurity Lecture — Demonstrating Secure Banking Architecture using Streamlit 💻")
