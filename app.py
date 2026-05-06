import streamlit as st
import sqlite3
import pandas as pd
import time
import secrets
import hashlib
import hmac
import base64
from datetime import datetime

DB_NAME = "p2p_auth.db"

st.set_page_config(
    page_title="Secure P2P Authentication",
    page_icon="🔐",
    layout="wide"
)

st.markdown("""
<style>
.stButton>button {
    background-color: #22a447;
    color: white;
    border-radius: 10px;
    padding: 0.6rem 1rem;
    font-weight: 600;
}
.main-card {
    background-color: #f7f9fc;
    padding: 20px;
    border-radius: 16px;
    border: 1px solid #e5e7eb;
}
</style>
""", unsafe_allow_html=True)


# ---------------- DATABASE ----------------

def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)


def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS peers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer_name TEXT UNIQUE,
        public_key TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer_name TEXT,
        phase TEXT,
        status TEXT,
        details TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()


def add_peer(peer_name, public_key):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO peers (peer_name, public_key, created_at)
    VALUES (?, ?, ?)
    """, (peer_name, public_key, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()


def get_peer(peer_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM peers WHERE peer_name=?", (peer_name,))
    result = cur.fetchone()
    conn.close()
    return result[0] if result else None


def get_all_peers():
    conn = get_connection()
    df = pd.read_sql_query(
        "SELECT id, peer_name, created_at FROM peers ORDER BY id DESC",
        conn
    )
    conn.close()
    return df


def add_log(peer_name, phase, status, details):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO logs (peer_name, phase, status, details, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """, (
        peer_name,
        phase,
        status,
        details,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def get_logs():
    conn = get_connection()
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
    conn.close()
    return df


# ---------------- SECURITY FUNCTIONS ----------------

def generate_private_key():
    return secrets.token_urlsafe(48)


def generate_public_key(private_key):
    return hashlib.sha256(private_key.encode()).hexdigest()


def sign_message(private_key, message):
    return hmac.new(
        private_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_identity(private_key, stored_public_key):
    generated_public_key = generate_public_key(private_key)
    return hmac.compare_digest(generated_public_key, stored_public_key)


def generate_session_key():
    return secrets.token_urlsafe(32)


def xor_encrypt_decrypt(data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    data_bytes = data.encode()

    output = bytearray()
    for i, b in enumerate(data_bytes):
        output.append(b ^ key_bytes[i % len(key_bytes)])

    return base64.b64encode(output).decode()


def xor_decrypt(encrypted_data, key):
    key_bytes = hashlib.sha256(key.encode()).digest()
    encrypted_bytes = base64.b64decode(encrypted_data.encode())

    output = bytearray()
    for i, b in enumerate(encrypted_bytes):
        output.append(b ^ key_bytes[i % len(key_bytes)])

    return output.decode()


def generate_mac(key, message):
    return hmac.new(
        key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_mac(key, message, mac_value):
    expected_mac = generate_mac(key, message)
    return hmac.compare_digest(expected_mac, mac_value)


# ---------------- INIT ----------------

create_tables()

if "verified_peer" not in st.session_state:
    st.session_state.verified_peer = None

if "session_key" not in st.session_state:
    st.session_state.session_key = None

if "phase3_complete" not in st.session_state:
    st.session_state.phase3_complete = False

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "current_peer" not in st.session_state:
    st.session_state.current_peer = None


# ---------------- SIDEBAR ----------------

st.sidebar.title("🔐 P2P Security")

menu = st.sidebar.radio(
    "Menu",
    [
        "Dashboard",
        "Register Peer",
        "Phase 1: Identity Verification",
        "Phase 2: Session Key",
        "Phase 3: Secure Transfer",
        "Secure Login",
        "Application Dashboard",
        "Attack Simulation",
        "Authentication Logs",
        "Logout"
    ]
)

st.sidebar.markdown("---")

if st.session_state.logged_in:
    st.sidebar.success(f"Logged in as: {st.session_state.current_peer}")
else:
    st.sidebar.warning("Not logged in")


# ---------------- HEADER ----------------

st.title("🔐 Secure Three-Phase P2P Authentication System")
st.caption("Python + Streamlit + SQLite + Hashing + HMAC + Session Key + Secure Login")
st.markdown("---")


# ---------------- DASHBOARD ----------------

if menu == "Dashboard":
    st.header("System Dashboard")

    peers = get_all_peers()
    logs = get_logs()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Registered Peers", len(peers))
    c2.metric("Total Events", len(logs))
    c3.metric("Logged In", "Yes" if st.session_state.logged_in else "No")
    c4.metric("Current Peer", st.session_state.current_peer or "None")

    st.subheader("Authentication Flow")
    st.info("""
    Register Peer → Phase 1 Identity Verification → Phase 2 Session Key →
    Phase 3 Secure Transfer → Secure Login → Application Dashboard
    """)

    if not peers.empty:
        st.subheader("Registered Peers")
        st.dataframe(peers, use_container_width=True)


# ---------------- REGISTER PEER ----------------

elif menu == "Register Peer":
    st.header("Register Peer")

    peer_name = st.text_input("Peer Name", placeholder="Example: Peer_A")

    if st.button("Generate Key and Register", use_container_width=True):
        if peer_name.strip() == "":
            st.error("Please enter a peer name.")
        else:
            private_key = generate_private_key()
            public_key = generate_public_key(private_key)

            add_peer(peer_name, public_key)
            add_log(peer_name, "Registration", "Success", "Peer registered successfully")

            st.success("Peer registered successfully.")

            st.download_button(
                "Download Private Key",
                private_key,
                file_name=f"{peer_name}_private_key.txt",
                mime="text/plain"
            )

            st.subheader("Stored Public Key Hash")
            st.code(public_key)

            st.warning("Download and keep the private key safely. It is required for Phase 1.")


# ---------------- PHASE 1 ----------------

elif menu == "Phase 1: Identity Verification":
    st.header("Phase 1: Identity Verification")

    peer_name = st.text_input("Peer Name", placeholder="Example: Peer_A")
    private_key = st.text_area("Paste Private Key", height=150)

    if st.button("Verify Identity", use_container_width=True):
        stored_public_key = get_peer(peer_name)

        if not stored_public_key:
            st.error("Peer not found. Register peer first.")
        elif not private_key.strip():
            st.error("Please paste the private key.")
        else:
            start = time.time()

            verified = verify_identity(private_key.strip(), stored_public_key)

            latency = round((time.time() - start) * 1000, 2)

            if verified:
                st.session_state.verified_peer = peer_name
                st.session_state.current_peer = peer_name

                add_log(
                    peer_name,
                    "Phase 1",
                    "Success",
                    f"Identity verified in {latency} ms"
                )

                st.success(f"Phase 1 successful. Identity verified. Latency: {latency} ms")
            else:
                add_log(
                    peer_name,
                    "Phase 1",
                    "Failed",
                    "Private key did not match stored public key"
                )

                st.error("Verification failed. Invalid private key.")


# ---------------- PHASE 2 ----------------

elif menu == "Phase 2: Session Key":
    st.header("Phase 2: Secure Session Key Establishment")

    peer_name = st.text_input("Peer Name", value=st.session_state.current_peer or "")

    if st.button("Generate Session Key", use_container_width=True):
        if not get_peer(peer_name):
            st.error("Peer not found.")
        elif st.session_state.verified_peer != peer_name:
            st.error("Complete Phase 1 identity verification first.")
        else:
            session_key = generate_session_key()
            st.session_state.session_key = session_key

            add_log(peer_name, "Phase 2", "Success", "Secure session key generated")

            st.success("Phase 2 successful. Session key generated.")
            st.code(session_key)


# ---------------- PHASE 3 ----------------

elif menu == "Phase 3: Secure Transfer":
    st.header("Phase 3: Secure Content Transfer")

    peer_name = st.text_input("Peer Name", value=st.session_state.current_peer or "")
    content = st.text_area(
        "Enter secure content",
        placeholder="Example: Confidential P2P content"
    )

    if st.button("Encrypt and Verify Transfer", use_container_width=True):
        if st.session_state.session_key is None:
            st.error("Generate session key first in Phase 2.")
        elif peer_name != st.session_state.verified_peer:
            st.error("Peer must complete Phase 1 and Phase 2 first.")
        elif content.strip() == "":
            st.error("Please enter content.")
        else:
            start = time.time()

            encrypted = xor_encrypt_decrypt(content, st.session_state.session_key)
            decrypted = xor_decrypt(encrypted, st.session_state.session_key)

            mac_value = generate_mac(st.session_state.session_key, content)
            integrity = verify_mac(st.session_state.session_key, content, mac_value)

            latency = round((time.time() - start) * 1000, 2)

            if integrity and decrypted == content:
                st.session_state.phase3_complete = True

                add_log(
                    peer_name,
                    "Phase 3",
                    "Success",
                    f"Content encrypted and integrity verified in {latency} ms"
                )

                st.success("Phase 3 successful. Secure transfer completed.")
                st.info("Now go to Secure Login to enter the protected application.")

                st.subheader("Encrypted Content")
                st.code(encrypted)

                st.subheader("HMAC Integrity Code")
                st.code(mac_value)

                st.subheader("Decrypted Content")
                st.write(decrypted)
            else:
                add_log(peer_name, "Phase 3", "Failed", "Integrity verification failed")
                st.error("Integrity verification failed.")


# ---------------- SECURE LOGIN ----------------

elif menu == "Secure Login":
    st.header("Secure Login")

    st.write("Login is allowed only after all three authentication phases are completed.")

    peer_name = st.text_input("Peer Name", value=st.session_state.current_peer or "")

    if st.button("Login to Application", use_container_width=True):
        if not get_peer(peer_name):
            st.error("Peer not found.")
        elif st.session_state.verified_peer != peer_name:
            st.error("Access denied. Complete Phase 1 first.")
        elif st.session_state.session_key is None:
            st.error("Access denied. Complete Phase 2 first.")
        elif not st.session_state.phase3_complete:
            st.error("Access denied. Complete Phase 3 first.")
        else:
            st.session_state.logged_in = True
            st.session_state.current_peer = peer_name

            add_log(
                peer_name,
                "Secure Login",
                "Success",
                "Peer logged into protected application"
            )

            st.success("Login successful. You can now access the Application Dashboard.")


# ---------------- APPLICATION DASHBOARD ----------------

elif menu == "Application Dashboard":
    if not st.session_state.logged_in:
        st.error("Access denied. Complete all three phases and secure login first.")
    else:
        st.header("Protected P2P Content Application")
        st.success(f"Welcome, {st.session_state.current_peer}")

        tab1, tab2, tab3 = st.tabs(
            ["Secure Message", "Upload Content", "Session Info"]
        )

        with tab1:
            st.subheader("Send Secure Message")
            message = st.text_area("Message")

            if st.button("Encrypt Message"):
                if message.strip() == "":
                    st.error("Enter a message.")
                else:
                    encrypted = xor_encrypt_decrypt(
                        message,
                        st.session_state.session_key
                    )

                    mac_value = generate_mac(
                        st.session_state.session_key,
                        message
                    )

                    st.success("Message encrypted successfully.")

                    st.subheader("Encrypted Message")
                    st.code(encrypted)

                    st.subheader("Message MAC")
                    st.code(mac_value)

        with tab2:
            st.subheader("Upload P2P Content")

            uploaded_file = st.file_uploader("Upload a file")

            if uploaded_file:
                file_bytes = uploaded_file.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()

                st.success("File uploaded successfully.")
                st.write("File name:", uploaded_file.name)
                st.write("File size:", len(file_bytes), "bytes")
                st.write("SHA-256 file hash:")
                st.code(file_hash)

        with tab3:
            st.subheader("Session Information")

            st.write("Authenticated Peer:", st.session_state.current_peer)
            st.write("Phase 1:", "Completed")
            st.write("Phase 2:", "Completed")
            st.write("Phase 3:", "Completed")
            st.write("Login Status:", "Logged In")


# ---------------- ATTACK SIMULATION ----------------

elif menu == "Attack Simulation":
    st.header("MITM / Identity Attack Simulation")

    target_peer = st.text_input("Target Peer Name", placeholder="Example: Peer_A")

    if st.button("Simulate Attack", use_container_width=True):
        stored_public_key = get_peer(target_peer)

        if not stored_public_key:
            st.error("Target peer not found.")
        else:
            fake_private_key = generate_private_key()

            attack_result = verify_identity(fake_private_key, stored_public_key)

            if attack_result:
                add_log("Attacker", "Attack Simulation", "Failed", "Fake identity accepted")
                st.error("Attack succeeded. System vulnerable.")
            else:
                add_log("Attacker", "Attack Simulation", "Success", "Fake identity rejected")
                st.success("Attack blocked: Fake identity rejected.")


# ---------------- LOGS ----------------

elif menu == "Authentication Logs":
    st.header("Authentication Logs")

    logs = get_logs()

    if logs.empty:
        st.info("No logs available.")
    else:
        phase_filter = st.selectbox(
            "Filter by Phase",
            ["All"] + sorted(logs["phase"].unique().tolist())
        )

        filtered = logs.copy()

        if phase_filter != "All":
            filtered = filtered[filtered["phase"] == phase_filter]

        st.dataframe(filtered.drop(columns=["id"]), use_container_width=True)

        st.download_button(
            "Download Logs as CSV",
            filtered.to_csv(index=False),
            file_name="authentication_logs.csv",
            mime="text/csv"
        )


# ---------------- LOGOUT ----------------

elif menu == "Logout":
    st.header("Logout")

    if st.button("Logout", use_container_width=True):
        peer = st.session_state.current_peer or "Unknown"

        add_log(peer, "Logout", "Success", "Peer logged out")

        st.session_state.logged_in = False
        st.session_state.current_peer = None
        st.session_state.verified_peer = None
        st.session_state.session_key = None
        st.session_state.phase3_complete = False

        st.success("Logged out successfully.")
