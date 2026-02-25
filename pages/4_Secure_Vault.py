import streamlit as st
from cryptography.fernet import Fernet
import os

# --------- LOGIN PROTECTION ----------
if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.warning("🔒 Please login first.")
    st.stop()

username = st.session_state.username
key = st.session_state.key
fernet = Fernet(key)

st.title("🔐 Secure Vault")
st.write(f"Welcome, **{username}**")

# --------- LOGOUT BUTTON ----------
if st.button("🚪 Logout"):
    st.session_state.clear()
    st.success("Logged out successfully.")
    st.stop()

st.markdown("---")

# --------- FILE UPLOAD ----------
uploaded_file = st.file_uploader("📤 Upload File to Encrypt & Store")

if uploaded_file:
    file_data = uploaded_file.read()
    encrypted_data = fernet.encrypt(file_data)

    user_folder = f"vault/{username}"
    os.makedirs(user_folder, exist_ok=True)

    file_path = os.path.join(user_folder, uploaded_file.name)

    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    st.success("✅ File encrypted and stored securely!")

st.markdown("---")

# --------- DISPLAY USER FILES ----------
st.subheader("📂 Your Encrypted Files")

user_folder = f"vault/{username}"

if os.path.exists(user_folder):
    files = os.listdir(user_folder)

    if files:
        for file in files:
            col1, col2 = st.columns(2)

            with col1:
                st.write(f"📄 {file}")

            with col2:
                # Download Button
                with open(os.path.join(user_folder, file), "rb") as f:
                    encrypted_data = f.read()

                decrypted_data = fernet.decrypt(encrypted_data)

                st.download_button(
                    label="⬇ Download",
                    data=decrypted_data,
                    file_name=file,
                    key=file
                )

        # --------- DELETE OPTION ----------
        st.markdown("---")
        delete_file = st.selectbox("🗑 Select file to delete", files)

        if st.button("Delete Selected File"):
            os.remove(os.path.join(user_folder, delete_file))
            st.success("File deleted successfully.")
            st.experimental_rerun()

    else:
        st.info("No files uploaded yet.")
else:
    st.info("Vault folder not found.")