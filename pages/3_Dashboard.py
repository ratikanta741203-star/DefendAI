import streamlit as st

if "logged_in" not in st.session_state or not st.session_state.logged_in:
    st.warning("Please login first.")
    st.stop()

st.title("📊 Dashboard")
st.write(f"Welcome, {st.session_state.username}!")
st.write("Access your Secure Vault from sidebar.")