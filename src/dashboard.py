import streamlit as st
import pandas as pd
import sqlite3
import os
import plotly.express as px
from dotenv import load_dotenv

# Page configuration
st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "data/nids.db")

@st.cache_resource
def get_db_connection():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def load_data():
    conn = get_db_connection()
    if conn is None:
        return pd.DataFrame()
    
    query = "SELECT * FROM alerts ORDER BY timestamp DESC"
    try:
        df = pd.read_sql_query(query, conn)
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()

# Header
st.title("🛡️ Network Intrusion Detection System")
st.markdown("Simple NIDS Dashboard using Suricata Alerts")

# Load Data
with st.spinner("Loading alerts..."):
    df = load_data()

if df.empty:
    st.warning("No alerts found in the database. Ensure Suricata is running and the collector is processing logs, or run the mock data generator.")
    st.info("To generate test data:\n1. `python src/mock_data.py`\n2. `python src/collector.py`")
else:
    # Sidebar Filters
    st.sidebar.header("Filters")
    
    # Date filter
    min_date = df['timestamp'].min().date()
    max_date = df['timestamp'].max().date()
    
    date_range = st.sidebar.date_input(
        "Select Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    # Filter dataframe based on selections
    filtered_df = df.copy()
    if len(date_range) == 2:
        start_date, end_date = date_range
        mask = (filtered_df['timestamp'].dt.date >= start_date) & (filtered_df['timestamp'].dt.date <= end_date)
        filtered_df = filtered_df.loc[mask]

    severity_filter = st.sidebar.multiselect(
        "Severity",
        options=sorted(df['alert_severity'].unique()),
        default=sorted(df['alert_severity'].unique())
    )
    
    if severity_filter:
        filtered_df = filtered_df[filtered_df['alert_severity'].isin(severity_filter)]

    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    
    high_sev_count = len(filtered_df[filtered_df['alert_severity'] == 1])
    
    col1.metric("Total Alerts", len(filtered_df))
    col2.metric("High Severity (1)", high_sev_count, delta_color="inverse")
    col3.metric("Unique Source IPs", filtered_df['src_ip'].nunique())
    col4.metric("Unique Signatures", filtered_df['alert_signature'].nunique())

    # Charts Row
    st.markdown("---")
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Alerts Over Time")
        if not filtered_df.empty:
            alerts_timeline = filtered_df.set_index('timestamp').resample('D').size().reset_index(name='count')
            fig_time = px.line(alerts_timeline, x='timestamp', y='count', markers=True)
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("Not enough data to plot timeline.")
            
    with c2:
        st.subheader("Top Alert Signatures")
        if not filtered_df.empty:
            top_sigs = filtered_df['alert_signature'].value_counts().reset_index().head(5)
            top_sigs.columns = ['Signature', 'Count']
            fig_sigs = px.bar(top_sigs, x='Count', y='Signature', orientation='h')
            fig_sigs.update_layout(yaxis={'categoryorder':'total ascending'})
            st.plotly_chart(fig_sigs, use_container_width=True)
            
    # Protocol and IPs
    c3, c4 = st.columns(2)
    
    with c3:
        st.subheader("Protocol Distribution")
        if not filtered_df.empty:
            proto_counts = filtered_df['proto'].value_counts().reset_index()
            proto_counts.columns = ['Protocol', 'Count']
            fig_proto = px.pie(proto_counts, values='Count', names='Protocol', hole=0.4)
            st.plotly_chart(fig_proto, use_container_width=True)
            
    with c4:
        st.subheader("Top Source IPs")
        if not filtered_df.empty:
            top_ips = filtered_df['src_ip'].value_counts().reset_index().head(10)
            top_ips.columns = ['Source IP', 'Count']
            st.dataframe(top_ips, use_container_width=True)

    # Detailed Table
    st.markdown("---")
    st.subheader("Recent Alerts (Detailed View)")
    
    display_cols = ['timestamp', 'src_ip', 'src_port', 'dest_ip', 'dest_port', 'proto', 'alert_severity', 'alert_signature']
    st.dataframe(
        filtered_df[display_cols].sort_values('timestamp', ascending=False).head(100),
        use_container_width=True
    )

    # Incident Response Guidelines
    with st.expander("🛡️ Basic Incident Response Guidelines"):
        st.markdown("""
        **Safety First: Passive Monitoring**
        This NIDS is configured for passive detection. It monitors traffic without blocking it.
        
        **Recommendations for High Severity Alerts (Severity 1):**
        1. **Verify:** Check if the traffic corresponds to known vulnerability scanners or legitimate administrative activity.
        2. **Investigate:** Look at the `src_ip`. Is it internal or external? Is it repeatedly trying different ports?
        3. **Contain:** If verified as malicious and ongoing, consider adding a firewall rule to block the `src_ip` at the edge router.
        4. **Do not automate blocking** blindly, as it may lead to denial of service (DoS) for legitimate users.
        """)

