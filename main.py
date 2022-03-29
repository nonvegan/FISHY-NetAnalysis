from zat.json_log_to_dataframe import JSONLogToDataFrame
import plotly.express as px
import plotly.graph_objects as go
from pandas_profiling import ProfileReport

log_to_df = JSONLogToDataFrame()

http_df = log_to_df.create_dataframe("logs/http.log")

""" profile = ProfileReport(orig_df, title="Zeek conn.log report", explorative=True)
profile.to_file("conn_report.html") """

def add_totals(df):
    df["total_pkts"] = df["orig_pkts"] + df["resp_pkts"]
    df["total_bytes"] = df["orig_bytes"] + df["resp_bytes"]
    df["total_ip_bytes"] = df["orig_ip_bytes"] + df["resp_ip_bytes"]
    return df

def add_flow_count(df):
    df['flow_count'] = 1
    return df

def resample_sum(df, rate):
    df = df.resample(rate).sum()
    return df

def flow_count_trace(df, name):
    return go.Scatter(x=df.index, y=df["flow_count"], name=name, mode="lines+markers")


sample_interval = "10S"

# conn.log
conn_df = log_to_df.create_dataframe("logs/conn.log")
conn_df = add_totals(conn_df)
conn_df = add_flow_count(conn_df)
conn_udp_df = resample_sum(conn_df.query("proto=='udp'"), sample_interval)
conn_tcp_df = resample_sum(conn_df.query("proto=='tcp'"), sample_interval)
conn_icmp_df = resample_sum(conn_df.query("proto=='icmp'"), sample_interval)
conn_df = resample_sum(conn_df, sample_interval)
conn_df = conn_df.iloc[1:] # Skip first samples

# http.log
http_df = log_to_df.create_dataframe("logs/http.log")
http_df = add_flow_count(http_df)
http_df = resample_sum(http_df, sample_interval)
http_df = http_df.iloc[1:] # Skip first samples

# dns.log
dns_df = log_to_df.create_dataframe("logs/dns.log")
dns_df = add_flow_count(dns_df)
dns_df = resample_sum(dns_df, sample_interval)
dns_df = dns_df.iloc[1:] # Skip first samples

# ssl.log
ssl_df = log_to_df.create_dataframe("logs/ssl.log")
ssl_df = add_flow_count(ssl_df)
ssl_df = resample_sum(ssl_df, sample_interval)
ssl_df = ssl_df.iloc[1:] # Skip first samples

# dce_rpc.log
dce_rpc_df = log_to_df.create_dataframe("logs/dce_rpc.log")
dce_rpc_df = add_flow_count(dce_rpc_df)
dce_rpc_df = resample_sum(dce_rpc_df, sample_interval)
dce_rpc_df = dce_rpc_df.iloc[1:] # Skip first samples

# kerberos.log
kerberos_df = log_to_df.create_dataframe("logs/kerberos.log")
kerberos_df = add_flow_count(kerberos_df)
kerberos_df = resample_sum(kerberos_df, sample_interval)
kerberos_df = kerberos_df.iloc[1:] # Skip first samples

# Slider template
def fig_update_layout():
    global fig
    fig.update_xaxes(showgrid=False, zeroline=False)
    fig.update_yaxes(showgrid=False, zeroline=False)
    fig.update_layout(
            title={'x':0.5, 'xanchor': 'center', 'yanchor': 'top'},
            font=dict( family="Courier New, monospace", size=18, color="RebeccaPurple"),
            yaxis=dict( autorange = True, fixedrange= False),
            xaxis=dict(
                rangeselector=dict(
                    buttons=list([
                        dict(count=1,
                            label="1m",
                            step="minute",
                            stepmode="backward"),
                        dict(count=2,
                            label="2m",
                            step="minute",
                            stepmode="backward"),
                        dict(step="all")])),
                    rangeslider=dict(visible=True)))

# Zeek Flows
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Zeek flows"}, legend_title="Zeek file")
fig_update_layout()
fig.add_trace(flow_count_trace(conn_df, "conn.log"))
fig.add_trace(flow_count_trace(http_df, "http.log"))
fig.add_trace(flow_count_trace(dns_df,  "dns.log"))
fig.add_trace(flow_count_trace(ssl_df,  "ssl.log"))
fig.add_trace(flow_count_trace(dce_rpc_df,  "dce_rpc.log"))
fig.add_trace(flow_count_trace(kerberos_df,  "kerberos.log"))
fig.show()

# Zeek Connection Packets
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Connection packets"}, legend_title="Packets")
fig_update_layout()
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["total_pkts"], name="total", mode='lines'))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["orig_pkts"], name="origin", mode='lines'))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["resp_pkts"], name="response", mode='lines'))
fig.show()

# Zeek Connection bytes
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Connection Bytes"}, legend_title="Packets")
fig_update_layout()
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["total_bytes"], name="total", mode='lines'))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["orig_bytes"], name="origin", mode='lines'))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["resp_bytes"], name="response", mode='lines'))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["total_ip_bytes"], name="total ip", mode='lines'))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["orig_ip_bytes"], name="origin ip", mode='lines'))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["resp_ip_bytes"], name="response ip", mode='lines'))
fig.show()

# Zeek Connection by protocol
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Connection Protocols"}, legend_title="Protocol")
fig_update_layout()
fig.add_trace(go.Scatter(x=conn_udp_df.index, y=conn_udp_df["flow_count"], name="udp", mode='lines'))
fig.add_trace(go.Scatter(x=conn_tcp_df.index, y=conn_tcp_df["flow_count"], name="tcp", mode='lines'))
fig.add_trace(go.Scatter(x=conn_icmp_df.index, y=conn_icmp_df["flow_count"], name="icmp", mode='lines'))
fig.show()
