from zat.json_log_to_dataframe import JSONLogToDataFrame
import plotly.graph_objects as go
from plotly.subplots import make_subplots

log_to_df = JSONLogToDataFrame()

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

def fig_apply_general_template():
    global fig
    fig.update_xaxes(showgrid=False, zeroline=False)
    fig.update_yaxes(showgrid=False, zeroline=False)
    fig.update_layout(
            hovermode='x unified',
            title={'x':0.5, 'xanchor': 'center', 'yanchor': 'top'},
            font=dict( size=18, color="RebeccaPurple"),
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
                    rangeslider=dict(visible=False)))

# Zeek Flows
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Zeek logs"}, legend_title="Zeek file")
fig_apply_general_template()
fig.add_trace(flow_count_trace(conn_df, "conn.log"))
fig.add_trace(flow_count_trace(http_df, "http.log"))
fig.add_trace(flow_count_trace(dns_df,  "dns.log"))
fig.add_trace(flow_count_trace(ssl_df,  "ssl.log"))
fig.add_trace(flow_count_trace(dce_rpc_df, "dce_rpc.log"))
fig.add_trace(flow_count_trace(kerberos_df, "kerberos.log"))
fig.show()
fig.write_html("1.html")

# Zeek Connection Packets
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Connection packets"}, legend_title="Packets")
fig_apply_general_template()
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["total_pkts"], name="Total"))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["orig_pkts"], name="Origin"))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["resp_pkts"], name="Response"))
fig.for_each_trace(lambda trace: trace.update(mode="lines", hoverinfo="name+x+y"))
fig.show()
fig.write_html("2.html")

# Zeek Connection bytes
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Connection Bytes"}, legend_title="Bytes")
fig_apply_general_template()
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["total_bytes"], name="Payload Total"))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["orig_bytes"], name="Payload Origin"))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["resp_bytes"], name="Payload Response"))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["total_ip_bytes"], name="Total IP"))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["orig_ip_bytes"], name="Origin IP"))
fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df["resp_ip_bytes"], name="Response IP"))
fig.for_each_trace(lambda trace: trace.update(mode="lines", hoverinfo="name+x+y"))
fig.show()
fig.write_html("3.html")

# Zeek Connection by protocol
fig = go.Figure()
fig.update_layout(title={ 'text': "SONAE Connection Protocols"}, legend_title="Protocol")
fig_apply_general_template()
fig.add_trace(go.Scatter(x=conn_udp_df.index, y=conn_udp_df["flow_count"], marker=dict(color='#636efa'), text=conn_udp_df["flow_count"], name="udp"))
fig.add_trace(go.Scatter(x=conn_tcp_df.index, y=conn_tcp_df["flow_count"], marker=dict(color='#ef553b'), text=conn_tcp_df["flow_count"], name="tcp"))
fig.add_trace(go.Scatter(x=conn_icmp_df.index, y=conn_icmp_df["flow_count"], marker=dict(color='#00cc96'), text=conn_icmp_df["flow_count"], name="icmp"))
fig.for_each_trace(lambda trace: trace.update(mode='lines+text+markers', textfont_color=trace.marker.color, textposition='top center', hoverinfo="name+x+y"))
fig.show()
fig.write_html("4.html")

fig = make_subplots(specs=[[{"secondary_y": True}]])
fig.update_layout(title={ 'text': "SONAE Avg Connection Duration"}, 
                  xaxis_title="Date", 
                  yaxis_title="Number of packets", 
                  yaxis2_title="Avg. Duration (s)", 
                  legend_title="Protocol")
fig_apply_general_template()
fig.add_trace(go.Scatter(x=conn_udp_df.index, y=conn_df["duration"] / conn_df["flow_count"], name="Duration", mode='lines'), secondary_y=True)
fig.add_trace(go.Bar(x=conn_udp_df.index, y=conn_df["orig_pkts"], name="Origin Packets"))
fig.add_trace(go.Bar(x=conn_udp_df.index, y=conn_df["resp_pkts"], name="Response Packets"))
fig.update_layout(barmode='stack')
fig.show()
fig.write_html("zeek_conn_packets_duration_dash.html")
