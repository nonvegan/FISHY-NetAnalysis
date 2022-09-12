from os import path, mkdir
from sys import getsizeof
from glob import glob
from warnings import simplefilter

from zat.json_log_to_dataframe import JSONLogToDataFrame
import plotly.graph_objects as go
import pandas as pd
import dateutil.parser as dparser

simplefilter(action="ignore", category=FutureWarning)
log_to_df = JSONLogToDataFrame()

skip_samples_n = 0
n_days = 2


def add_totals(df):
    df["total_pkts"] = df["orig_pkts"] + df["resp_pkts"]
    df["total_bytes"] = df["orig_bytes"] + df["resp_bytes"]
    df["total_ip_bytes"] = df["orig_ip_bytes"] + df["resp_ip_bytes"]
    return df


def add_flow_count(df):
    df["flow_count"] = 1
    return df


def resample_sum(df, rate):
    return df.resample(rate).sum()


def size_in_megabytes(x):
    return getsizeof(x) / (1024 * 1024)


def log_to_df_print(filenames, i):
    print("Loading {} to a dataframe {}/{}".format(filenames[i], i + 1, len(filenames)))
    return log_to_df.create_dataframe(filenames[i])


def start_date(first_log_filename):
    # datetime.date(year=2022,month=6,day=1)
    return dparser.parse(first_log_filename, fuzzy=True, dayfirst=False)


def fig_apply_general_template(fig):
    fig.update_xaxes(showgrid=False, zeroline=False)
    fig.update_yaxes(showgrid=False, zeroline=False)
    fig.update_layout(
        hovermode="x unified",
        title={"x": 0.5, "xanchor": "center", "yanchor": "top"},
        font=dict(size=18, color="RebeccaPurple"),
        yaxis=dict(autorange=True, fixedrange=False),
        xaxis=dict(rangeslider=dict(visible=False)),
    )


# conn.log
conn_files = glob("logs/conn*.log")[0:n_days]
conn_df = pd.DataFrame()
for i in range(len(conn_files)):
    conn_file = conn_files[i]
    sub_conn_df = log_to_df_print(conn_files, i)
    sub_conn_df = add_totals(sub_conn_df)
    sub_conn_df = add_flow_count(sub_conn_df)
    # sub_conn_df = resample_sum(sub_conn_df, sample_interval)
    conn_df = pd.concat([conn_df, sub_conn_df])
print("Size of Conn DF -> {}MB".format(size_in_megabytes(conn_df)))
conn_df = resample_sum(conn_df, "1min")
conn_df = conn_df.iloc[skip_samples_n:]
conn_df = conn_df.loc[start_date(conn_files[0]) :]
print("Size of Resampled Conn DF -> {}MB\n".format(size_in_megabytes(conn_df)))

conn_metric_intervals = ["30min", "1hour", "1day"]
conn_metrics_to_report = ["flow_count", "duration"]

if not path.exists("./metrics"):
    mkdir("metrics")


for metric_interval in conn_metric_intervals:
    conn_df = resample_sum(conn_df, pd.Timedelta(metric_interval))
    for metric in conn_metrics_to_report:
        id_min = conn_df[metric].idxmin()
        id_max = conn_df[metric].idxmax()
        print(
            "{}/{}: Avg: {}, Min: {} ({}), Max: {} ({})".format(
                metric,
                metric_interval,
                conn_df[metric].mean(),
                conn_df[metric][id_min],
                id_min,
                conn_df[metric][id_max],
                id_max,
            )
        )
        fig = go.Figure()
        fig.update_layout(
            title={"text": "Connection Sum({})/{}".format(metric, metric_interval)},
            xaxis_title="timestamp",
            yaxis_title=metric,
        )
        fig_apply_general_template(fig)
        fig.add_trace(go.Scatter(x=conn_df.index, y=conn_df[metric]))
        fig.write_html("metrics/{}_{}_{}.html".format("conn", metric, metric_interval))

    print("")
# conn_df.to_csv("conn_df.csv")
