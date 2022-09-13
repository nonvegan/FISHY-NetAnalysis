from genericpath import exists
from os import path, mkdir, makedirs
from shutil import rmtree
from sys import getsizeof
from glob import glob
from warnings import simplefilter

from zat.json_log_to_dataframe import JSONLogToDataFrame

import plotly.graph_objects as go
import pandas as pd
import dateutil.parser as dparser

simplefilter(action="ignore", category=FutureWarning)
log_to_df = JSONLogToDataFrame()


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


def resample_uniq(df, rate):
    return df.resample(rate).nunique()


def size_in_megabytes(x):
    return getsizeof(x) / (1024 * 1024)


def log_to_df_print(filename):
    global conn_filenames_len
    global conn_filenames_index
    print(
        "Loading {} to a dataframe {}/{}".format(
            filename, conn_filenames_index + 1, conn_filenames_len
        )
    )
    return log_to_df.create_dataframe(filename)


def log_date(log_filename):
    # datetime.date(year=2022,month=6,day=1)
    return dparser.parse(log_filename, fuzzy=True, dayfirst=False)


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


def write_metric_figure(df, zeek_file, metric_aggr, metric, metric_interval, base_path):
    fig = go.Figure()
    fig.update_layout(
        title={
            "text": "{} {}({})/{}".format(
                zeek_file, metric_aggr, metric, metric_interval
            )
        },
        xaxis_title="timestamp",
        yaxis_title=metric,
    )
    fig_apply_general_template(fig)
    fig.add_trace(go.Scatter(x=df.index, y=df[metric]))

    if not path.exists("{}/{}/{}".format(base_path, metric_aggr, metric)):
        makedirs("{}/{}/{}".format(base_path, metric_aggr, metric))

    fig.write_html(
        "{}/{}/{}/{}_{}_{}_{}.html".format(
            base_path,
            metric_aggr,
            metric,
            zeek_file,
            metric_aggr,
            metric,
            metric_interval,
        )
    )


def print_metric_info(df, zeek_file, metric_aggr, metric, metric_interval):
    id_min = df[metric].idxmin()
    id_max = df[metric].idxmax()
    print(
        "{} {}({})/{}: Avg: {}, Min: {} ({}), Max: {} ({})\n".format(
            zeek_file,
            metric_aggr,
            metric,
            metric_interval,
            df[metric].mean(),
            df[metric][id_min],
            id_min,
            df[metric][id_max],
            id_max,
        )
    )


# conn.log
n_days = 7
conn_metric_intervals = ["30min", "1H", "24H"]
conn_metrics_to_sum = ["flow_count", "duration"]
conn_metrics_to_count_uniques = [
    "id.orig_h",
    "id.resp_h",
    "id.orig_p",
    "id.resp_p",
    "orig_l2_addr",
    "resp_l2_addr",
]

conn_filenames = sorted(glob("logs/conn*.log"))[0:n_days]
conn_filenames_len = len(conn_filenames)

conn_df = pd.DataFrame()
conn_df_uniques = pd.DataFrame()

for i in range(len(conn_filenames)):
    conn_filenames_index = i
    sub_conn_df = log_to_df_print(conn_filenames[i])
    sub_conn_df = add_totals(sub_conn_df)
    sub_conn_df = add_flow_count(sub_conn_df)

    sub_conn_df.drop(
        set(sub_conn_df) - set(conn_metrics_to_sum + conn_metrics_to_count_uniques),
        axis=1,
        inplace=True,
    )

    conn_df_uniques = pd.concat(
        [conn_df_uniques, sub_conn_df[conn_metrics_to_count_uniques]]
    )
    sub_conn_df.drop(conn_metrics_to_count_uniques, inplace=True, axis=1)

    conn_df = pd.concat([conn_df, sub_conn_df])

print(conn_df.info())
print("Size of Conn DF -> {}MB".format(size_in_megabytes(conn_df)))

print(conn_df_uniques.info())
print("Size of Conn DF Unique -> {}MB".format(size_in_megabytes(conn_df_uniques)))

conn_df = resample_sum(conn_df, "1min").loc[log_date(conn_filenames[0]) :]
print("Size of Resampled Conn DF -> {}MB\n".format(size_in_megabytes(conn_df)))
# conn_df.to_csv("conn_df.csv")

if path.exists("./metrics"):
    rmtree("./metrics")
mkdir("./metrics")

for metric_interval in conn_metric_intervals:
    conn_df = resample_sum(conn_df, pd.Timedelta(metric_interval))
    for conn_metric_to_sum in conn_metrics_to_sum:
        print_metric_info(conn_df, "conn", "sum", conn_metric_to_sum, metric_interval)
        write_metric_figure(
            conn_df, "conn", "sum", conn_metric_to_sum, metric_interval, "./metrics"
        )

for metric_interval in conn_metric_intervals:
    resampled_conn_df_uniques = resample_uniq(conn_df_uniques, metric_interval).loc[
        log_date(conn_filenames[0]) :
    ]
    for conn_metric_to_count_uniques in conn_metrics_to_count_uniques:
        print_metric_info(
            resampled_conn_df_uniques,
            "conn",
            "unique",
            conn_metric_to_count_uniques,
            metric_interval,
        )
        write_metric_figure(
            resampled_conn_df_uniques,
            "conn",
            "unique",
            conn_metric_to_count_uniques,
            metric_interval,
            "./metrics",
        )
