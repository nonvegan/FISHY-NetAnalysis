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

def add_flow_count(df):
    df["flow_count"] = 1
    return df


def resample_sum(df, rate):
    return df.resample(rate).sum()

def resample_mean(df, rate):
    return df.resample(rate).mean()


def resample_uniq(df, rate):
    return df.resample(rate).nunique()


def size_in_megabytes(x):
    return getsizeof(x) / (1024 * 1024)


def log_to_df_print(filename):
    global http_filenames_len
    global http_filenames_index
    print(
        "Loading {} to a dataframe {}/{}".format(
            filename, http_filenames_index + 1, http_filenames_len
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


# http.log
n_days = 100
logs_input_path = "./logs"
http_metric_intervals = ["1H"]
http_metrics_to_sum = ["flow_count", "request_body_len", "response_body_len"]

http_filenames = sorted(glob("{}/http*.log".format(logs_input_path)))[0:n_days]
http_filenames_len = len(http_filenames)

http_df = pd.DataFrame()

for i in range(len(http_filenames)):
    http_filenames_index = i
    sub_http_df = log_to_df_print(http_filenames[i])
    sub_http_df = add_flow_count(sub_http_df)

    sub_http_df.drop(
        set(sub_http_df) - set(http_metrics_to_sum),
        axis=1,
        inplace=True,
    )
    http_df = pd.concat([http_df, sub_http_df])

print(http_df.info())
print("Size of HTTP DF -> {}MB".format(size_in_megabytes(http_df)))

http_df = resample_sum(http_df, "1min").loc[log_date(http_filenames[0]) :]
print("Size of Resampled HTTP DF -> {}MB\n".format(size_in_megabytes(http_df)))

if path.exists("./metrics"):
    rmtree("./metrics")
mkdir("./metrics")

for metric_interval in http_metric_intervals:
    http_df = resample_sum(http_df, pd.Timedelta(metric_interval))
    for http_metric_to_sum in http_metrics_to_sum:
        print_metric_info(http_df, "http", "mean", http_metric_to_sum, metric_interval)
        write_metric_figure(
            http_df, "http", "mean", http_metric_to_sum, metric_interval, "./metrics"
        )