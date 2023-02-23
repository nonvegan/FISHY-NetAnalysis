import glob
from zat.json_log_to_dataframe import JSONLogToDataFrame
from pandas_profiling import ProfileReport

log_to_df = JSONLogToDataFrame()

logs = list(map(lambda x: x[5:-4], glob.glob("logs/*.log")))

for unwanted_log in ["packet_filter", "reporter"]:
    if(unwanted_log in logs):
	    logs.remove(unwanted_log)

for log in ["conn", "http"]:
    print(log)
    df = log_to_df.create_dataframe("logs/{}.log".format(log))
    df.to_csv("datasets/{}.csv".format(log))
    profile = ProfileReport(df, title="Zeek {} report".format(log), explorative=True)
    profile.to_file("reports/{}_report.html".format(log))
