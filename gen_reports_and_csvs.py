import glob
from zat.json_log_to_dataframe import JSONLogToDataFrame
from pandas_profiling import ProfileReport

log_to_df = JSONLogToDataFrame()

logs = list(map(lambda x: x[5:-4], glob.glob("logs/*.log")))
logs.remove("stats")
for log in logs:
    print(log)
    df = log_to_df.create_dataframe("logs/{}.log".format(log))
    df.to_csv("datasets/{}.csv".format(log))
    profile = ProfileReport(df, title="Zeek {} report".format(log), minimal=True)
    profile.to_file("reports/{}_report.html".format(log))
