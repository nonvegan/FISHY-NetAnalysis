

module_name = "METRIC_TRACK"
module_dependencies = ["base/protocols/conn", "base/frameworks/sumstats", "base/frameworks/notice"] 
notice_type_name = "Metric_threshold_crossed"

def output_conn_sum_metric(metric_name, metric_interval, metric_threshold):
    with open("{}_sum_metric.zeek".format(metric_name), "w") as file_handle:

        # String vars
        metric_limit_var_str = "metric_{}_limit".format(metric_name)
        metric_interval_var_str = "metric_{}_epoch_interval".format(metric_name)
        metric_sumstats_stream_name_str = "metric.conn.{}".format(metric_name)
        metric_sumstats_name_str = "{}.sum".format(metric_sumstats_stream_name_str)

        # Module dependencies
        for module_dependency in module_dependencies:
            file_handle.write("@load {}\n".format(module_dependency))

        file_handle.write("\nmodule {};\n\n".format(module_name));

        #Module variables
        file_handle.write("export {\n\tredef enum Notice::Type += {\n\t\t" + notice_type_name + "\n\t};\n")
        file_handle.write("\tconst {} = {} &redef;\n".format(metric_interval_var_str, metric_interval))
        file_handle.write("\tconst {}: double = {} &redef;\n".format(metric_limit_var_str, metric_threshold))
        file_handle.write("}\n");

        # Zeek init
        file_handle.write("\nevent zeek_init()\n{\n")
        file_handle.write("\tSumStats::create([$name = \"{}\",\n".format(metric_sumstats_name_str))
        file_handle.write("\t\t$reducers = set(SumStats::Reducer($stream=\"{}\", $apply=set(SumStats::SUM))),\n".format(metric_sumstats_stream_name_str))
        file_handle.write("\t\t$epoch = {},\n".format(metric_interval_var_str))
        file_handle.write("\t\t$threshold_val(key: SumStats::Key, result: SumStats::Result) =\n\t\t{\n")
        file_handle.write("\t\treturn result[\"" + metric_sumstats_stream_name_str + "\"]$sum;\n\t\t},\n")
        file_handle.write("\t\t$threshold={},\n".format(metric_limit_var_str));
        file_handle.write("\t\t$threshold_crossed(key: SumStats::Key, result: SumStats::Result) =\n\t\t{\n")
        file_handle.write("\t\tlocal r = result[\""+ metric_sumstats_stream_name_str +"\"];\n")
        file_handle.write("\t\tNOTICE([$note={},\n".format(notice_type_name))
        file_handle.write("\t\t\t$msg=fmt(\"Threshold of %s crossed (%d in the last %s)\", {}, r$dbl, {}),\n"
                          .format(metric_name, metric_interval_var_str))
        file_handle.write("\t\t\t$identifier=\""+ metric_sumstats_name_str +"\"]);\n\t\t}\n")
        file_handle.write("\t]);\n")
        file_handle.write("}\n")

        # Event
        file_handle.write("\nevent Conn::log_conn(rec: Conn::Info)\n{\n")
        file_handle.write("\tSumStats::observe(\"metric.conn.{}\", SumStats::Key(), SumStats::Observation($dbl=rec${}))\n"
                          .format(metric_name, metric_name));
        file_handle.write("}\n")


output_conn_sum_metric("duration", "30secs", "30")
