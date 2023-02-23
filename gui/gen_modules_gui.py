import dearpygui.dearpygui as dpg
from subprocess import run
from os import chdir
from gen_conn_metric_module import output_conn_sum_metric

INTERVAL_DICT = {
    "seconds": "secs",
    "minutes": "mins",
    "hours": "hrs",
    "days": "days"
}

def gen_button_callback():
    metric_measure=dpg.get_value(item="metric_measure")
    metric_calc=dpg.get_value(item="metric_calc")

    if metric_measure != "":
        if metric_calc == "sum":
            dpg.show_item("file_dialog_id")
    else:
        print("Missing parameters")
 
def generate_script(sender, app_data):
    metric_calc=dpg.get_value(item="metric_calc")
    metric_measure=dpg.get_value(item="metric_measure")
    metric_threshold=dpg.get_value(item="metric_threshold")
    metric_interval=str(dpg.get_value(item="metric_interval_0")) + INTERVAL_DICT[dpg.get_value("metric_interval_1")]

    print("Generating zeek script -> {}_{}_{}_{}".format(metric_calc, metric_threshold, metric_measure, metric_interval))

    if app_data["file_path_name"] != "":
        print(app_data["file_path_name"])
        output_conn_sum_metric(metric_measure, metric_threshold, metric_interval, app_data["file_path_name"])

def cancel_callback(sender, app_data):
    print('Cancel was clicked.')
    print("Sender: ", sender)
    print("App Data: ", app_data)


dpg.create_context()
dpg.create_viewport(title='Zeek Metric Module generator', width=600, height=400, resizable=False)
dpg.setup_dearpygui()

with dpg.handler_registry():
    dpg.add_key_down_handler(key=dpg.mvKey_Q, callback=lambda: dpg.stop_dearpygui())

with dpg.file_dialog(directory_selector=False, show=False, callback=generate_script, id="file_dialog_id", default_filename="metric",
        modal=True, cancel_callback=cancel_callback):
    dpg.add_file_extension(".zeek")
        
with dpg.window(label="Change Channel",tag="Primary Window"):
    dpg.add_text("Metric Calculation:")
    dpg.add_combo(items=["sum"], default_value="sum", tag="metric_calc")

    dpg.add_text("Metric Measure:")
    dpg.add_combo(items=["duration", "resp_bytes", "resp_pkts"], tag="metric_measure")

    dpg.add_text("Metric Threshold:")
    dpg.add_input_double(min_value=0, min_clamped=True, step=100, step_fast=False, tag="metric_threshold")

    dpg.add_text("Metric interval:")
    interval_group = dpg.add_group(horizontal=True)
    dpg.add_input_int(min_value=0, min_clamped=True, parent=interval_group, step_fast=True, width=200, tag="metric_interval_0")
    dpg.add_combo(items=["seconds", "minutes", "hours", "days"], 
            parent=interval_group, default_value="seconds", width=100, tag="metric_interval_1")

    dpg.add_spacer(height=10)
    dpg.add_button(label="Generate Zeek script", tag="gen_button", width=300, callback=gen_button_callback)

dpg.show_viewport()
dpg.set_primary_window("Primary Window", True)
dpg.start_dearpygui()
dpg.destroy_context()
