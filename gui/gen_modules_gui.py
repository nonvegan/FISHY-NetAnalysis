import dearpygui.dearpygui as dpg
from subprocess import run
from os import chdir
from gen_conn_metric_module import output_conn_sum_metric
from dearpy_helpers import alert_popup

INTERVAL_DICT = {"seconds": "secs", "minutes": "mins", "hours": "hrs", "days": "days"}


def get_metric_values():
    metric_values = {
        "metric_calc": dpg.get_value("metric_calc"),
        "metric_measure": dpg.get_value("metric_measure"),
        "metric_threshold": dpg.get_value("metric_threshold"),
        "metric_interval": str(dpg.get_value("metric_interval_0"))
        + INTERVAL_DICT[dpg.get_value("metric_interval_1")],
    }
    return metric_values


def gen_button_callback():
    metric_values = get_metric_values()
    print(metric_values)

    if metric_values["metric_measure"] != "":
        if metric_values["metric_calc"] == "sum":
            dpg.show_item("file_dialog_id")
    else:
        print("Missing parameters")


def cancel_callback(sender, app_data):
    pass


def generate_script(sender, app_data):
    print(app_data["file_path_name"])

    metric_values = get_metric_values()

    try:
        output_conn_sum_metric(
            metric_values["metric_measure"],
            metric_values["metric_threshold"],
            metric_values["metric_interval"],
            app_data["file_path_name"],
        )
        alert_popup("Script Generated", "File saved at: " + app_data["file_path_name"])
    except Exception as e:
        alert_popup("Error", "Something went wrong: " + str(e))


dpg.create_context()
dpg.create_viewport(
    title="Zeek Metric Module generator", width=550, height=500, resizable=False
)
# dpg.set_global_font_scale(1)

with dpg.handler_registry():
    dpg.add_key_down_handler(key=dpg.mvKey_Q, callback=lambda: dpg.stop_dearpygui())

with dpg.file_dialog(
    directory_selector=False,
    show=False,
    callback=generate_script,
    id="file_dialog_id",
    default_filename="metric",
    modal=True,
    cancel_callback=cancel_callback,
):
    dpg.add_file_extension(".zeek")

with dpg.window(label="Change Channel", tag="Primary Window"):
    dpg.set_primary_window("Primary Window", True)
    dpg.add_text("Metric Calculation:")
    dpg.add_radio_button(
        items=["sum", "average", "uniques"],
        default_value="sum",
        tag="metric_calc",
        enabled=False,
        horizontal=True,
    )

    dpg.add_text("Metric Measure:")
    dpg.add_combo(
        items=["duration", "resp_bytes", "resp_pkts"], tag="metric_measure", width=300
    )

    dpg.add_text("Metric Threshold:")
    dpg.add_input_double(
        min_value=0,
        min_clamped=True,
        step=100,
        step_fast=False,
        tag="metric_threshold",
        width=300,
    )

    dpg.add_text("Metric interval:")
    interval_group = dpg.add_group(horizontal=True)
    dpg.add_input_int(
        min_value=0,
        min_clamped=True,
        parent=interval_group,
        step_fast=True,
        width=200,
        tag="metric_interval_0",
    )
    dpg.add_combo(
        items=["seconds", "minutes", "hours", "days"],
        parent=interval_group,
        default_value="seconds",
        width=92,
        tag="metric_interval_1",
    )

    dpg.add_spacer(height=10)
    dpg.add_button(
        label="Generate Zeek script",
        tag="gen_button",
        width=300,
        callback=gen_button_callback,
    )

dpg.setup_dearpygui()
dpg.show_viewport()
dpg.start_dearpygui()
dpg.destroy_context()
