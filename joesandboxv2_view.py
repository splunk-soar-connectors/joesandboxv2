# File: joesandboxv2_view.py
# Copyright (c) 2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.


def _get_ctx_result(result, provides):

    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param
    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    ctx_result['data'] = data[0]
    if ctx_result["data"].get("sample_details"):
        for index, module_data in enumerate(ctx_result['data']['sample_details']['system_behavior']):
            module_data.update({
                "div_parent_id": "module_data_{index}".format(index=index),
                "div_child_id": "module_data_{index}-data".format(index=index),
                "href_child_id": "#module_data_{index}-data".format(index=index)
            })
            ctx_result['data']['sample_details']['system_behavior'][index] = module_data

    ctx_result['action'] = provides
    return ctx_result


# Function to provide custom view for 'get report', 'detonate file' and 'detonate url' actions
def sample_details(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == 'check status':
        return 'joesandboxv2_check_status.html'

    return 'joesandboxv2_sample_details.html'
