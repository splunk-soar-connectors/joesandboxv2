from joesandboxv2_consts import JOE_JSON_ANALYSIS, JOE_JSON_RESPONSE


def get_nonempty_report_analysis(response_data):
    """Return the analysis object only when the report response is usable."""
    if not isinstance(response_data, dict):
        return None

    report = response_data.get(JOE_JSON_RESPONSE)
    if not isinstance(report, dict):
        return None

    analysis = report.get(JOE_JSON_ANALYSIS)
    if not isinstance(analysis, dict) or not analysis:
        return None

    return analysis
