"""Shared Microsoft Defender event interpretation.

Defender's ``actionName`` is not a reliable remediation status by itself.
For example, ``Not Applicable`` can accompany an execution named
``Suspended`` and a successful zero-error result.  Keep the interpretation in
one small module so the alert UI and notification email cannot disagree.
"""


def _text(value):
    if value is None:
        return ''
    if isinstance(value, (dict, list, tuple)):
        return ''
    return str(value).strip()


def pick(eventdata, *keys):
    """Return the first non-empty Defender field, accepting key-style aliases.

    Wazuh/Windows Defender events are not consistent about field spelling.
    The same value can arrive as ``action Name``, ``actionName``, or
    ``Action Name``.  Compare a compact, case-insensitive form as a final
    fallback so the UI and email normalizer interpret all of these forms
    identically.
    """
    if not isinstance(eventdata, dict):
        return ''

    def compact(value):
        return ''.join(ch.lower() for ch in str(value) if ch.isalnum())

    compact_keys = {}
    for actual_key in eventdata:
        normalized_key = compact(actual_key)
        if normalized_key and normalized_key not in compact_keys:
            compact_keys[normalized_key] = actual_key

    for key in keys:
        value = _text(eventdata.get(key))
        if value and value.lower() not in ('none', 'null'):
            return value

        actual_key = compact_keys.get(compact(key))
        if actual_key is not None:
            value = _text(eventdata.get(actual_key))
            if value and value.lower() not in ('none', 'null'):
                return value

    return ''


def _contains_any(value, words):
    value = (value or '').lower()
    return any(word in value for word in words)


def normalize_defender_event(eventdata, description=''):
    """Return a conservative, shared remediation interpretation.

    A success is only reported when Defender provides a positive signal:
    a handled execution/action, an explicit successful result, a zero error
    code combined with a successful description, or an explicit
    "no additional actions required" message.
    """
    eventdata = eventdata if isinstance(eventdata, dict) else {}
    description = _text(description)

    threat_name = pick(
        eventdata, 'threat name', 'threatName', 'Threat Name',
        'name', 'detection', 'Detection',
    )
    action_name = pick(
        eventdata, 'action name', 'actionName', 'Action Name',
        'action', 'Action',
    )
    execution_name = pick(
        eventdata, 'execution name', 'executionName', 'Execution Name',
        'execution', 'Execution',
    )
    error_code = pick(
        eventdata, 'error code', 'errorCode', 'Error Code',
        'status code', 'statusCode',
    )
    error_description = pick(
        eventdata, 'error description', 'errorDescription', 'Error Description',
    )
    additional_actions = pick(
        eventdata,
        'additional actions string', 'additionalActionsString',
        'Additional Actions String', 'additional actions',
        'additionalActions', 'Additional Actions',
    )
    execution_result = pick(
        eventdata,
        'execution result', 'executionResult', 'Execution Result',
        'result', 'Result', 'outcome', 'Outcome',
    )
    state = pick(eventdata, 'state', 'State')

    action_lower = action_name.lower()
    execution_lower = execution_name.lower()
    result_lower = execution_result.lower()
    error_lower = error_description.lower()
    additional_lower = additional_actions.lower()
    code_normalized = error_code.lower().replace(' ', '')

    handled_words = (
        'suspend', 'quarantin', 'remov', 'clean', 'block',
        'delete', 'remediat', 'mitigat', 'isolat',
    )
    failure_words = (
        'fail', 'error', 'unsuccess', 'unable', 'could not',
        'not completed', 'denied',
    )
    pending_words = ('pending', 'in progress', 'queued', 'awaiting')
    not_applicable = action_lower in ('not applicable', 'n/a', 'na')
    no_additional_action = _contains_any(
        additional_lower,
        ('no additional actions required', 'no additional action required'),
    )
    explicit_success = _contains_any(
        ' '.join((result_lower, error_lower)),
        ('success', 'successfully', 'completed successfully',
         'operation completed', 'completed with no errors'),
    )
    zero_error = code_normalized in ('0', '0x0', '0x00000000')
    handled_execution = _contains_any(execution_lower, handled_words)
    handled_action = _contains_any(action_lower, handled_words) and not not_applicable
    failed = (
        _contains_any(' '.join((execution_lower, result_lower, error_lower)), failure_words)
        or (error_code and not zero_error and not error_code.lower() in ('1', 'ok'))
    )
    pending = _contains_any(
        ' '.join((execution_lower, action_lower, result_lower, error_lower)),
        pending_words,
    )

    # Order matters: a clear failure or pending state must not be upgraded by
    # a generic description elsewhere in the event.
    if failed:
        status_code = 'FAILED'
        status_label = 'Action Failed'
        action_taken = False
        additional_required = True
        execution_status = 'FAILED'
    elif pending and not (handled_execution or explicit_success or no_additional_action):
        status_code = 'PENDING'
        status_label = 'Action Pending'
        action_taken = False
        additional_required = True
        execution_status = 'PENDING'
    elif (
        handled_execution
        or handled_action
        or explicit_success
        or (zero_error and (execution_name or execution_result or error_description))
        or no_additional_action
    ):
        status_code = 'COMPLETED'
        status_label = (
            'Completed — No Additional Action Required'
            if no_additional_action
            else 'Action Completed'
        )
        action_taken = True
        additional_required = False if no_additional_action else False
        execution_status = 'SUCCESS'
    else:
        status_code = 'ACTION_REQUIRED'
        status_label = 'Action Required'
        action_taken = False
        additional_required = True
        execution_status = 'NOT_COMPLETED'

    action_type = (
        execution_name
        if execution_name and execution_lower not in ('not applicable', 'n/a', 'na')
        else action_name
        if action_name and not not_applicable
        else 'Detection Only'
    )
    if execution_status == 'SUCCESS' and action_type == 'Detection Only':
        action_type = 'Completed'

    if execution_status == 'SUCCESS':
        result_display = error_description or execution_result or 'Successful'
        notification_message = (
            'No further action is required from the IT team.'
            if no_additional_action
            else 'Microsoft Defender successfully processed the detected threat.'
        )
    elif execution_status == 'FAILED':
        result_display = error_description or execution_result or 'Failed'
        notification_message = 'Additional investigation and remediation are required.'
    elif execution_status == 'PENDING':
        result_display = execution_result or 'Remediation is pending.'
        notification_message = 'Remediation is still pending confirmation.'
    else:
        result_display = execution_result or error_description or 'Not completed'
        notification_message = 'The detected threat requires IT team action.'

    return {
        'threat_name': threat_name,
        'action_name': action_name,
        'execution_name': execution_name,
        'action_type': action_type,
        'action_status': status_code,
        'action_status_label': status_label,
        'action_taken': action_taken,
        'additional_action_required': additional_required,
        'execution_status': execution_status,
        'execution_result': result_display,
        'error_code': error_code,
        'error_description': error_description,
        'additional_actions': additional_actions,
        'state': state,
        'status_resolved': status_code == 'COMPLETED',
        'notification_action_required': additional_required,
        'notification_message': notification_message,
    }