"""State module for dnscontrol formula."""

__virtualname__ = "dnscontrol"
__salt__ = globals().get("__salt__", {})
__opts__ = globals().get("__opts__", {})


def __virtual__():
    if "dnscontrol.apply_payload" not in __salt__:
        return False, "dnscontrol execution module is not available (apply_payload missing)"
    return __virtualname__


def managed(
    name,
    config_dir=None,
    zones=None,
    providers=None,
    warnings=None,
    fail_on_warnings=True,
    dnscontrol_bin=None,
    lock_file=None,
    lock_timeout_sec=None,
    creds_mode=None,
    config_mode=None,
    template_base=None,
    saltenv=None,
    test=None,
):
    """Ensure dnscontrol config is validated and applied from prepared payload."""
    ret = {
        "name": name,
        "result": True,
        "changes": {},
        "comment": "",
    }

    if test is None:
        test = __opts__.get("test", False)

    mod_result = __salt__["dnscontrol.apply_payload"](
        zones=zones,
        providers=providers,
        warnings=warnings,
        fail_on_warnings=fail_on_warnings,
        config_dir=config_dir,
        dnscontrol_bin=dnscontrol_bin,
        lock_file=lock_file,
        lock_timeout_sec=lock_timeout_sec,
        creds_mode=creds_mode,
        config_mode=config_mode,
        template_base=template_base,
        saltenv=saltenv,
        test=test,
    )

    ret["changes"] = mod_result.get("changes", {})
    ret["comment"] = mod_result.get("comment", "")

    if not mod_result.get("result", False):
        ret["result"] = False
        report = mod_result.get("report") or {}
        errors = report.get("errors") or []
        warnings = report.get("warnings") or []

        if errors or warnings:
            summary = []
            if errors:
                summary.append("errors={}".format(len(errors)))
            if warnings:
                summary.append("warnings={}".format(len(warnings)))
            if summary:
                suffix = " ({}).".format(", ".join(summary))
                ret["comment"] = (ret["comment"] or "dnscontrol.apply failed") + suffix
        return ret

    if test:
        if ret["changes"].get("would_push"):
            ret["result"] = None
            if not ret["comment"]:
                ret["comment"] = "Preview completed in test mode; push would be executed"
        else:
            ret["result"] = True
            if not ret["comment"]:
                ret["comment"] = "Preview completed in test mode; no changes to push"
        return ret

    ret["result"] = True
    return ret
