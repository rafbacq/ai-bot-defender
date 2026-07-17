"""One account-scoped view of every long-running application operation.

Each subsystem keeps the execution details it needs (a generator subprocess,
an Ansible process group, provider-query threads, and so on).  This module only
normalizes their safe public state so every authenticated page can show that
work is still running and link back to the correct progress view.
"""

from __future__ import annotations

from . import (
    provenance_service,
    run_manager,
    selfplay_service,
    task_service,
    template_gen,
)


_TASK_DESTINATIONS = {
    "site-deploy": ("Site deployment", "/sites?job={id}"),
    "site-start": ("Site start", "/sites?job={id}"),
    "site-stop": ("Site take-down", "/sites?job={id}"),
    "site-delete": ("Site deletion", "/sites?job={id}"),
    "campaign-intelligence": ("Campaign analysis", "/logs?job={id}"),
    "manual-prompt": ("Prompt generation", "/query?job={id}#manual"),
    "membership-inference": ("Membership inference", "/query?job={id}#membership"),
}


def _task_items(owner, is_admin):
    items = []
    for task in task_service.list_jobs(
        requester=owner, is_admin=is_admin, active_only=True,
    ):
        title, href = _TASK_DESTINATIONS.get(
            task.get("kind"),
            (str(task.get("kind") or "Background operation").replace("-", " ").title(),
             "/"),
        )
        items.append({
            "id": task["id"],
            "kind": task.get("kind"),
            "title": title,
            "status": task.get("status") or "running",
            "label": task.get("label") or title,
            "started": task.get("started"),
            "updated": task.get("updated"),
            "href": href.format(id=task["id"]),
        })
    return items


def _generation_items(owner, is_admin):
    return [
        {
            "id": job["id"],
            "kind": "template-generation",
            "title": "Template generation",
            "status": job.get("status") or "running",
            "label": job.get("label") or "Generating a honeypot template…",
            "started": job.get("started_at"),
            "updated": job.get("updated"),
            "href": f"/generator?job={job['id']}",
        }
        for job in template_gen.list_generations(
            requester=owner, is_admin=is_admin, active_only=True,
        )
    ]


def list_active(*, owner=None, is_admin=False):
    """Return every currently-running job visible to ``owner``, newest first."""
    items = _task_items(owner, is_admin)
    items.extend(_generation_items(owner, is_admin))

    for run in run_manager.active_runs(requester=owner, is_admin=is_admin):
        run = dict(run)
        run["title"] = "Manual evaluation" if run.get("kind") == "manual" else "Detection run"
        items.append(run)

    for probe in provenance_service.active_probes(
        requester=owner, is_admin=is_admin,
    ):
        probe = dict(probe)
        probe["title"] = "RAG experiment" if "rag" in probe.get("kind", "") else "Provenance probe"
        items.append(probe)

    selfplay = selfplay_service.active_job(requester=owner, is_admin=is_admin)
    if selfplay:
        selfplay = dict(selfplay)
        selfplay["title"] = "Adversarial self-play"
        items.append(selfplay)

    items.sort(key=lambda item: item.get("updated") or item.get("started") or 0, reverse=True)
    return items


def summary(*, owner=None, is_admin=False):
    jobs = list_active(owner=owner, is_admin=is_admin)
    return {"count": len(jobs), "jobs": jobs}

