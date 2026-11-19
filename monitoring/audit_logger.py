"""Minimal structured audit logger. Avoid logging plaintext, keys, or tokens."""
import json, logging, datetime
logger = logging.getLogger("secure_storage.audit")


def audit_event(event: str, actor_id: str, resource_id: str = "", outcome: str = "success") -> None:
    logger.info(json.dumps({"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            "event": event, "actor_id": actor_id,
                            "resource_id": resource_id, "outcome": outcome}))
