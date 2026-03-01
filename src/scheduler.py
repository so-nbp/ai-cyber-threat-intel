"""Job scheduler for automated threat intelligence collection."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from .collectors import get_all_collectors
from .storage.database import ThreatDatabase
from .storage.file_store import FileStore
from .utils.config import AppConfig
from .utils.logging import get_logger

logger = get_logger("scheduler")


async def run_collection_cycle(config: AppConfig) -> Dict[str, Any]:
    """Run a full collection cycle across all sources."""
    cycle_id = f"cycle-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    logger.info("collection_cycle_started", cycle_id=cycle_id)

    db = ThreatDatabase(config.storage.db_path)
    db.initialize()
    file_store = FileStore(config.storage.raw_data_path)

    collectors = get_all_collectors(config)
    results = []

    for collector in collectors:
        try:
            result, items = await collector.run()

            if items:
                file_store.store_raw(items, collector.SOURCE_NAME)
                new_count, updated_count = db.store_items(items)
                result.items_new = new_count
                result.items_updated = updated_count

            db.store_collection_run(result, cycle_id=cycle_id)
            results.append(result)

            logger.info(
                "collector_completed",
                source=collector.SOURCE_NAME,
                collected=result.items_collected,
                new=result.items_new,
                success=result.success,
            )
        except Exception as e:
            logger.error("collector_error", source=collector.SOURCE_NAME, error=str(e))

    db.close()

    total_collected = sum(r.items_collected for r in results)
    total_new = sum(r.items_new for r in results)
    all_success = all(r.success for r in results)

    logger.info("collection_cycle_completed", cycle_id=cycle_id,
                total_collected=total_collected, total_new=total_new, all_success=all_success)

    return {
        "cycle_id": cycle_id,
        "total_collected": total_collected,
        "total_new": total_new,
        "all_success": all_success,
        "results": [r.model_dump() for r in results],
    }


def _sync_run_collection(config: AppConfig) -> None:
    asyncio.run(run_collection_cycle(config))


def start_scheduler(config: AppConfig) -> None:
    scheduler = BlockingScheduler()
    hour = config.scheduler.daily_collection_hour
    minute = config.scheduler.daily_collection_minute

    scheduler.add_job(
        _sync_run_collection, trigger=CronTrigger(hour=hour, minute=minute),
        args=[config], id="daily_collection", name="Daily Threat Intelligence Collection",
        replace_existing=True,
    )

    logger.info("scheduler_started", hour=hour, minute=minute)
    print(f"Scheduler started. Daily collection at {hour:02d}:{minute:02d} UTC.")
    print("Press Ctrl+C to stop.")

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("scheduler_stopped")
        print("\nScheduler stopped.")
