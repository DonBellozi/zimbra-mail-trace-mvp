from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models_zimbra_cleanup import ZimbraMailCleanupRun
from app.routers.zimbra_mail_cleanup import _active_progress
from app.services.zimbra import ZimbraService
from app.services.zimbra_mail_cleanup import (
    RuleExecution,
    ZimbraMailCleanupService,
    format_duration_ms,
)
from app.services.zimbra_mail_cleanup_scheduler import ZimbraMailCleanupScheduler


class FakeSettings:
    app_timezone = "UTC"
    zimbra_backend = "ssh_zmprov"
    zimbra_domains = ["company.ru"]
    zimbra_mail_cleanup_workers = 2
    zimbra_ssh_user = "zimbra"
    dry_run = False


class DummyClient:
    def close(self):
        return None


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def create_rule(service: ZimbraMailCleanupService):
    return service.create_rule(
        name="Поздравления",
        condition_type="from",
        condition_value="congratulations@company.ru",
        retention_days=30,
        scope_mode="except",
        mailboxes="archive@company.ru",
        actor="admin",
    )


def mark_schedule_configured(
    service: ZimbraMailCleanupService,
    db: Session,
    value: datetime,
) -> None:
    service.get_settings_record().schedule_changed_at = value
    db.commit()


def search_output(*ids: str, more: bool = False) -> str:
    rows = [
        "   Id  Type   From   Subject   Date",
        "   ----  ----   ----   ----   ----",
    ]
    rows.extend(
        f"{index}. {message_id} mess sender subject 08/01/26 10:00"
        for index, message_id in enumerate(ids, start=1)
    )
    return "\n".join(
        [f"num: {len(ids)}, more: {str(more).lower()}", *rows]
    )


def test_rule_is_created_disabled_and_query_is_safely_scoped(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)

    rule = create_rule(service)
    execution = service._execution(rule)

    assert rule.enabled is False
    assert rule.automatic_cleanup is False
    assert service.rule_mailboxes(rule) == ["archive@company.ru"]
    assert service.build_query(execution) == (
        'is:anywhere -in:trash -in:junk '
        'from:"congratulations@company.ru" before:-30days'
    )


def test_rule_rejects_mailbox_outside_configured_domains(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)

    with pytest.raises(ValueError, match="вне разрешенных доменов"):
        service.create_rule(
            name="Тест",
            condition_type="to",
            condition_value="all@company.ru",
            retention_days=14,
            scope_mode="selected",
            mailboxes="user@outside.example",
            actor="admin",
        )


def test_search_parser_returns_only_message_ids():
    parsed = ZimbraMailCleanupService.parse_search_output(
        search_output("431", "432", more=True)
    )

    assert parsed.message_ids == ("431", "432")
    assert parsed.more is True


def test_duration_is_shown_as_readable_time():
    assert format_duration_ms(3_995_800) == "1 ч 6 мин 36 сек"
    assert format_duration_ms(65_000) == "1 мин 5 сек"
    assert format_duration_ms(1_250) == "1,2 сек."


def test_active_progress_uses_one_shared_mailbox_counter():
    runs = [
        SimpleNamespace(
            batch_processed_mailboxes=7,
            processed_mailboxes=5,
            batch_checked_mailboxes=12,
            checked_mailboxes=10,
            found_messages=15,
            deleted_messages=15,
            remaining_messages=0,
            error_count=0,
        ),
        SimpleNamespace(
            batch_processed_mailboxes=7,
            processed_mailboxes=7,
            batch_checked_mailboxes=12,
            checked_mailboxes=12,
            found_messages=3,
            deleted_messages=3,
            remaining_messages=1,
            error_count=1,
        ),
    ]

    progress = _active_progress(runs)

    assert progress["processed_mailboxes"] == 7
    assert progress["total_mailboxes"] == 12
    assert progress["found_messages"] == 18
    assert progress["remaining_messages"] == 1


def test_dry_run_checks_mailboxes_without_deleting(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    rule = create_rule(service)

    def command(_client, mailbox, args, **_kwargs):
        assert args[0] == "search"
        return search_output("431", "432") if mailbox == "user@company.ru" else search_output()

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["archive@company.ru", "user@company.ru", "two@company.ru"],
        ),
        patch.object(ZimbraService, "_client", return_value=DummyClient()),
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            side_effect=command,
        ) as execute,
    ):
        run = service.dry_run(rule.id, actor="admin")

    assert run.status == "success"
    assert run.checked_mailboxes == 2
    assert run.processed_mailboxes == 2
    assert run.matched_mailboxes == 1
    assert run.found_messages == 2
    assert run.deleted_messages == 0
    assert all(call.args[2][0] == "search" for call in execute.call_args_list)


def test_enable_and_manual_cleanup_require_fresh_matching_preview(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    rule = create_rule(service)

    with pytest.raises(ValueError, match="выполните успешную проверку"):
        service.set_rule_state(
            rule.id,
            enabled=True,
            automatic_cleanup=True,
            actor="admin",
        )

    deleted_arguments: list[str] = []

    def dry_command(_client, _mailbox, args, **_kwargs):
        return search_output("431") if args[0] == "search" else ""

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["user@company.ru"],
        ),
        patch.object(ZimbraService, "_client", return_value=DummyClient()),
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            side_effect=dry_command,
        ),
    ):
        preview = service.dry_run(rule.id, actor="admin")

    enabled = service.set_rule_state(
        rule.id,
        enabled=True,
        automatic_cleanup=True,
        actor="admin",
    )
    assert enabled.enabled is True
    assert enabled.automatic_cleanup is True

    search_calls = 0

    def cleanup_command(_client, _mailbox, args, **kwargs):
        nonlocal search_calls
        if args[0] == "search":
            search_calls += 1
            return search_output("431") if search_calls == 1 else search_output()
        assert kwargs["mutating"] is True
        deleted_arguments.append(args[1])
        return ""

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["user@company.ru"],
        ),
        patch.object(ZimbraService, "_client", return_value=DummyClient()),
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            side_effect=cleanup_command,
        ),
    ):
        run = service.manual_cleanup(
            rule.id,
            preview_run_id=preview.id,
            actor="admin",
        )

    assert run.status == "success"
    assert run.deleted_messages == 1
    assert run.remaining_messages == 0
    assert search_calls == 2
    assert deleted_arguments == ["431"]


def test_cleanup_rechecks_and_reports_messages_that_remain(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    rule = create_rule(service)
    search_calls = 0

    def command(_client, _mailbox, args, **_kwargs):
        nonlocal search_calls
        if args[0] == "search":
            search_calls += 1
            return search_output("431")
        return ""

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["user@company.ru"],
        ),
        patch.object(ZimbraService, "_client", return_value=DummyClient()),
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            side_effect=command,
        ),
    ):
        run = service._run_rules(
            [rule],
            mode="manual_cleanup",
            trigger="manual",
            actor="admin",
        )[0]

    assert search_calls == 2
    assert run.found_messages == 1
    assert run.deleted_messages == 1
    assert run.remaining_messages == 1
    assert run.truncated_mailboxes == 1
    assert run.status == "warning"
    assert "после удаления остались" in run.error_message
    assert run.search_query.endswith('before:-30days')
    assert run.search_cutoff_date is not None


def test_edit_disables_rule_until_new_preview(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    rule = create_rule(service)
    rule.enabled = True
    rule.automatic_cleanup = True
    db.commit()

    updated = service.update_rule(
        rule.id,
        name="Поздравления 2",
        condition_type="from",
        condition_value="congratulations@company.ru",
        retention_days=45,
        scope_mode="all",
        mailboxes="",
        actor="admin",
    )

    assert updated.enabled is False
    assert updated.automatic_cleanup is False
    assert updated.retention_days == 45


def test_scheduled_rules_share_one_mailbox_ssh_session(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    first = create_rule(service)
    second = service.create_rule(
        name="Общая рассылка",
        condition_type="to",
        condition_value="all@company.ru",
        retention_days=14,
        scope_mode="all",
        mailboxes="",
        actor="admin",
    )
    first.enabled = second.enabled = True
    first.automatic_cleanup = second.automatic_cleanup = True
    db.commit()

    client = DummyClient()
    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["user@company.ru"],
        ),
        patch.object(ZimbraService, "_client", return_value=client) as open_client,
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            return_value=search_output(),
        ) as execute,
    ):
        runs = service.scheduled_cleanup()

    assert len(runs) == 2
    open_client.assert_called_once()
    assert execute.call_count == 2


def test_cleanup_releases_shared_query_lock_before_mailbox_processing(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    rule = create_rule(service)
    list_lock_was_free: list[bool] = []
    list_login_lock_was_free: list[bool] = []
    mailbox_lock_was_free: list[bool] = []

    def list_mailboxes():
        acquired = ZimbraService._query_lock.acquire(blocking=False)
        list_lock_was_free.append(acquired)
        if acquired:
            ZimbraService._query_lock.release()
        login_acquired = ZimbraService._login_query_lock.acquire(
            blocking=False
        )
        list_login_lock_was_free.append(login_acquired)
        if login_acquired:
            ZimbraService._login_query_lock.release()
        return ["user@company.ru"]

    def command(_client, _mailbox, _args, **_kwargs):
        acquired = ZimbraService._query_lock.acquire(blocking=False)
        mailbox_lock_was_free.append(acquired)
        if acquired:
            ZimbraService._query_lock.release()
        return search_output()

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            side_effect=list_mailboxes,
        ),
        patch.object(ZimbraService, "_client", return_value=DummyClient()),
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            side_effect=command,
        ),
    ):
        run = service.dry_run(rule.id, actor="admin")

    assert run.status == "success"
    assert list_lock_was_free == [False]
    assert list_login_lock_was_free == [True]
    assert mailbox_lock_was_free == [True]


def test_batch_dry_run_checks_unverified_rules_in_one_mailbox_pass(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    first = create_rule(service)
    second = service.create_rule(
        name="Общая рассылка",
        condition_type="to",
        condition_value="all@company.ru",
        retention_days=14,
        scope_mode="all",
        mailboxes="",
        actor="admin",
    )

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["user@company.ru"],
        ) as list_mailboxes,
        patch.object(
            ZimbraService,
            "_client",
            return_value=DummyClient(),
        ) as open_client,
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            return_value=search_output("431"),
        ) as execute,
    ):
        runs = service.dry_run_unverified(actor="admin")

    assert {run.rule_id for run in runs} == {first.id, second.id}
    assert all(run.trigger == "manual_batch" for run in runs)
    assert all(run.found_messages == 1 for run in runs)
    assert all(run.batch_checked_mailboxes == 1 for run in runs)
    assert all(run.batch_processed_mailboxes == 1 for run in runs)
    list_mailboxes.assert_called_once()
    open_client.assert_called_once()
    assert execute.call_count == 2
    assert service.unverified_rules() == []


def test_prepared_run_is_visible_and_tracks_completed_mailboxes(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    rule = create_rule(service)
    queued = service.prepare_dry_run(rule.id, actor="admin")

    assert queued.status == "queued"
    assert [run.id for run in service.active_runs()] == [queued.id]

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["one@company.ru", "two@company.ru"],
        ),
        patch.object(ZimbraService, "_client", return_value=DummyClient()),
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            return_value=search_output("431"),
        ),
    ):
        run = service.execute_prepared_runs([queued.id])[0]

    assert run.status == "success"
    assert run.checked_mailboxes == 2
    assert run.processed_mailboxes == 2
    assert run.found_messages == 2
    assert service.active_runs() == []


def test_interrupted_queued_run_is_closed_on_startup(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    queued = service.prepare_dry_run(create_rule(service).id, actor="admin")

    assert service.recover_interrupted_runs() == 1

    db.refresh(queued)
    assert queued.status == "failed"
    assert queued.completed_at is not None
    assert "перезапуском" in queued.error_message


def test_weekly_schedule_runs_at_most_once_per_iso_week(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    service.save_settings(
        schedule_mode="weekly",
        schedule_weekday=6,
        schedule_time="03:00",
        actor="admin",
    )
    before = datetime(2026, 8, 30, 2, 59, tzinfo=timezone.utc)
    due = datetime(2026, 8, 30, 3, 1, tzinfo=timezone.utc)
    mark_schedule_configured(
        service,
        db,
        datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc),
    )

    assert service.weekly_due(now=before) is False
    assert service.weekly_due(now=due) is True

    db.add(
        ZimbraMailCleanupRun(
            rule_id=1,
            rule_name="Правило",
            mode="automatic_cleanup",
            trigger="scheduled",
            status="success",
            started_at=due,
            completed_at=due,
        )
    )
    db.commit()

    assert service.weekly_due(
        now=datetime(2026, 8, 30, 4, 0, tzinfo=timezone.utc)
    ) is False


def test_weekly_schedule_records_when_no_rules_are_enabled(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    service.save_settings(
        schedule_mode="weekly",
        schedule_weekday=6,
        schedule_time="03:00",
        actor="admin",
    )
    due = datetime(2026, 8, 30, 3, 1, tzinfo=timezone.utc)
    mark_schedule_configured(
        service,
        db,
        datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc),
    )

    runs = service.run_weekly_if_due(now=due)

    assert len(runs) == 1
    assert runs[0].status == "skipped"
    assert "Нет включённых правил" in runs[0].error_message
    assert service.weekly_due(now=due + timedelta(minutes=1)) is False


def test_failed_weekly_run_is_retried_after_ten_minutes(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    service.save_settings(
        schedule_mode="weekly",
        schedule_weekday=6,
        schedule_time="03:00",
        actor="admin",
    )
    failed_at = datetime(2026, 8, 30, 3, 1, tzinfo=timezone.utc)
    mark_schedule_configured(
        service,
        db,
        datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc),
    )
    db.add(
        ZimbraMailCleanupRun(
            rule_id=1,
            rule_name="Правило",
            mode="automatic_cleanup",
            trigger="scheduled",
            status="failed",
            started_at=failed_at,
            completed_at=failed_at,
        )
    )
    db.commit()

    assert service.weekly_due(
        now=failed_at + timedelta(minutes=9),
    ) is False
    assert service.weekly_due(
        now=failed_at + timedelta(minutes=10),
    ) is True


def test_dedicated_scheduler_starts_due_weekly_cleanup(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    rule = create_rule(service)
    rule.enabled = True
    rule.automatic_cleanup = True
    service.save_settings(
        schedule_mode="weekly",
        schedule_weekday=6,
        schedule_time="03:00",
        actor="admin",
    )
    mark_schedule_configured(
        service,
        db,
        datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc),
    )
    db.commit()
    scheduler = ZimbraMailCleanupScheduler(
        FakeSettings(),
        lambda: Session(db.bind),
    )

    with (
        patch.object(
            ZimbraService,
            "list_user_mailboxes",
            return_value=["user@company.ru"],
        ),
        patch.object(ZimbraService, "_client", return_value=DummyClient()),
        patch.object(
            ZimbraService,
            "execute_mailbox_command",
            return_value=search_output(),
        ),
    ):
        count = scheduler.run_once(
            now=datetime(2026, 8, 30, 3, 1, tzinfo=timezone.utc),
        )

    assert count == 1
    run = db.scalars(
        select(ZimbraMailCleanupRun).where(
            ZimbraMailCleanupRun.trigger == "scheduled"
        )
    ).one()
    assert run.status == "success"
    assert run.processed_mailboxes == 1
    settings_row = service.get_settings_record()
    db.refresh(settings_row)
    assert settings_row.scheduler_status == "completed"
    assert settings_row.scheduler_last_check_at is not None


def test_tuesday_schedule_is_numeric_and_catches_up_on_wednesday(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    service.save_settings(
        schedule_mode="weekly",
        schedule_weekday=1,
        schedule_time="09:00",
        actor="admin",
    )
    mark_schedule_configured(
        service,
        db,
        datetime(2026, 8, 31, 8, 0, tzinfo=timezone.utc),
    )

    decision = service.weekly_schedule_decision(
        now=datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc),
    )

    assert decision.due is True
    assert decision.due_at == datetime(
        2026,
        9,
        1,
        9,
        0,
        tzinfo=timezone.utc,
    )
    assert "Вторник" in decision.reason


def test_tuesday_time_is_evaluated_in_moscow_timezone(db):
    class MoscowSettings(FakeSettings):
        app_timezone = "Europe/Moscow"

    service = ZimbraMailCleanupService(MoscowSettings(), db)
    service.save_settings(
        schedule_mode="weekly",
        schedule_weekday=1,
        schedule_time="09:00",
        actor="admin",
    )
    mark_schedule_configured(
        service,
        db,
        datetime(2026, 8, 31, 5, 0, tzinfo=timezone.utc),
    )

    decision = service.weekly_schedule_decision(
        now=datetime(2026, 9, 1, 6, 1, tzinfo=timezone.utc),
    )

    assert decision.current.strftime("%A %H:%M") == "Tuesday 09:01"
    assert decision.due is True
    assert decision.due_at.strftime("%A %H:%M %z") == "Tuesday 09:00 +0300"


def test_scheduler_records_why_tuesday_run_is_still_waiting(db):
    service = ZimbraMailCleanupService(FakeSettings(), db)
    service.save_settings(
        schedule_mode="weekly",
        schedule_weekday=1,
        schedule_time="09:00",
        actor="admin",
    )
    mark_schedule_configured(
        service,
        db,
        datetime(2026, 8, 31, 8, 0, tzinfo=timezone.utc),
    )
    scheduler = ZimbraMailCleanupScheduler(
        FakeSettings(),
        lambda: Session(db.bind),
    )

    assert scheduler.run_once(
        now=datetime(2026, 9, 1, 8, 30, tzinfo=timezone.utc),
    ) == 0

    row = service.get_settings_record()
    db.refresh(row)
    assert row.scheduler_status == "waiting"
    assert row.scheduler_last_check_at == datetime(
        2026,
        9,
        1,
        8,
        30,
    )
    assert "вторник" in row.scheduler_message


def test_user_mailbox_listing_excludes_system_resources_and_other_domains():
    output = """\
# name user@company.ru
mail: user@company.ru
zimbraAccountStatus: active

# name admin@company.ru
mail: admin@company.ru

# name room@company.ru
mail: room@company.ru
zimbraCalResType: Location

# name user@outside.example
mail: user@outside.example
"""

    class Input:
        class Channel:
            @staticmethod
            def shutdown_write():
                return None

        channel = Channel()

    class ListingClient(DummyClient):
        @staticmethod
        def exec_command(_command, timeout):
            assert timeout == 190
            return Input(), object(), object()

    service = ZimbraService(FakeSettings())
    with (
        patch.object(service, "_client", return_value=ListingClient()),
        patch.object(
            service,
            "_read_remote_command",
            return_value=(0, output, ""),
        ),
    ):
        mailboxes = service.list_user_mailboxes()

    assert mailboxes == ["user@company.ru"]


def test_cleanup_page_and_scheduler_are_wired():
    root = Path(__file__).resolve().parents[1]
    main = (root / "app/main.py").read_text(encoding="utf-8")
    settings_router = (
        root / "app/routers/settings_ui.py"
    ).read_text(encoding="utf-8")
    scheduler = (
        root / "app/services/zimbra_mail_cleanup_scheduler.py"
    ).read_text(encoding="utf-8")
    settings_page = (root / "app/templates/settings.html").read_text(
        encoding="utf-8"
    )
    template = (root / "app/templates/zimbra_mail_cleanup.html").read_text(
        encoding="utf-8"
    )

    assert "zimbra_mail_cleanup.router" in main
    assert "ZimbraMailCleanupScheduler" in main
    assert "weekly_schedule_decision" in scheduler
    assert "update_scheduler_state" in scheduler
    assert 'href="/settings/zimbra-mail-cleanup"' in settings_page
    # Настройки Техэксперта уже хранятся в БД. Старый settings_ui обращался
    # к удаленным env-полям Settings и ронял весь раздел настроек после
    # частичного обновления файлов.
    assert "settings.techexpert_" not in settings_router
    assert "Проверить новые и изменённые" in template
    assert 'onchange="this.form.submit()"' in template
    assert "<span>Включено</span>" in template
    assert "<span>Автоочистка</span>" in template
    assert "Автоочистка раз в неделю" not in template
    assert "Достигнут лимит" not in template
    assert "Создать выключенным" in template
    assert "Выполнить очистку по результату" in template
    assert "cleanup-live-progress" in template
    assert template.count("<progress") == 1
    assert "Общий проход по почтовым ящикам" in template
    assert "Осталось после контроля" in template
    assert "Контроль после удаления не выполнялся" in template
    assert "Фактический фильтр Zimbra" in template
    assert "Состояние планировщика" in template
    assert "Проверено" in template
    assert 'data-cleanup-start' in template
