from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, time as dt_time, timedelta, timezone
from zoneinfo import ZoneInfo

from email_validator import EmailNotValidError, validate_email
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import AuditLog
from app.models_zimbra_cleanup import (
    ZimbraMailCleanupRun,
    ZimbraMailCleanupSettings,
    ZimbraMailRetentionRule,
)
from app.services.zimbra import ZimbraService


CONDITION_TYPES = {"from", "to"}
SCOPE_MODES = {"all", "selected", "except"}
SCHEDULE_MODES = {"manual", "weekly"}
PREVIEW_MAX_AGE_HOURS = 24
SEARCH_LIMIT = 1000
MAX_DELETE_PASSES = 10
ACTIVE_RUN_STATUSES = {"queued", "running"}
SCHEDULE_FAILURE_RETRY_MINUTES = 10
SUMMARY_RE = re.compile(
    r"num:\s*(\d+)\s*,\s*more:\s*(true|false)",
    re.IGNORECASE,
)
MESSAGE_ROW_RE = re.compile(
    r"^\s*\d+\.\s+(\S+)\s+mess(?:age)?(?:\s|$)",
    re.IGNORECASE,
)

WEEKDAY_LABELS = {
    0: "Понедельник",
    1: "Вторник",
    2: "Среда",
    3: "Четверг",
    4: "Пятница",
    5: "Суббота",
    6: "Воскресенье",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def format_duration_ms(value: int | float | None) -> str:
    """Показать длительность без неудобных тысяч секунд."""

    milliseconds = max(0, int(value or 0))
    if milliseconds < 10_000:
        return f"{milliseconds / 1000:.1f}".replace(".", ",") + " сек."
    total_seconds = int(round(milliseconds / 1000))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours} ч {minutes} мин {seconds} сек"
    if minutes:
        return f"{minutes} мин {seconds} сек"
    return f"{seconds} сек"


def normalize_email(value: str, *, field_name: str = "e-mail") -> str:
    try:
        return validate_email(
            str(value or "").strip(),
            check_deliverability=False,
        ).normalized.lower()
    except EmailNotValidError as exc:
        raise ValueError(f"Некорректный {field_name}: {exc}") from exc


def normalize_mailbox_list(value: str | list[str]) -> list[str]:
    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = re.split(r"[\r\n,;]+", str(value or ""))
    result: list[str] = []
    for raw in raw_items:
        text = str(raw or "").strip()
        if not text:
            continue
        mailbox = normalize_email(text, field_name="адрес ящика")
        if mailbox not in result:
            result.append(mailbox)
    return result


@dataclass(frozen=True)
class SearchBatch:
    message_ids: tuple[str, ...]
    more: bool


@dataclass(frozen=True)
class RuleExecution:
    id: int
    condition_type: str
    condition_value: str
    retention_days: int
    scope_mode: str
    mailboxes: tuple[str, ...]


@dataclass(frozen=True)
class MailboxResult:
    rule_id: int
    mailbox: str
    found: int
    deleted: int
    remaining: int
    truncated: bool
    duration_ms: int
    error: str = ""


@dataclass(frozen=True)
class WeeklyScheduleDecision:
    enabled: bool
    due: bool
    current: datetime
    due_at: datetime | None
    next_run_at: datetime | None
    reason: str
    latest_run_id: int = 0
    latest_run_status: str = ""


class ZimbraMailCleanupService:
    """Правила хранения сообщений поверх существующего SSH/Zimbra-клиента."""

    _run_lock = threading.Lock()

    def __init__(self, settings: Settings, db: Session):
        self.settings = settings
        self.db = db

    def get_settings_record(self) -> ZimbraMailCleanupSettings:
        row = self.db.get(ZimbraMailCleanupSettings, 1)
        if row is None:
            now = utcnow()
            row = ZimbraMailCleanupSettings(
                id=1,
                schedule_mode="manual",
                schedule_weekday=6,
                schedule_time="03:00",
                schedule_changed_at=now,
            )
            self.db.add(row)
            self.db.commit()
            self.db.refresh(row)
        elif row.schedule_changed_at is None:
            row.schedule_changed_at = row.updated_at or row.created_at or utcnow()
            self.db.commit()
            self.db.refresh(row)
        return row

    def settings_view(self) -> dict[str, object]:
        row = self.get_settings_record()
        last_check_at = as_utc(row.scheduler_last_check_at)
        scheduler_stale = bool(
            last_check_at is not None
            and row.scheduler_status != "running"
            and (utcnow() - last_check_at).total_seconds() > 90
        )
        automatic_rule_count = int(
            self.db.scalar(
                select(func.count(ZimbraMailRetentionRule.id)).where(
                    ZimbraMailRetentionRule.deleted_at.is_(None),
                    ZimbraMailRetentionRule.enabled.is_(True),
                    ZimbraMailRetentionRule.automatic_cleanup.is_(True),
                )
            )
            or 0
        )
        return {
            "schedule_mode": row.schedule_mode,
            "schedule_weekday": row.schedule_weekday,
            "schedule_time": row.schedule_time,
            "weekday_label": WEEKDAY_LABELS.get(
                row.schedule_weekday,
                str(row.schedule_weekday),
            ),
            "workers": int(self.settings.zimbra_mail_cleanup_workers),
            "automatic_rule_count": automatic_rule_count,
            "scheduler_last_check_at": row.scheduler_last_check_at,
            "scheduler_status": row.scheduler_status,
            "scheduler_stale": scheduler_stale,
            "scheduler_message": row.scheduler_message,
            "scheduler_next_run_at": row.scheduler_next_run_at,
            "timezone": self.settings.app_timezone,
            "updated_by": row.updated_by,
            "updated_at": row.schedule_changed_at or row.updated_at,
        }

    @staticmethod
    def _parse_time(value: str) -> str:
        match = re.fullmatch(r"(\d{2}):(\d{2})", str(value or "").strip())
        if not match:
            raise ValueError("Время запуска должно быть в формате ЧЧ:ММ")
        hour, minute = (int(part) for part in match.groups())
        if hour > 23 or minute > 59:
            raise ValueError("Указано недопустимое время запуска")
        return f"{hour:02d}:{minute:02d}"

    def save_settings(
        self,
        *,
        schedule_mode: str,
        schedule_weekday: int,
        schedule_time: str,
        actor: str,
    ) -> ZimbraMailCleanupSettings:
        mode = str(schedule_mode or "").strip().lower()
        if mode not in SCHEDULE_MODES:
            raise ValueError("Выберите ручной или еженедельный режим")
        weekday = int(schedule_weekday)
        if weekday not in WEEKDAY_LABELS:
            raise ValueError("Выберите корректный день недели")
        normalized_time = self._parse_time(schedule_time)
        row = self.get_settings_record()
        row.schedule_mode = mode
        row.schedule_weekday = weekday
        row.schedule_time = normalized_time
        row.updated_by = str(actor or "")[:256]
        changed_at = utcnow()
        row.schedule_changed_at = changed_at
        row.updated_at = changed_at
        row.scheduler_last_check_at = None
        row.scheduler_status = "pending"
        row.scheduler_message = "Расписание сохранено, ожидается проверка планировщика"
        row.scheduler_next_run_at = None
        self._audit(
            actor,
            "zimbra_mail_cleanup_settings_saved",
            "settings:1",
            {
                "schedule_mode": mode,
                "schedule_weekday": weekday,
                "schedule_time": normalized_time,
            },
        )
        self.db.commit()
        self.db.refresh(row)
        return row

    def update_scheduler_state(
        self,
        *,
        status: str,
        message: str,
        next_run_at: datetime | None,
        checked_at: datetime | None = None,
    ) -> ZimbraMailCleanupSettings:
        row = self.get_settings_record()
        row.scheduler_last_check_at = as_utc(checked_at) or utcnow()
        row.scheduler_status = str(status or "")[:32]
        row.scheduler_message = str(message or "")[:2000]
        row.scheduler_next_run_at = as_utc(next_run_at)
        self.db.commit()
        self.db.refresh(row)
        return row

    def rules(self) -> list[ZimbraMailRetentionRule]:
        return list(
            self.db.scalars(
                select(ZimbraMailRetentionRule)
                .where(ZimbraMailRetentionRule.deleted_at.is_(None))
                .order_by(
                    ZimbraMailRetentionRule.name,
                    ZimbraMailRetentionRule.id,
                )
            ).all()
        )

    def get_rule(self, rule_id: int) -> ZimbraMailRetentionRule:
        row = self.db.get(ZimbraMailRetentionRule, int(rule_id))
        if row is None or row.deleted_at is not None:
            raise ValueError("Правило хранения не найдено")
        return row

    def _allowed_domains(self) -> set[str]:
        domains = {
            str(value or "").strip().lower()
            for value in self.settings.zimbra_domains
            if str(value or "").strip()
        }
        if not domains:
            raise ValueError(
                "Не заданы ZIMBRA_DOMAINS: область очистки нельзя ограничить"
            )
        return domains

    def _validate_rule_values(
        self,
        *,
        name: str,
        condition_type: str,
        condition_value: str,
        retention_days: int,
        scope_mode: str,
        mailboxes: str | list[str],
    ) -> dict[str, object]:
        normalized_name = " ".join(str(name or "").split())
        if not normalized_name:
            raise ValueError("Укажите название правила")
        if len(normalized_name) > 256:
            raise ValueError("Название правила слишком длинное")
        normalized_type = str(condition_type or "").strip().lower()
        if normalized_type not in CONDITION_TYPES:
            raise ValueError("Поддерживаются только условия «От кого» и «Кому»")
        normalized_value = normalize_email(
            condition_value,
            field_name="значение условия",
        )
        days = int(retention_days)
        if days < 1 or days > 3650:
            raise ValueError("Срок хранения должен быть от 1 до 3650 дней")
        normalized_scope = str(scope_mode or "").strip().lower()
        if normalized_scope not in SCOPE_MODES:
            raise ValueError("Выберите корректную область применения")
        normalized_mailboxes = normalize_mailbox_list(mailboxes)
        allowed_domains = self._allowed_domains()
        outside = [
            mailbox
            for mailbox in normalized_mailboxes
            if mailbox.rsplit("@", 1)[-1] not in allowed_domains
        ]
        if outside:
            raise ValueError(
                "Ящики вне разрешенных доменов Zimbra: " + ", ".join(outside)
            )
        if normalized_scope == "selected" and not normalized_mailboxes:
            raise ValueError("Для выбранных ящиков укажите хотя бы один адрес")
        if normalized_scope == "all":
            normalized_mailboxes = []
        return {
            "name": normalized_name,
            "condition_type": normalized_type,
            "condition_value": normalized_value,
            "retention_days": days,
            "scope_mode": normalized_scope,
            "mailboxes": normalized_mailboxes,
        }

    def create_rule(
        self,
        *,
        name: str,
        condition_type: str,
        condition_value: str,
        retention_days: int,
        scope_mode: str,
        mailboxes: str | list[str],
        actor: str,
    ) -> ZimbraMailRetentionRule:
        values = self._validate_rule_values(
            name=name,
            condition_type=condition_type,
            condition_value=condition_value,
            retention_days=retention_days,
            scope_mode=scope_mode,
            mailboxes=mailboxes,
        )
        row = ZimbraMailRetentionRule(
            name=str(values["name"]),
            condition_type=str(values["condition_type"]),
            condition_value=str(values["condition_value"]),
            retention_days=int(values["retention_days"]),
            enabled=False,
            automatic_cleanup=False,
            scope_mode=str(values["scope_mode"]),
            mailboxes_json=json.dumps(values["mailboxes"], ensure_ascii=False),
            created_by=str(actor or "")[:256],
            updated_by=str(actor or "")[:256],
        )
        self.db.add(row)
        self.db.flush()
        self._audit(
            actor,
            "zimbra_mail_cleanup_rule_created",
            f"rule:{row.id}",
            self.rule_snapshot(row),
        )
        self.db.commit()
        self.db.refresh(row)
        return row

    def update_rule(
        self,
        rule_id: int,
        *,
        name: str,
        condition_type: str,
        condition_value: str,
        retention_days: int,
        scope_mode: str,
        mailboxes: str | list[str],
        actor: str,
    ) -> ZimbraMailRetentionRule:
        row = self.get_rule(rule_id)
        values = self._validate_rule_values(
            name=name,
            condition_type=condition_type,
            condition_value=condition_value,
            retention_days=retention_days,
            scope_mode=scope_mode,
            mailboxes=mailboxes,
        )
        row.name = str(values["name"])
        row.condition_type = str(values["condition_type"])
        row.condition_value = str(values["condition_value"])
        row.retention_days = int(values["retention_days"])
        row.scope_mode = str(values["scope_mode"])
        row.mailboxes_json = json.dumps(values["mailboxes"], ensure_ascii=False)
        # После изменения условия старый dry-run больше ничего не подтверждает.
        row.enabled = False
        row.automatic_cleanup = False
        row.updated_by = str(actor or "")[:256]
        row.updated_at = utcnow()
        self._audit(
            actor,
            "zimbra_mail_cleanup_rule_updated",
            f"rule:{row.id}",
            self.rule_snapshot(row),
        )
        self.db.commit()
        self.db.refresh(row)
        return row

    @staticmethod
    def rule_mailboxes(rule: ZimbraMailRetentionRule) -> list[str]:
        try:
            values = json.loads(rule.mailboxes_json or "[]")
        except (TypeError, json.JSONDecodeError):
            values = []
        if not isinstance(values, list):
            return []
        return [str(value).strip().lower() for value in values if str(value).strip()]

    def rule_snapshot(self, rule: ZimbraMailRetentionRule) -> dict[str, object]:
        return {
            "rule_id": int(rule.id or 0),
            "name": rule.name,
            "condition_type": rule.condition_type,
            "condition_value": rule.condition_value,
            "retention_days": int(rule.retention_days),
            "scope_mode": rule.scope_mode,
            "mailboxes": self.rule_mailboxes(rule),
        }

    def _snapshot_json(self, rule: ZimbraMailRetentionRule) -> str:
        return json.dumps(
            self.rule_snapshot(rule),
            ensure_ascii=False,
            sort_keys=True,
        )

    def latest_preview(
        self,
        rule: ZimbraMailRetentionRule,
    ) -> ZimbraMailCleanupRun | None:
        expected = self._snapshot_json(rule)
        return self.db.scalars(
            select(ZimbraMailCleanupRun)
            .where(
                ZimbraMailCleanupRun.rule_id == rule.id,
                ZimbraMailCleanupRun.mode == "dry_run",
                ZimbraMailCleanupRun.status.in_({"success", "warning"}),
                ZimbraMailCleanupRun.rule_snapshot_json == expected,
            )
            .order_by(
                desc(ZimbraMailCleanupRun.completed_at),
                desc(ZimbraMailCleanupRun.id),
            )
            .limit(1)
        ).first()

    def unverified_rules(self) -> list[ZimbraMailRetentionRule]:
        """Новые/изменённые правила без dry-run текущей редакции."""

        return [rule for rule in self.rules() if self.latest_preview(rule) is None]

    def preview_is_fresh(self, run: ZimbraMailCleanupRun | None) -> bool:
        completed = as_utc(run.completed_at) if run is not None else None
        return bool(
            completed is not None
            and utcnow() - completed <= timedelta(hours=PREVIEW_MAX_AGE_HOURS)
        )

    def set_rule_state(
        self,
        rule_id: int,
        *,
        enabled: bool,
        automatic_cleanup: bool,
        actor: str,
    ) -> ZimbraMailRetentionRule:
        row = self.get_rule(rule_id)
        if enabled:
            preview = self.latest_preview(row)
            if not self.preview_is_fresh(preview):
                raise ValueError(
                    "Перед включением выполните успешную проверку правила. "
                    "Результат проверки действует 24 часа."
                )
        row.enabled = bool(enabled)
        row.automatic_cleanup = bool(enabled and automatic_cleanup)
        row.updated_by = str(actor or "")[:256]
        row.updated_at = utcnow()
        self._audit(
            actor,
            "zimbra_mail_cleanup_rule_state_changed",
            f"rule:{row.id}",
            {
                "enabled": row.enabled,
                "automatic_cleanup": row.automatic_cleanup,
            },
        )
        self.db.commit()
        self.db.refresh(row)
        return row

    def delete_rule(self, rule_id: int, *, actor: str) -> None:
        row = self.get_rule(rule_id)
        row.enabled = False
        row.automatic_cleanup = False
        row.deleted_at = utcnow()
        row.updated_by = str(actor or "")[:256]
        row.updated_at = utcnow()
        self._audit(
            actor,
            "zimbra_mail_cleanup_rule_deleted",
            f"rule:{row.id}",
            {"name": row.name},
        )
        self.db.commit()

    @staticmethod
    def build_query(execution: RuleExecution) -> str:
        return (
            # В Zimbra нежелательная почта хранится в системной папке Junk.
            # Папки `spam` у ящика может не быть, и `-in:spam` тогда роняет
            # весь поиск с mail.NO_SUCH_FOLDER.
            "is:anywhere -in:trash -in:junk "
            f'{execution.condition_type}:"{execution.condition_value}" '
            f"before:-{execution.retention_days}days"
        )

    @staticmethod
    def parse_search_output(output: str) -> SearchBatch:
        summary = SUMMARY_RE.search(str(output or ""))
        more = bool(summary and summary.group(2).lower() == "true")
        message_ids: list[str] = []
        for raw_line in str(output or "").splitlines():
            match = MESSAGE_ROW_RE.match(raw_line)
            if match and match.group(1) not in message_ids:
                message_ids.append(match.group(1))
        return SearchBatch(tuple(message_ids), more)

    @staticmethod
    def _execution(rule: ZimbraMailRetentionRule) -> RuleExecution:
        return RuleExecution(
            id=int(rule.id),
            condition_type=rule.condition_type,
            condition_value=rule.condition_value,
            retention_days=int(rule.retention_days),
            scope_mode=rule.scope_mode,
            mailboxes=tuple(ZimbraMailCleanupService.rule_mailboxes(rule)),
        )

    @staticmethod
    def _applies(mailbox: str, execution: RuleExecution) -> bool:
        selected = set(execution.mailboxes)
        if execution.scope_mode == "selected":
            return mailbox in selected
        if execution.scope_mode == "except":
            return mailbox not in selected
        return True

    def _process_mailbox(
        self,
        zimbra: ZimbraService,
        mailbox: str,
        executions: list[RuleExecution],
        *,
        delete: bool,
    ) -> list[MailboxResult]:
        started = time.monotonic()
        try:
            client = zimbra._client()
        except Exception as exc:
            elapsed = int((time.monotonic() - started) * 1000)
            return [
                MailboxResult(
                    rule_id=execution.id,
                    mailbox=mailbox,
                    found=0,
                    deleted=0,
                    remaining=0,
                    truncated=False,
                    duration_ms=elapsed,
                    error=str(exc)[:2000],
                )
                for execution in executions
            ]

        results: list[MailboxResult] = []
        try:
            for execution in executions:
                rule_started = time.monotonic()
                found = 0
                deleted = 0
                remaining = 0
                truncated = False
                error = ""
                try:
                    for pass_number in range(MAX_DELETE_PASSES if delete else 1):
                        output = zimbra.execute_mailbox_command(
                            client,
                            mailbox,
                            [
                                "search",
                                "-t",
                                "message",
                                "-l",
                                str(SEARCH_LIMIT),
                                self.build_query(execution),
                            ],
                            timeout=180,
                        )
                        batch = self.parse_search_output(output)
                        found += len(batch.message_ids)
                        if not delete or not batch.message_ids:
                            truncated = batch.more
                            break
                        zimbra.execute_mailbox_command(
                            client,
                            mailbox,
                            ["deleteMessage", ",".join(batch.message_ids)],
                            timeout=180,
                            mutating=True,
                        )
                        deleted += len(batch.message_ids)
                        if not batch.more:
                            break
                        if pass_number == MAX_DELETE_PASSES - 1:
                            truncated = True
                    if delete and deleted:
                        verification_output = zimbra.execute_mailbox_command(
                            client,
                            mailbox,
                            [
                                "search",
                                "-t",
                                "message",
                                "-l",
                                str(SEARCH_LIMIT),
                                self.build_query(execution),
                            ],
                            timeout=180,
                        )
                        verification = self.parse_search_output(
                            verification_output
                        )
                        remaining = len(verification.message_ids)
                        truncated = bool(remaining or verification.more)
                except Exception as exc:
                    error = str(exc)[:2000]
                results.append(
                    MailboxResult(
                        rule_id=execution.id,
                        mailbox=mailbox,
                        found=found,
                        deleted=deleted,
                        remaining=remaining,
                        truncated=truncated,
                        duration_ms=int((time.monotonic() - rule_started) * 1000),
                        error=error,
                    )
                )
        finally:
            client.close()
        return results

    def _create_run(
        self,
        rule: ZimbraMailRetentionRule,
        *,
        mode: str,
        trigger: str,
        actor: str,
        preview_run_id: int = 0,
        status: str = "running",
    ) -> ZimbraMailCleanupRun:
        now = utcnow()
        execution = self._execution(rule)
        cutoff_date = (
            now.astimezone(ZoneInfo(self.settings.app_timezone)).date()
            - timedelta(days=int(rule.retention_days))
        )
        row = ZimbraMailCleanupRun(
            rule_id=int(rule.id),
            rule_name=rule.name,
            mode=mode,
            trigger=trigger,
            status=status,
            initiated_by=str(actor or "")[:256],
            source_preview_run_id=int(preview_run_id or 0),
            rule_snapshot_json=self._snapshot_json(rule),
            search_query=self.build_query(execution),
            search_cutoff_date=cutoff_date,
            started_at=now,
            progress_at=now,
        )
        self.db.add(row)
        self.db.flush()
        return row

    def active_runs(self) -> list[ZimbraMailCleanupRun]:
        return list(
            self.db.scalars(
                select(ZimbraMailCleanupRun)
                .where(ZimbraMailCleanupRun.status.in_(ACTIVE_RUN_STATUSES))
                .order_by(
                    ZimbraMailCleanupRun.started_at,
                    ZimbraMailCleanupRun.id,
                )
            ).all()
        )

    def _ensure_no_active_runs(self) -> None:
        if self.active_runs():
            raise RuntimeError("Проверка или очистка почты Zimbra уже выполняется")

    def _prepare_runs(
        self,
        rules: list[ZimbraMailRetentionRule],
        *,
        mode: str,
        trigger: str,
        actor: str,
        preview_run_id: int = 0,
    ) -> list[ZimbraMailCleanupRun]:
        if not rules:
            return []
        if mode != "dry_run" and self.settings.dry_run:
            raise RuntimeError("Глобальный DRY_RUN запрещает удаление сообщений")
        self._ensure_no_active_runs()
        rows = [
            self._create_run(
                rule,
                mode=mode,
                trigger=trigger,
                actor=actor,
                preview_run_id=preview_run_id,
                status="queued",
            )
            for rule in rules
        ]
        self.db.commit()
        for row in rows:
            self.db.refresh(row)
        return rows

    def prepare_dry_run(
        self,
        rule_id: int,
        *,
        actor: str,
    ) -> ZimbraMailCleanupRun:
        return self._prepare_runs(
            [self.get_rule(rule_id)],
            mode="dry_run",
            trigger="manual",
            actor=actor,
        )[0]

    def prepare_dry_run_unverified(
        self,
        *,
        actor: str,
    ) -> list[ZimbraMailCleanupRun]:
        rules = self.unverified_rules()
        if not rules:
            raise ValueError("Новых или изменённых правил для проверки нет")
        return self._prepare_runs(
            rules,
            mode="dry_run",
            trigger="manual_batch",
            actor=actor,
        )

    def _validated_preview(
        self,
        rule: ZimbraMailRetentionRule,
        preview_run_id: int,
    ) -> ZimbraMailCleanupRun:
        preview = self.db.get(ZimbraMailCleanupRun, int(preview_run_id))
        if (
            preview is None
            or preview.rule_id != rule.id
            or preview.mode != "dry_run"
            or preview.status not in {"success", "warning"}
            or preview.rule_snapshot_json != self._snapshot_json(rule)
            or not self.preview_is_fresh(preview)
        ):
            raise ValueError(
                "Перед очисткой выполните свежую проверку неизмененного правила"
            )
        if preview.found_messages <= 0:
            raise ValueError("По последней проверке сообщений для удаления нет")
        return preview

    def prepare_manual_cleanup(
        self,
        rule_id: int,
        *,
        preview_run_id: int,
        actor: str,
    ) -> ZimbraMailCleanupRun:
        rule = self.get_rule(rule_id)
        preview = self._validated_preview(rule, preview_run_id)
        return self._prepare_runs(
            [rule],
            mode="manual_cleanup",
            trigger="manual",
            actor=actor,
            preview_run_id=preview.id,
        )[0]

    def _mark_prepared_runs_failed(
        self,
        runs: list[ZimbraMailCleanupRun],
        error: Exception,
    ) -> None:
        completed_at = utcnow()
        message = str(error)[:4000]
        for run in runs:
            if run.status not in ACTIVE_RUN_STATUSES:
                continue
            run.status = "failed"
            run.error_count = max(1, int(run.error_count or 0))
            run.error_message = message
            run.completed_at = completed_at
            run.progress_at = completed_at
        self.db.commit()

    def execute_prepared_runs(
        self,
        run_ids: list[int],
    ) -> list[ZimbraMailCleanupRun]:
        normalized_ids = list(dict.fromkeys(int(value) for value in run_ids))
        runs = [
            run
            for run_id in normalized_ids
            if (run := self.db.get(ZimbraMailCleanupRun, run_id)) is not None
        ]
        if len(runs) != len(normalized_ids) or not runs:
            raise ValueError("Не удалось найти подготовленный запуск")
        if any(run.status != "queued" for run in runs):
            raise ValueError("Подготовленный запуск уже был обработан")
        mode = runs[0].mode
        trigger = runs[0].trigger
        if any(run.mode != mode or run.trigger != trigger for run in runs):
            error = ValueError("В очередь попали несовместимые запуски")
            self._mark_prepared_runs_failed(runs, error)
            raise error
        rules: list[ZimbraMailRetentionRule] = []
        try:
            for run in runs:
                rule = self.get_rule(run.rule_id)
                if run.rule_snapshot_json != self._snapshot_json(rule):
                    raise ValueError(
                        f"Правило «{run.rule_name}» изменилось после постановки в очередь"
                    )
                rules.append(rule)
            return self._run_rules(
                rules,
                mode=mode,
                trigger=trigger,
                actor=runs[0].initiated_by,
                preview_run_id=runs[0].source_preview_run_id,
                prepared_run_ids={run.rule_id: run.id for run in runs},
            )
        except Exception as exc:
            self.db.rollback()
            refreshed = [
                run
                for run_id in normalized_ids
                if (run := self.db.get(ZimbraMailCleanupRun, run_id)) is not None
            ]
            self._mark_prepared_runs_failed(refreshed, exc)
            raise

    def recover_interrupted_runs(self) -> int:
        runs = self.active_runs()
        if not runs:
            return 0
        error = RuntimeError("Запуск прерван перезапуском приложения")
        self._mark_prepared_runs_failed(runs, error)
        return len(runs)

    def _finish_runs(
        self,
        rules: list[ZimbraMailRetentionRule],
        runs: dict[int, ZimbraMailCleanupRun],
        results: list[MailboxResult],
        applicable_counts: dict[int, int],
        *,
        started: float,
        actor: str,
    ) -> list[ZimbraMailCleanupRun]:
        by_rule: dict[int, list[MailboxResult]] = {int(rule.id): [] for rule in rules}
        for result in results:
            by_rule.setdefault(result.rule_id, []).append(result)

        completed_at = utcnow()
        for rule in rules:
            run = runs[int(rule.id)]
            rule_results = by_rule.get(int(rule.id), [])
            errors = [item for item in rule_results if item.error]
            truncated = [item for item in rule_results if item.truncated]
            matched = [item for item in rule_results if item.found > 0]
            run.checked_mailboxes = applicable_counts.get(int(rule.id), 0)
            run.processed_mailboxes = run.checked_mailboxes
            run.batch_processed_mailboxes = run.batch_checked_mailboxes
            run.matched_mailboxes = len(matched)
            run.found_messages = sum(item.found for item in rule_results)
            run.deleted_messages = sum(item.deleted for item in rule_results)
            run.remaining_messages = sum(item.remaining for item in rule_results)
            run.truncated_mailboxes = len(truncated)
            run.error_count = len(errors)
            run.duration_ms = int((time.monotonic() - started) * 1000)
            run.details_json = json.dumps(
                [
                    {
                        "mailbox": item.mailbox,
                        "found": item.found,
                        "deleted": item.deleted,
                        "remaining": item.remaining,
                        "truncated": item.truncated,
                        "duration_ms": item.duration_ms,
                        "error": item.error,
                    }
                    for item in rule_results
                    if (
                        item.found
                        or item.deleted
                        or item.remaining
                        or item.truncated
                        or item.error
                    )
                ],
                ensure_ascii=False,
            )
            if errors and len(errors) >= max(1, len(rule_results)):
                run.status = "failed"
            elif errors:
                run.status = "partial"
            elif truncated:
                run.status = "warning"
            else:
                run.status = "success"
            if errors:
                run.error_message = f"Ошибки в {len(errors)} ящиках"
            elif truncated and run.mode == "dry_run":
                run.error_message = (
                    f"В {len(truncated)} ящиках найдено больше "
                    f"{SEARCH_LIMIT} сообщений. Показано не всё."
                )
            elif truncated:
                run.error_message = (
                    f"В {len(truncated)} ящиках после удаления остались "
                    "подходящие письма. Повторите проверку и очистку."
                )
            else:
                run.error_message = ""
            run.completed_at = completed_at
            run.progress_at = completed_at
            rule.last_run_at = completed_at
            rule.last_run_status = run.status
            self._audit(
                actor,
                "zimbra_mail_cleanup_run_completed",
                f"run:{run.id}",
                {
                    "rule_id": rule.id,
                    "mode": run.mode,
                    "status": run.status,
                    "checked_mailboxes": run.checked_mailboxes,
                    "found_messages": run.found_messages,
                    "deleted_messages": run.deleted_messages,
                    "remaining_messages": run.remaining_messages,
                    "error_count": run.error_count,
                },
            )
        self.db.commit()
        for run in runs.values():
            self.db.refresh(run)
        return [runs[int(rule.id)] for rule in rules]

    def _fail_runs(
        self,
        rules: list[ZimbraMailRetentionRule],
        runs: dict[int, ZimbraMailCleanupRun],
        error: Exception,
        *,
        actor: str,
        started: float,
    ) -> list[ZimbraMailCleanupRun]:
        completed_at = utcnow()
        message = str(error)[:4000]
        for rule in rules:
            run = runs[int(rule.id)]
            run.status = "failed"
            run.error_count = 1
            run.error_message = message
            run.duration_ms = int((time.monotonic() - started) * 1000)
            run.completed_at = completed_at
            run.progress_at = completed_at
            rule.last_run_at = completed_at
            rule.last_run_status = "failed"
            self._audit(
                actor,
                "zimbra_mail_cleanup_run_failed",
                f"run:{run.id}",
                {"rule_id": rule.id, "mode": run.mode, "error": message},
            )
        self.db.commit()
        return [runs[int(rule.id)] for rule in rules]

    def _run_rules(
        self,
        rules: list[ZimbraMailRetentionRule],
        *,
        mode: str,
        trigger: str,
        actor: str,
        preview_run_id: int = 0,
        prepared_run_ids: dict[int, int] | None = None,
    ) -> list[ZimbraMailCleanupRun]:
        if mode not in {"dry_run", "manual_cleanup", "automatic_cleanup"}:
            raise ValueError("Неизвестный режим очистки Zimbra")
        delete = mode != "dry_run"
        if delete and self.settings.dry_run:
            raise RuntimeError("Глобальный DRY_RUN запрещает удаление сообщений")
        if not rules:
            return []
        prepared_runs: dict[int, ZimbraMailCleanupRun] | None = None
        if prepared_run_ids is not None:
            prepared_runs = {
                int(rule.id): self.db.get(
                    ZimbraMailCleanupRun,
                    int(prepared_run_ids[int(rule.id)]),
                )
                for rule in rules
            }
            if any(
                run is None or run.status != "queued"
                for run in prepared_runs.values()
            ):
                raise ValueError("Подготовленный запуск уже недоступен")
        if prepared_run_ids is None:
            self._ensure_no_active_runs()
        if not self._run_lock.acquire(blocking=False):
            raise RuntimeError("Проверка или очистка почты Zimbra уже выполняется")

        started = time.monotonic()
        if prepared_run_ids is None:
            runs = {
                int(rule.id): self._create_run(
                    rule,
                    mode=mode,
                    trigger=trigger,
                    actor=actor,
                    preview_run_id=preview_run_id,
                )
                for rule in rules
            }
        else:
            runs = prepared_runs
            now = utcnow()
            for run in runs.values():
                run.status = "running"
                run.started_at = now
                run.completed_at = None
                run.progress_at = now
                run.checked_mailboxes = 0
                run.processed_mailboxes = 0
                run.batch_checked_mailboxes = 0
                run.batch_processed_mailboxes = 0
                run.matched_mailboxes = 0
                run.found_messages = 0
                run.deleted_messages = 0
                run.remaining_messages = 0
                run.truncated_mailboxes = 0
                run.error_count = 0
                run.duration_ms = 0
                run.details_json = "[]"
                run.error_message = ""
                execution = self._execution(
                    next(rule for rule in rules if int(rule.id) == run.rule_id)
                )
                run.search_query = self.build_query(execution)
                run.search_cutoff_date = (
                    now.astimezone(
                        ZoneInfo(self.settings.app_timezone)
                    ).date()
                    - timedelta(days=execution.retention_days)
                )
        self.db.commit()
        try:
            zimbra = ZimbraService(self.settings)
            executions = [self._execution(rule) for rule in rules]
            # Полный cleanup может идти больше часа. Общий query-lock нужен
            # только для тяжелого `gaa -v`, которым строится исходный список
            # ящиков. Удерживать его на всех zmmailbox-командах нельзя: тогда
            # интерфейс регистрации не может проверить свободный логин, а
            # плановое наблюдение Zimbra ждет окончания всей очистки.
            with zimbra._query_lock:
                mailboxes = zimbra.list_user_mailboxes()
            mailbox_executions = {
                mailbox: [
                    execution
                    for execution in executions
                    if self._applies(mailbox, execution)
                ]
                for mailbox in mailboxes
            }
            mailbox_executions = {
                mailbox: values
                for mailbox, values in mailbox_executions.items()
                if values
            }
            applicable_counts = {
                execution.id: sum(
                    execution in values
                    for values in mailbox_executions.values()
                )
                for execution in executions
            }
            progress_at = utcnow()
            batch_mailbox_count = len(mailbox_executions)
            for rule in rules:
                run = runs[int(rule.id)]
                run.checked_mailboxes = applicable_counts[int(rule.id)]
                run.batch_checked_mailboxes = batch_mailbox_count
                run.progress_at = progress_at
            self.db.commit()
            results: list[MailboxResult] = []
            workers = max(
                1,
                min(
                    int(self.settings.zimbra_mail_cleanup_workers),
                    len(mailbox_executions) or 1,
                ),
            )
            with ThreadPoolExecutor(
                max_workers=workers,
                thread_name_prefix="zimbra-mail-cleanup",
            ) as pool:
                batch_processed_mailboxes = 0
                futures = [
                    pool.submit(
                        self._process_mailbox,
                        zimbra,
                        mailbox,
                        values,
                        delete=delete,
                    )
                    for mailbox, values in mailbox_executions.items()
                ]
                for future in as_completed(futures):
                    mailbox_results = future.result()
                    results.extend(mailbox_results)
                    batch_processed_mailboxes += 1
                    progress_at = utcnow()
                    for run in runs.values():
                        run.batch_processed_mailboxes = (
                            batch_processed_mailboxes
                        )
                    for result in mailbox_results:
                        run = runs[result.rule_id]
                        run.processed_mailboxes += 1
                        run.matched_mailboxes += int(result.found > 0)
                        run.found_messages += result.found
                        run.deleted_messages += result.deleted
                        run.remaining_messages += result.remaining
                        run.truncated_mailboxes += int(result.truncated)
                        run.error_count += int(bool(result.error))
                        run.duration_ms = int(
                            (time.monotonic() - started) * 1000
                        )
                        run.progress_at = progress_at
                    self.db.commit()
            return self._finish_runs(
                rules,
                runs,
                results,
                applicable_counts,
                started=started,
                actor=actor,
            )
        except Exception as exc:
            self.db.rollback()
            # После rollback заново получаем уже сохраненные строки запусков.
            runs = {
                rule_id: self.db.get(ZimbraMailCleanupRun, run.id)
                for rule_id, run in runs.items()
            }
            return self._fail_runs(
                rules,
                runs,
                exc,
                actor=actor,
                started=started,
            )
        finally:
            self._run_lock.release()

    def dry_run(self, rule_id: int, *, actor: str) -> ZimbraMailCleanupRun:
        rule = self.get_rule(rule_id)
        return self._run_rules(
            [rule],
            mode="dry_run",
            trigger="manual",
            actor=actor,
        )[0]

    def dry_run_unverified(
        self,
        *,
        actor: str,
    ) -> list[ZimbraMailCleanupRun]:
        rules = self.unverified_rules()
        if not rules:
            raise ValueError("Новых или изменённых правил для проверки нет")
        return self._run_rules(
            rules,
            mode="dry_run",
            trigger="manual_batch",
            actor=actor,
        )

    def manual_cleanup(
        self,
        rule_id: int,
        *,
        preview_run_id: int,
        actor: str,
    ) -> ZimbraMailCleanupRun:
        rule = self.get_rule(rule_id)
        preview = self._validated_preview(rule, preview_run_id)
        return self._run_rules(
            [rule],
            mode="manual_cleanup",
            trigger="manual",
            actor=actor,
            preview_run_id=preview.id,
        )[0]

    def scheduled_cleanup(
        self,
        *,
        actor: str = "system",
        now: datetime | None = None,
    ) -> list[ZimbraMailCleanupRun]:
        rules = list(
            self.db.scalars(
                select(ZimbraMailRetentionRule)
                .where(
                    ZimbraMailRetentionRule.deleted_at.is_(None),
                    ZimbraMailRetentionRule.enabled.is_(True),
                    ZimbraMailRetentionRule.automatic_cleanup.is_(True),
                )
                .order_by(ZimbraMailRetentionRule.id)
            ).all()
        )
        if not rules:
            completed_at = as_utc(now) or utcnow()
            run = ZimbraMailCleanupRun(
                rule_id=0,
                rule_name="Недельная очистка",
                mode="automatic_cleanup",
                trigger="scheduled",
                status="skipped",
                initiated_by=actor,
                error_message="Нет включённых правил с автоочисткой",
                started_at=completed_at,
                completed_at=completed_at,
                progress_at=completed_at,
            )
            self.db.add(run)
            self.db.flush()
            self._audit(
                actor,
                "zimbra_mail_cleanup_run_skipped",
                f"run:{run.id}",
                {"reason": "no_automatic_rules"},
            )
            self.db.commit()
            self.db.refresh(run)
            return [run]
        return self._run_rules(
            rules,
            mode="automatic_cleanup",
            trigger="scheduled",
            actor=actor,
        )

    def weekly_schedule_decision(
        self,
        *,
        now: datetime | None = None,
    ) -> WeeklyScheduleDecision:
        config = self.get_settings_record()
        tz = ZoneInfo(self.settings.app_timezone)
        current = (as_utc(now) or utcnow()).astimezone(tz)
        if config.schedule_mode != "weekly":
            return WeeklyScheduleDecision(
                enabled=False,
                due=False,
                current=current,
                due_at=None,
                next_run_at=None,
                reason="Выбран режим «Только вручную»",
            )
        hour, minute = (int(part) for part in config.schedule_time.split(":", 1))
        days_since_weekday = (
            current.weekday() - int(config.schedule_weekday)
        ) % 7
        due_date = current.date() - timedelta(days=days_since_weekday)
        due = datetime.combine(
            due_date,
            dt_time(hour=hour, minute=minute),
            tzinfo=tz,
        )
        if due > current:
            due -= timedelta(days=7)
        next_weekly_run = due + timedelta(days=7)
        changed_at = (
            as_utc(
                config.schedule_changed_at
                or config.updated_at
                or config.created_at
            )
            or utcnow()
        ).astimezone(tz)
        current_label = WEEKDAY_LABELS[current.weekday()].lower()
        if due < changed_at:
            return WeeklyScheduleDecision(
                enabled=True,
                due=False,
                current=current,
                due_at=due,
                next_run_at=next_weekly_run,
                reason=(
                    f"Сейчас {current_label}, {current:%d.%m.%Y %H:%M}. "
                    "Ближайший срок по сохранённому расписанию ещё не наступил"
                ),
            )
        latest = self.db.scalars(
            select(ZimbraMailCleanupRun)
            .where(ZimbraMailCleanupRun.trigger == "scheduled")
            .order_by(
                desc(ZimbraMailCleanupRun.started_at),
                desc(ZimbraMailCleanupRun.id),
            )
            .limit(1)
        ).first()
        started = as_utc(latest.started_at) if latest is not None else None
        if started is None or started.astimezone(tz) < due:
            return WeeklyScheduleDecision(
                enabled=True,
                due=True,
                current=current,
                due_at=due,
                next_run_at=due,
                reason=(
                    f"Наступил недельный срок: "
                    f"{WEEKDAY_LABELS[int(config.schedule_weekday)]}, "
                    f"{due:%d.%m.%Y %H:%M} ({self.settings.app_timezone})"
                ),
            )
        if latest.status == "failed":
            finished = as_utc(latest.completed_at) or started
            retry_at = finished + timedelta(
                minutes=SCHEDULE_FAILURE_RETRY_MINUTES
            )
            retry_local = retry_at.astimezone(tz)
            retry_due = current.astimezone(timezone.utc) >= retry_at
            return WeeklyScheduleDecision(
                enabled=True,
                due=retry_due,
                current=current,
                due_at=due,
                next_run_at=current if retry_due else retry_local,
                reason=(
                    f"Запуск #{latest.id} завершился ошибкой; "
                    + (
                        "разрешён повторный запуск"
                        if retry_due
                        else f"повтор в {retry_local:%d.%m.%Y %H:%M}"
                    )
                ),
                latest_run_id=int(latest.id),
                latest_run_status=latest.status,
            )
        return WeeklyScheduleDecision(
            enabled=True,
            due=False,
            current=current,
            due_at=due,
            next_run_at=next_weekly_run,
            reason=(
                f"Недельный срок уже обработан запуском #{latest.id} "
                f"со статусом «{latest.status}»"
            ),
            latest_run_id=int(latest.id),
            latest_run_status=latest.status,
        )

    def weekly_due(self, *, now: datetime | None = None) -> bool:
        return self.weekly_schedule_decision(now=now).due

    def run_weekly_if_due(
        self,
        *,
        now: datetime | None = None,
    ) -> list[ZimbraMailCleanupRun]:
        if not self.weekly_due(now=now):
            return []
        return self.scheduled_cleanup(actor="system", now=now)

    def recent_runs(self, *, limit: int = 30) -> list[ZimbraMailCleanupRun]:
        return list(
            self.db.scalars(
                select(ZimbraMailCleanupRun)
                .order_by(
                    desc(ZimbraMailCleanupRun.started_at),
                    desc(ZimbraMailCleanupRun.id),
                )
                .limit(max(1, int(limit)))
            ).all()
        )

    def get_run(self, run_id: int) -> ZimbraMailCleanupRun | None:
        return self.db.get(ZimbraMailCleanupRun, int(run_id))

    @staticmethod
    def run_details(run: ZimbraMailCleanupRun | None) -> list[dict[str, object]]:
        if run is None:
            return []
        try:
            values = json.loads(run.details_json or "[]")
        except (TypeError, json.JSONDecodeError):
            return []
        return values if isinstance(values, list) else []

    def _audit(
        self,
        actor: str,
        action: str,
        target: str,
        details: dict[str, object],
    ) -> None:
        self.db.add(
            AuditLog(
                actor=str(actor or "")[:256],
                action=action,
                target=target,
                result="success",
                details=json.dumps(
                    details,
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            )
        )
