from __future__ import annotations

import shlex
import threading
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path

import paramiko

from app.config import Settings


@dataclass(frozen=True)
class ZimbraCreateResult:
    primary_email: str
    aliases: tuple[str, ...]


@dataclass(frozen=True)
class ZimbraAccountIdentity:
    zimbra_id: str
    primary_email: str
    login: str
    addresses: tuple[str, ...]
    account_status: str = ""


class BackgroundLoginCheckCancelled(RuntimeError):
    """Фоновая проверка альтернатив остановлена перед созданием учетных записей."""


class ZimbraService:
    # Результаты коротко кэшируются, чтобы фоновая проверка списка,
    # проверка выбранного логина и повторная проверка не запускали несколько
    # одинаковых JVM-процессов zmprov подряд.
    _CACHE_TTL_SECONDS = 45.0
    _cache_lock = threading.Lock()
    # Полные серверные обходы (`gaa -v`) сериализуются отдельно от быстрых
    # проверок логинов в интерфейсе регистрации. Долгая служебная операция не
    # должна делать форму создания учетной записи неработоспособной.
    _query_lock = threading.Lock()
    _login_query_lock = threading.Lock()
    _background_state_lock = threading.Lock()
    _background_cancel_event: threading.Event | None = None
    _login_cache: dict[
        tuple[str, int, tuple[str, ...], str],
        tuple[float, bool],
    ] = {}

    def __init__(self, settings: Settings):
        self.settings = settings

    @classmethod
    def begin_background_check(cls) -> threading.Event:
        """Начать новую фоновую проверку, отменив предыдущую."""
        with cls._background_state_lock:
            if cls._background_cancel_event is not None:
                cls._background_cancel_event.set()
            event = threading.Event()
            cls._background_cancel_event = event
            return event

    @classmethod
    def cancel_background_checks(cls) -> None:
        """Остановить текущую проверку альтернатив перед созданием учетных записей."""
        with cls._background_state_lock:
            if cls._background_cancel_event is not None:
                cls._background_cancel_event.set()

    @classmethod
    def finish_background_check(cls, event: threading.Event) -> None:
        with cls._background_state_lock:
            if cls._background_cancel_event is event:
                cls._background_cancel_event = None

    @staticmethod
    def _raise_if_cancelled(cancel_event: threading.Event | None) -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise BackgroundLoginCheckCancelled("Фоновая проверка альтернатив отменена")

    def _read_ssh_password(self) -> str:
        if self.settings.zimbra_ssh_password_file:
            password_file = Path(self.settings.zimbra_ssh_password_file)
            if not password_file.is_file():
                raise RuntimeError("Не найден файл с SSH-паролем Zimbra")
            password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
        else:
            password = self.settings.zimbra_ssh_password

        if not password:
            raise RuntimeError(
                "Не задан SSH-пароль Zimbra: укажите ZIMBRA_SSH_PASSWORD "
                "или ZIMBRA_SSH_PASSWORD_FILE"
            )
        return password

    def _resolve_ssh_auth(self) -> str:
        auth = self.settings.zimbra_ssh_auth
        if auth != "auto":
            return auth

        private_key = Path(self.settings.zimbra_ssh_private_key)
        if self.settings.zimbra_ssh_private_key and private_key.is_file():
            return "key"
        return "password"

    def _client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        known_hosts = Path(self.settings.zimbra_ssh_known_hosts)
        if not known_hosts.exists():
            raise RuntimeError("Не найден файл known_hosts для Zimbra")
        client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs: dict[str, object] = {
            "hostname": self.settings.zimbra_ssh_host,
            "port": self.settings.zimbra_ssh_port,
            "username": self.settings.zimbra_ssh_user,
            "look_for_keys": False,
            "allow_agent": False,
            "timeout": 10,
            "banner_timeout": 10,
            "auth_timeout": 10,
        }

        auth = self._resolve_ssh_auth()
        if auth == "key":
            private_key = Path(self.settings.zimbra_ssh_private_key)
            if not private_key.is_file():
                raise RuntimeError("Не найден закрытый SSH-ключ Zimbra")
            connect_kwargs["key_filename"] = str(private_key)
        elif auth == "password":
            connect_kwargs["password"] = self._read_ssh_password()
        else:
            raise RuntimeError(f"Неизвестный режим SSH-аутентификации Zimbra: {auth}")

        try:
            client.connect(**connect_kwargs)
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(15)
        except Exception:
            client.close()
            raise
        return client

    def _zmprov_command(self) -> str:
        # zmprov – Java-приложение. В неинтерактивной SSH-сессии locale
        # пользователя может не загружаться, из-за чего национальные символы
        # повреждаются при чтении команд из stdin. Явно фиксируем установленную на сервере locale ru_RU.utf8 для
        # каждого запуска, не изменяя глобальные настройки сервера.
        utf8_env = "/usr/bin/env LC_ALL=ru_RU.utf8 LANG=ru_RU.utf8"
        if self.settings.zimbra_ssh_user.strip().lower() == "zimbra":
            return f"{utf8_env} /opt/zimbra/bin/zmprov"
        return f"sudo -n -u zimbra {utf8_env} /opt/zimbra/bin/zmprov"

    def _zmmailbox_command(self) -> str:
        utf8_env = "/usr/bin/env LC_ALL=ru_RU.utf8 LANG=ru_RU.utf8"
        if self.settings.zimbra_ssh_user.strip().lower() == "zimbra":
            return f"{utf8_env} /opt/zimbra/bin/zmmailbox"
        return f"sudo -n -u zimbra {utf8_env} /opt/zimbra/bin/zmmailbox"

    @staticmethod
    def _read_remote_command(
        stdout,
        stderr,
        *,
        timeout: int,
    ) -> tuple[int, str, str]:
        """Вычитать stdout/stderr без риска заполнить SSH-буфер."""

        channel = stdout.channel
        deadline = time.monotonic() + max(1, int(timeout))
        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        while True:
            progressed = False
            while channel.recv_ready():
                out_chunks.append(channel.recv(65536))
                progressed = True
            while channel.recv_stderr_ready():
                err_chunks.append(channel.recv_stderr(65536))
                progressed = True
            if (
                channel.exit_status_ready()
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                break
            if time.monotonic() >= deadline:
                channel.close()
                raise RuntimeError("Превышено время ожидания команды Zimbra")
            if not progressed:
                time.sleep(0.05)

        return (
            channel.recv_exit_status(),
            b"".join(out_chunks).decode("utf-8", errors="replace").strip(),
            b"".join(err_chunks).decode("utf-8", errors="replace").strip(),
        )

    def execute_mailbox_command(
        self,
        client: paramiko.SSHClient,
        mailbox: str,
        args: list[str],
        *,
        timeout: int = 180,
        mutating: bool = False,
    ) -> str:
        """Выполнить одну штатную команду zmmailbox в открытом SSH-сеансе."""

        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")
        if mutating and self.settings.dry_run:
            return "DRY-RUN"
        normalized_mailbox = str(mailbox or "").strip().lower()
        if "@" not in normalized_mailbox:
            raise ValueError("Некорректный почтовый ящик Zimbra")
        command = (
            f"{self._zmmailbox_command()} -z -m "
            f"{shlex.quote(normalized_mailbox)} -t {max(1, int(timeout))} "
            f"{shlex.join(args)}"
        )
        stdin, stdout, stderr = client.exec_command(
            command,
            timeout=max(1, int(timeout)) + 10,
        )
        stdin.channel.shutdown_write()
        code, out, err = self._read_remote_command(
            stdout,
            stderr,
            timeout=max(1, int(timeout)) + 10,
        )
        if code != 0:
            raise RuntimeError(
                "zmmailbox завершился с ошибкой: "
                f"{err or out or f'код {code}'}"
            )
        return out

    def list_user_mailboxes(self) -> list[str]:
        """Получить пользовательские ящики только из настроенных доменов."""

        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")
        domains = {
            str(value or "").strip().lower()
            for value in self.settings.zimbra_domains
            if str(value or "").strip()
        }
        if not domains:
            raise RuntimeError(
                "Не заданы ZIMBRA_DOMAINS: безопасный список ящиков построить нельзя"
            )

        client = self._client()
        try:
            command = f"{self._zmprov_command()} -l gaa -v"
            stdin, stdout, stderr = client.exec_command(command, timeout=190)
            stdin.channel.shutdown_write()
            code, out, err = self._read_remote_command(
                stdout,
                stderr,
                timeout=190,
            )
            if code != 0:
                raise RuntimeError(
                    "Не удалось получить список ящиков Zimbra: "
                    f"{err or out or f'код {code}'}"
                )
        finally:
            client.close()

        system_local_parts = {
            "admin",
            "galsync",
            "ham",
            "mailer-daemon",
            "postmaster",
            "root",
            "spam",
            "virus-quarantine",
            "wiki",
        }
        system_prefixes = (
            "galsync.",
            "ham.",
            "spam.",
            "virus-quarantine.",
            "wiki.",
        )
        mailboxes: list[str] = []
        current_name = ""
        attrs: dict[str, list[str]] = {}

        def flush() -> None:
            nonlocal current_name, attrs
            primary = next(
                (
                    value.strip().lower()
                    for value in attrs.get("mail", [])
                    if value.strip()
                ),
                current_name.strip().lower(),
            )
            system_flag = any(
                value.strip().lower() == "true"
                for key in ("zimbraisystemresource", "zimbraisystemaccount")
                for value in attrs.get(key, [])
            )
            calendar_resource = any(
                value.strip()
                for value in attrs.get("zimbracalrestype", [])
            )
            if primary and "@" in primary and not system_flag and not calendar_resource:
                local, domain = primary.rsplit("@", 1)
                if (
                    domain in domains
                    and local not in system_local_parts
                    and not local.startswith(system_prefixes)
                    and primary not in mailboxes
                ):
                    mailboxes.append(primary)
            current_name = ""
            attrs = {}

        for raw_line in out.splitlines():
            line = raw_line.rstrip("\r\n")
            if line.startswith("# name "):
                flush()
                current_name = line[7:].strip()
            elif ":" in line:
                name, value = line.split(":", 1)
                attrs.setdefault(name.strip().lower(), []).append(value.strip())
        flush()
        return sorted(mailboxes)

    def _execute_zmprov(
        self,
        client: paramiko.SSHClient,
        args: list[str],
        allow_not_found: bool = False,
    ) -> str:
        stdin, stdout, stderr = client.exec_command(self._zmprov_command(), timeout=30)
        # Изменяющие команды передаем через stdin, чтобы пароль создаваемого
        # ящика не попадал в аргументы процесса и не был виден в ps.
        # Paramiko необходимо передавать готовые UTF-8 bytes.
        # При передаче Python str кириллица в некоторых версиях превращается
        # в младшие байты Unicode: «Тестов» -> «"5AB>2».
        payload = (shlex.join(args) + "\n").encode("utf-8")

        # Пишем непосредственно в SSH-канал, минуя текстовую файловую
        # обертку Paramiko. Так на удаленную сторону гарантированно уходят
        # именно подготовленные UTF-8 bytes без промежуточного преобразования.
        channel = stdin.channel
        channel.sendall(payload)
        channel.shutdown_write()

        code = channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        combined = f"{err}\n{out}"
        not_found = "NO_SUCH_ACCOUNT" in combined or "account.NO_SUCH_ACCOUNT" in combined

        if not_found:
            if allow_not_found:
                return out
            raise RuntimeError(err or out or "account.NO_SUCH_ACCOUNT")

        if code != 0:
            raise RuntimeError(f"zmprov завершился с кодом {code}: {err or out}")
        return out

    def _execute_zmprov_direct(
        self,
        client: paramiko.SSHClient,
        args: list[str],
        allow_not_found: bool = False,
    ) -> str:
        """Выполнить zmprov с аргументами командной строки.

        Этот режим применяется только для команд без паролей и других
        секретов. Он обходит интерактивный stdin-парсер zmprov, который на
        данном сервере повреждает кириллицу, несмотря на UTF-8 locale.
        """
        command = f"{self._zmprov_command()} {shlex.join(args)}"
        stdin, stdout, stderr = client.exec_command(command, timeout=30)
        stdin.channel.shutdown_write()

        code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        combined = f"{err}\n{out}"
        not_found = (
            "NO_SUCH_ACCOUNT" in combined
            or "account.NO_SUCH_ACCOUNT" in combined
        )

        if not_found:
            if allow_not_found:
                return out
            raise RuntimeError(err or out or "account.NO_SUCH_ACCOUNT")

        if code != 0:
            raise RuntimeError(f"zmprov завершился с кодом {code}: {err or out}")
        return out

    def _execute_zmprov_lookup(
        self,
        client: paramiko.SSHClient,
        args: list[str],
        *,
        cancel_event: threading.Event | None = None,
    ) -> str:
        self._raise_if_cancelled(cancel_event)
        command = f"{self._zmprov_command()} -l {shlex.join(args)}"
        stdin, stdout, stderr = client.exec_command(command, timeout=45)
        stdin.channel.shutdown_write()

        channel = stdout.channel
        deadline = time.monotonic() + 45.0
        while not channel.exit_status_ready():
            if cancel_event is not None and cancel_event.is_set():
                channel.close()
                raise BackgroundLoginCheckCancelled(
                    "Фоновая проверка альтернатив отменена"
                )
            if time.monotonic() >= deadline:
                channel.close()
                raise RuntimeError("Превышено время ожидания ответа zmprov")
            time.sleep(0.05)

        code = channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        combined = f"{err}\n{out}"

        if "NO_SUCH_ACCOUNT" in combined or "account.NO_SUCH_ACCOUNT" in combined:
            raise RuntimeError(err or out or "account.NO_SUCH_ACCOUNT")
        if code != 0:
            raise RuntimeError(f"zmprov завершился с кодом {code}: {err or out}")
        return out

    def _run_zmprov(
        self,
        args: list[str],
        allow_not_found: bool = False,
        mutating: bool = True,
    ) -> str:
        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")
        if mutating and self.settings.dry_run:
            return "DRY-RUN"

        client = self._client()
        try:
            return self._execute_zmprov(client, args, allow_not_found=allow_not_found)
        finally:
            client.close()

    def _run_zmprov_direct(
        self,
        args: list[str],
        allow_not_found: bool = False,
        mutating: bool = True,
    ) -> str:
        """Запустить команду без секретов через обычные аргументы процесса."""
        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")
        if mutating and self.settings.dry_run:
            return "DRY-RUN"

        client = self._client()
        try:
            return self._execute_zmprov_direct(
                client,
                args,
                allow_not_found=allow_not_found,
            )
        finally:
            client.close()

    @staticmethod
    def _is_not_found_error(exc: RuntimeError) -> bool:
        message = str(exc)
        return "NO_SUCH_ACCOUNT" in message or "account.NO_SUCH_ACCOUNT" in message

    @staticmethod
    def _escape_ldap_filter_value(value: str) -> str:
        return (
            value.replace("\\", r"\5c")
            .replace("*", r"\2a")
            .replace("(", r"\28")
            .replace(")", r"\29")
            .replace("\x00", r"\00")
        )

    def _cache_key(self, login: str) -> tuple[str, int, tuple[str, ...], str]:
        domains = tuple(domain.strip().lower() for domain in self.settings.zimbra_domains)
        return (
            self.settings.zimbra_ssh_host.strip().lower(),
            self.settings.zimbra_ssh_port,
            domains,
            login.strip().lower(),
        )

    def _cache_get(self, login: str) -> bool | None:
        key = self._cache_key(login)
        now = time.monotonic()
        with self._cache_lock:
            cached = self._login_cache.get(key)
            if cached is None:
                return None
            stored_at, exists = cached
            if now - stored_at > self._CACHE_TTL_SECONDS:
                self._login_cache.pop(key, None)
                return None
            return exists

    def _cache_set(self, login: str, exists: bool) -> None:
        key = self._cache_key(login)
        with self._cache_lock:
            self._login_cache[key] = (time.monotonic(), exists)

    def _cache_remove(self, login: str) -> None:
        key = self._cache_key(login)
        with self._cache_lock:
            self._login_cache.pop(key, None)

    def _search_existing_logins(
        self,
        client: paramiko.SSHClient,
        logins: list[str],
        *,
        cancel_event: threading.Event | None = None,
    ) -> set[str]:
        """Найти все занятые логины одним запуском zmprov.

        searchAccounts выполняет один LDAP-запрос по всем первичным адресам
        и алиасам. Это заменяет до N*D отдельных запусков `zmprov -l ga`.
        """
        address_to_login: dict[str, str] = {}
        clauses: list[str] = []

        for login in logins:
            for domain in self.settings.zimbra_domains:
                email = f"{login}@{domain}".lower()
                address_to_login[email] = login
                escaped = self._escape_ldap_filter_value(email)
                clauses.extend(
                    [
                        f"(mail={escaped})",
                        f"(zimbraMailAlias={escaped})",
                        f"(zimbraMailDeliveryAddress={escaped})",
                    ]
                )

        if not clauses:
            return set()

        ldap_query = f"(|{''.join(clauses)})"
        # Число найденных объектов не может быть больше числа проверяемых
        # адресов, но небольшой запас полезен при нескольких совпадениях.
        limit = max(20, min(len(address_to_login) * 2, 500))
        output = self._execute_zmprov_lookup(
            client,
            ["sa", "-v", ldap_query, "limit", str(limit)],
            cancel_event=cancel_event,
        )

        existing: set[str] = set()
        interesting_attributes = {
            "mail",
            "zimbramailalias",
            "zimbramaildeliveryaddress",
            "name",
        }

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            value = ""
            lower_line = line.lower()
            if lower_line.startswith("# name "):
                value = line[7:].strip()
            elif ":" in line:
                attribute, candidate_value = line.split(":", 1)
                if attribute.strip().lower() in interesting_attributes:
                    value = candidate_value.strip()

            normalized_value = value.lower()
            login = address_to_login.get(normalized_value)
            if login:
                existing.add(login)

        return existing

    def _fallback_existing_logins(
        self,
        client: paramiko.SSHClient,
        logins: list[str],
        *,
        cancel_event: threading.Event | None = None,
    ) -> set[str]:
        """Совместимый запасной способ для старых сборок Zimbra."""
        existing: set[str] = set()
        for login in logins:
            self._raise_if_cancelled(cancel_event)
            for domain in self.settings.zimbra_domains:
                self._raise_if_cancelled(cancel_event)
                email = f"{login}@{domain}"
                try:
                    self._execute_zmprov_lookup(
                        client,
                        ["ga", email, "zimbraId"],
                        cancel_event=cancel_event,
                    )
                    existing.add(login)
                    break
                except RuntimeError as exc:
                    if self._is_not_found_error(exc):
                        continue
                    raise
        return existing

    def test_connection(self) -> str:
        """Проверить SSH и выполнение безопасной команды zmprov."""
        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")

        client = self._client()
        try:
            output = self._execute_zmprov_direct(
                client,
                ["gcf", "zimbraDefaultDomainName"],
            )
        finally:
            client.close()

        for line in output.splitlines():
            if line.lower().startswith("zimbradefaultdomainname:"):
                domain = line.split(":", 1)[1].strip()
                if domain:
                    return f"SSH и zmprov доступны. Основной домен Zimbra: {domain}"
        return "SSH и zmprov доступны"

    def address_exists(self, email: str) -> bool:
        if not self.settings.zimbra_check_enabled:
            return False
        try:
            client = self._client()
            try:
                self._execute_zmprov_lookup(client, ["ga", email, "zimbraId"])
            finally:
                client.close()
            return True
        except RuntimeError as exc:
            if self._is_not_found_error(exc):
                return False
            raise

    @staticmethod
    def _parse_search_accounts(
        output: str,
    ) -> list[ZimbraAccountIdentity]:
        """Разобрать `zmprov sa -v` в карточки Zimbra."""
        accounts: list[ZimbraAccountIdentity] = []
        current_name = ""
        attrs: dict[str, list[str]] = {}

        def flush() -> None:
            nonlocal current_name, attrs
            if not current_name and not attrs:
                return

            zimbra_id = ""
            primary_email = ""
            addresses: list[str] = []

            for value in attrs.get("zimbraid", []):
                if value.strip():
                    zimbra_id = value.strip()
                    break

            mail_values = attrs.get("mail", [])
            if mail_values:
                primary_email = mail_values[0].strip().lower()

            if not primary_email and current_name:
                primary_email = current_name.strip().lower()

            for key in (
                "mail",
                "zimbramailalias",
                "zimbramaildeliveryaddress",
            ):
                for value in attrs.get(key, []):
                    normalized = value.strip().lower()
                    if normalized and normalized not in addresses:
                        addresses.append(normalized)

            if primary_email and primary_email not in addresses:
                addresses.insert(0, primary_email)

            account_status = ""
            for value in attrs.get("zimbraaccountstatus", []):
                if value.strip():
                    account_status = value.strip().lower()
                    break

            if zimbra_id and primary_email:
                login = primary_email.split("@", 1)[0].lower()
                accounts.append(
                    ZimbraAccountIdentity(
                        zimbra_id=zimbra_id,
                        primary_email=primary_email,
                        login=login,
                        addresses=tuple(addresses),
                        account_status=account_status,
                    )
                )

            current_name = ""
            attrs = {}

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.lower().startswith("# name "):
                flush()
                current_name = line[7:].strip()
                continue

            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            attrs.setdefault(key.strip().lower(), []).append(value.strip())

        flush()
        return accounts

    def _search_accounts(
        self,
        ldap_query: str,
        *,
        expected_count: int,
    ) -> list[ZimbraAccountIdentity]:
        client = self._client()
        try:
            output = self._execute_zmprov_lookup(
                client,
                [
                    "sa",
                    "-v",
                    ldap_query,
                    "limit",
                    str(max(20, min(expected_count * 2, 500))),
                ],
            )
            return self._parse_search_accounts(output)
        finally:
            client.close()

    def accounts_by_addresses(
        self,
        emails: list[str],
    ) -> dict[str, ZimbraAccountIdentity]:
        """Разрешить e-mail/alias в стабильную карточку Zimbra пакетно."""
        if not self.settings.zimbra_check_enabled:
            return {}
        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")

        normalized = list(
            dict.fromkeys(
                email.strip().lower()
                for email in emails
                if email.strip() and "@" in email
            )
        )
        if not normalized:
            return {}

        result: dict[str, ZimbraAccountIdentity] = {}
        for offset in range(0, len(normalized), 50):
            chunk = normalized[offset:offset + 50]
            clauses: list[str] = []
            for address in chunk:
                escaped = self._escape_ldap_filter_value(address)
                clauses.extend(
                    [
                        f"(mail={escaped})",
                        f"(zimbraMailAlias={escaped})",
                        f"(zimbraMailDeliveryAddress={escaped})",
                    ]
                )
            accounts = self._search_accounts(
                f"(|{''.join(clauses)})",
                expected_count=len(chunk),
            )
            for account in accounts:
                for address in account.addresses:
                    if address in chunk:
                        result[address] = account
        return result

    def accounts_by_ids(
        self,
        zimbra_ids: list[str],
    ) -> dict[str, ZimbraAccountIdentity]:
        """Получить Zimbra-карточки по стабильным zimbraId пакетно."""
        if not self.settings.zimbra_check_enabled:
            return {}
        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")

        normalized = list(
            dict.fromkeys(
                str(value or "").strip()
                for value in zimbra_ids
                if str(value or "").strip()
            )
        )
        if not normalized:
            return {}

        result: dict[str, ZimbraAccountIdentity] = {}
        for offset in range(0, len(normalized), 100):
            chunk = normalized[offset:offset + 100]
            clauses = [
                f"(zimbraId={self._escape_ldap_filter_value(value)})"
                for value in chunk
            ]
            accounts = self._search_accounts(
                f"(|{''.join(clauses)})",
                expected_count=len(chunk),
            )
            for account in accounts:
                if account.zimbra_id in chunk:
                    result[account.zimbra_id] = account
        return result

    def account_by_address(
        self,
        email: str,
    ) -> ZimbraAccountIdentity | None:
        normalized = str(email or "").strip().lower()
        if not normalized:
            return None
        return self.accounts_by_addresses([normalized]).get(normalized)

    def addresses_exist(self, emails: list[str]) -> set[str]:
        return set(self.accounts_by_addresses(emails))


    def logins_exist_any_domain(
        self,
        logins: list[str],
        *,
        force_refresh: bool = False,
        background: bool = False,
    ) -> set[str]:
        if not self.settings.zimbra_check_enabled:
            return set()
        if self.settings.zimbra_backend == "disabled":
            raise RuntimeError("Zimbra backend отключен")

        normalized = list(
            dict.fromkeys(
                login.strip().lower()
                for login in logins
                if login.strip()
            )
        )
        if not normalized:
            return set()

        existing: set[str] = set()
        missing: list[str] = []

        if force_refresh:
            # Явная кнопка «Проверить снова» и итоговая проверка перед
            # созданием должны видеть внешние удаления немедленно, не ожидая
            # окончания короткого кэша Zimbra.
            missing = list(normalized)
        else:
            for login in normalized:
                cached = self._cache_get(login)
                if cached is None:
                    missing.append(login)
                elif cached:
                    existing.add(login)

        if not missing:
            return existing

        cancel_event = self.begin_background_check() if background else None

        def execute_query() -> set[str]:
            self._raise_if_cancelled(cancel_event)

            still_missing: list[str] = []
            if force_refresh:
                still_missing = list(missing)
            else:
                for login in missing:
                    cached = self._cache_get(login)
                    if cached is None:
                        still_missing.append(login)
                    elif cached:
                        existing.add(login)

            if not still_missing:
                return existing

            client = self._client()
            try:
                try:
                    found = self._search_existing_logins(
                        client,
                        still_missing,
                        cancel_event=cancel_event,
                    )
                except BackgroundLoginCheckCancelled:
                    raise
                except RuntimeError:
                    # Старые или измененные сборки Zimbra могут не принимать
                    # searchAccounts в ожидаемом виде. В этом случае сохраняем
                    # прежний надежный способ проверки.
                    found = self._fallback_existing_logins(
                        client,
                        still_missing,
                        cancel_event=cancel_event,
                    )
            finally:
                client.close()

            self._raise_if_cancelled(cancel_event)
            for login in still_missing:
                is_existing = login in found
                self._cache_set(login, is_existing)
                if is_existing:
                    existing.add(login)

            return existing

        try:
            if force_refresh and not background:
                # Финальная проверка выбранного логина имеет приоритет и не
                # ожидает завершения полного списка альтернатив.
                return execute_query()

            # Фоновые проверки логинов объединяем между собой, но не ставим
            # их в очередь за полным обходом ящиков или почтовой очисткой.
            while not self._login_query_lock.acquire(timeout=0.1):
                self._raise_if_cancelled(cancel_event)
            try:
                return execute_query()
            finally:
                self._login_query_lock.release()
        finally:
            if cancel_event is not None:
                self.finish_background_check(cancel_event)

    def login_exists_any_domain(
        self,
        login: str,
        *,
        force_refresh: bool = False,
    ) -> bool:
        normalized = login.strip().lower()
        return normalized in self.logins_exist_any_domain(
            [normalized],
            force_refresh=force_refresh,
            background=False,
        )

    def create_account(
        self,
        login: str,
        domain: str,
        password: str,
        last_name: str,
        first_name: str,
        middle_name: str,
    ) -> ZimbraCreateResult:
        primary_domain = (
            self.settings.zimbra_primary_domain
            if self.settings.zimbra_domain_mode == "primary_alias"
            else domain
        )
        primary_email = f"{login}@{primary_domain}"
        display_name = " ".join(
            part for part in [last_name, first_name, middle_name] if part
        )

        # Пароль остается вне аргументов процесса: создание ящика передаем
        # через stdin. На этом этапе используются только ASCII-значения.
        create_args = ["ca", primary_email, password]
        if self.settings.zimbra_cos_id:
            create_args.extend(["zimbraCOSId", self.settings.zimbra_cos_id])
        self._run_zmprov(create_args)

        # Кириллические атрибуты передаем отдельной обычной командой `ma`.
        # Ручная проверка на сервере подтвердила, что именно этот режим с
        # ru_RU.utf8 сохраняет русские буквы корректно.
        profile_args = [
            "ma",
            primary_email,
            "displayName",
            display_name,
            "zimbraPrefFromDisplay",
            display_name,
            "givenName",
            first_name,
        ]
        if middle_name:
            # В учетной записи Zimbra поле Middle Name / Отчество
            # хранится в стандартном LDAP-атрибуте initials.
            profile_args.extend(["initials", middle_name])
        profile_args.extend(["sn", last_name])

        try:
            self._run_zmprov_direct(profile_args)
        except Exception as profile_exc:
            # После разделения команд не оставляем пустой тестовый ящик,
            # если запись ФИО завершилась ошибкой.
            if not self.settings.dry_run:
                try:
                    self._run_zmprov_direct(["da", primary_email])
                except Exception as rollback_exc:
                    raise RuntimeError(
                        "Ящик создан, но ФИО не записано; также не удалось "
                        f"удалить неполную учетную запись: {rollback_exc}"
                    ) from profile_exc
            raise

        aliases: list[str] = []
        if (
            self.settings.zimbra_domain_mode == "primary_alias"
            and self.settings.zimbra_create_aliases
        ):
            for alias_domain in self.settings.zimbra_domains:
                alias = f"{login}@{alias_domain}"
                if alias.lower() == primary_email.lower():
                    continue
                self._run_zmprov(["aaa", primary_email, alias])
                aliases.append(alias)

        if not self.settings.dry_run:
            self._cache_set(login, True)

        return ZimbraCreateResult(
            primary_email=primary_email,
            aliases=tuple(aliases),
        )

    def delete_account(self, email: str) -> None:
        self._run_zmprov(["da", email])
        login = email.split("@", 1)[0].strip().lower()
        if login:
            self._cache_remove(login)

    def close_account(self, email: str) -> None:
        """Перевести учетную запись Zimbra в штатный статус closed / «Закрыта»."""
        normalized = str(email or "").strip().lower()
        if not normalized or "@" not in normalized:
            raise ValueError("Не передан адрес учетной записи Zimbra")
        if self.settings.dry_run:
            return
        self._run_zmprov_direct(
            ["ma", normalized, "zimbraAccountStatus", "closed"]
        )

    def open_account(self, email: str) -> None:
        """Вернуть закрытый ящик Zimbra в штатный статус active."""

        normalized = str(email or "").strip().lower()
        if not normalized or "@" not in normalized:
            raise ValueError("Не передан адрес учетной записи Zimbra")
        if self.settings.dry_run:
            return
        self._run_zmprov_direct(
            ["ma", normalized, "zimbraAccountStatus", "active"]
        )

    def remove_alias(self, primary_email: str, alias: str) -> None:
        """Удалить только организационный alias, не затрагивая сам ящик."""
        primary = str(primary_email or "").strip().lower()
        normalized_alias = str(alias or "").strip().lower()
        if not primary or "@" not in primary:
            raise ValueError("Не передан основной адрес учетной записи Zimbra")
        if not normalized_alias or "@" not in normalized_alias:
            raise ValueError("Не передан удаляемый alias Zimbra")
        if primary == normalized_alias:
            raise ValueError("Основной адрес нельзя удалить как alias")
        if self.settings.dry_run:
            return
        self._run_zmprov_direct(["raa", primary, normalized_alias])

    def lock_account(self, email: str) -> None:
        """Совместимость со старым вызовом: блокировка теперь означает «Закрыта»."""
        self.close_account(email)

    def set_dismissal_note(self, email: str, dismissal_date: date) -> None:
        self._run_zmprov(
            ["ma", email, "zimbraNotes", dismissal_date.strftime("%d.%m.%Y")]
        )
