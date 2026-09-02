from app.parser import parse_line


def test_lmtp_delivery():
    event = parse_line("Aug 31 22:25:03 mail postfix/lmtp[322563]: 508EF6922A46: to=<user@domain.ru>, relay=mail.domain.ru[10.0.10.4]:7025, delay=0.23, delays=0.01/0.01/0.01/0.2, dsn=2.1.5, status=sent (250 2.1.5 Delivery OK)", 2026)
    assert event and event.kind == "delivery"
    assert event.queue_id == "508EF6922A46"
    assert event.fields["to"] == "user@domain.ru"
    assert event.fields["relay_ip"] == "10.0.10.4"
    assert event.fields["reply"] == "250 2.1.5 Delivery OK"


def test_queue_link():
    event = parse_line("Sep  2 15:19:42 mail postfix/smtp[305528]: D31DF693C8CD: to=<u@example.ru>, relay=mx[10.0.10.176]:25, delay=0.94, delays=0.02/0/0.02/0.9, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as B6F8DE0016)", 2026)
    assert event and event.fields["child_queue_id"] == "B6F8DE0016"


def test_rejection_without_queue():
    event = parse_line("Sep  2 00:23:05 mail postfix/smtps/smtpd[1]: NOQUEUE: reject: RCPT from post.domain.ru[10.0.10.248]: 550 5.1.1 rejected; from=<noreply@domain.ru> to=<missing@domain.ru> proto=ESMTP helo=<host>", 2026)
    assert event and event.kind == "rejected"
    assert event.fields["client_ip"] == "10.0.10.248"
    assert event.fields["to"] == "missing@domain.ru"


def test_unrelated_line_is_ignored():
    assert parse_line("Sep  2 00:00:02 mail slapd[1]: housekeeping", 2026) is None

