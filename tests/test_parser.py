from modules import parser


def test_parses_headers_and_body(sample_dir):
    with open(f"{sample_dir}/phishing_sample.eml", 'rb') as f:
        raw = f.read()
    parsed = parser.parse_email(raw)

    assert parsed['subject'] == 'Urgent: Your account has been suspended'
    assert 'paypa1-secure.com' in parsed['sender_domain']
    assert 'Verify Now' in parsed['body_plain']


def test_extracts_originating_ip_from_received_chain(sample_dir):
    with open(f"{sample_dir}/phishing_sample.eml", 'rb') as f:
        raw = f.read()
    parsed = parser.parse_email(raw)
    assert parsed['originating_ip'] == '185.220.101.45'


def test_extracts_urls_from_body():
    urls = parser.extract_urls("Click here http://bit.ly/verify-paypal-acct now")
    assert 'http://bit.ly/verify-paypal-acct' in urls


def test_private_ip_detection():
    assert parser._is_private_ip('192.168.1.1') is True
    assert parser._is_private_ip('127.0.0.1') is True
    assert parser._is_private_ip('8.8.8.8') is False


def test_handles_minimal_email_without_crashing():
    raw = b"From: a@example.com\nTo: b@example.com\nSubject: Hi\n\nHello there."
    parsed = parser.parse_email(raw)
    assert parsed['subject'] == 'Hi'
