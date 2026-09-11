"""
USP 6: Lightweight, API-based integration with existing Gmail/Outlook/Exchange
setups — no infrastructure overhaul needed.

Implementation note: full OAuth (Gmail API / Microsoft Graph) needs a
registered cloud app + client secret, which is a deployment-time setup step
for whoever hosts this platform. For a lightweight, drop-in integration that
works immediately against any existing mailbox, this uses standard IMAP
(imaplib, built into Python) with an app password — the same "no infra
overhaul" pitch, just over IMAP instead of a vendor-specific SDK.
To upgrade to full Gmail API / Microsoft Graph OAuth later, swap the
connection function bodies below; the rest of the pipeline (fetch -> analyze)
does not need to change.
"""
import imaplib
import email as email_lib

PROVIDER_IMAP_HOSTS = {
    'gmail': 'imap.gmail.com',
    'outlook': 'outlook.office365.com',
    'exchange': 'outlook.office365.com',  # Exchange Online uses the same endpoint
}


def fetch_recent_emails(provider, username, app_password, limit=10, mailbox='INBOX'):
    """
    Connects over IMAP and returns the raw bytes of the `limit` most recent
    emails. Requires an app password (Gmail: Google Account > App Passwords;
    Outlook/Exchange: enable IMAP + app password / modern auth token).

    Returns: {'status': 'success', 'emails': [raw_bytes, ...]} or
             {'status': 'error', 'message': str}
    """
    host = PROVIDER_IMAP_HOSTS.get(provider)
    if not host:
        return {'status': 'error', 'message': f"Unknown provider '{provider}'. Use gmail, outlook, or exchange."}

    try:
        imap = imaplib.IMAP4_SSL(host)
        imap.login(username, app_password)
        imap.select(mailbox)

        status, data = imap.search(None, 'ALL')
        if status != 'OK':
            return {'status': 'error', 'message': 'Could not search mailbox.'}

        msg_ids = data[0].split()
        recent_ids = msg_ids[-limit:] if len(msg_ids) > limit else msg_ids
        recent_ids.reverse()  # newest first

        raw_emails = []
        for mid in recent_ids:
            status, msg_data = imap.fetch(mid, '(RFC822)')
            if status == 'OK' and msg_data and msg_data[0]:
                raw_emails.append(msg_data[0][1])

        imap.logout()
        return {'status': 'success', 'emails': raw_emails, 'count': len(raw_emails)}

    except imaplib.IMAP4.error as e:
        return {'status': 'error', 'message': f'IMAP authentication/connection failed: {e}. '
                                                f'Make sure IMAP is enabled and you are using an app password, '
                                                f'not your normal login password.'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}


def quick_preview(raw_bytes):
    """Small helper to show Subject/From in a picker UI before full analysis."""
    msg = email_lib.message_from_bytes(raw_bytes)
    return {'subject': msg.get('Subject', '(no subject)'), 'from': msg.get('From', '(unknown sender)')}
