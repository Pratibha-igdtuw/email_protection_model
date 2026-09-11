"""
USP 6 upgrade: Gmail OAuth2 integration, replacing the app-password/IMAP
approach with the real Gmail API + OAuth2 authorization-code flow for
Gmail accounts. This is the fix for "Mailbox integration uses app
passwords over IMAP, not OAuth -- a real limitation for Gmail/Outlook
at scale": app passwords require the *user* to go generate one manually
outside the app, don't support fine-grained/revocable scopes, and Google
is steadily tightening "less secure app" access. OAuth fixes all three:
standard consent screen, revocable from the user's Google Account at any
time, and scoped to read-only mail access (`gmail.readonly`) only.

Outlook/Exchange still use the IMAP app-password path in
modules/mailbox_connector.py -- Microsoft Graph OAuth (via `msal`) is the
same shape of upgrade and is the natural next step (see README "Adding
Microsoft OAuth"), but is not wired up here to keep this change reviewable.

Setup (see README "Gmail OAuth setup" for the full walkthrough):
  1. Create a project in Google Cloud Console, enable the Gmail API.
  2. Create an OAuth 2.0 Client ID (type: Web application) with an
     authorized redirect URI matching GOOGLE_OAUTH_REDIRECT_URI below.
  3. Set these env vars before running the app:
       GOOGLE_OAUTH_CLIENT_ID
       GOOGLE_OAUTH_CLIENT_SECRET
       GOOGLE_OAUTH_REDIRECT_URI   (e.g. https://yourhost/connect-mailbox/oauth/callback)

If these env vars are not set, `is_configured()` returns False and the app
falls back to offering only the IMAP app-password path for Gmail too, so
the feature degrades gracefully rather than crashing on missing config.
"""
import os
from datetime import datetime, timedelta

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def is_configured():
    return bool(
        os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
        and os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')
        and os.environ.get('GOOGLE_OAUTH_REDIRECT_URI')
    )


def _client_config():
    return {
        "web": {
            "client_id": os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
            "client_secret": os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [os.environ.get('GOOGLE_OAUTH_REDIRECT_URI')],
        }
    }


def build_auth_url(state):
    """Returns the Google consent-screen URL to redirect the user to."""
    from google_auth_oauthlib.flow import Flow

    flow = Flow.from_client_config(_client_config(), scopes=SCOPES,
                                    redirect_uri=os.environ.get('GOOGLE_OAUTH_REDIRECT_URI'))
    auth_url, _ = flow.authorization_url(
        access_type='offline',       # needed to get a refresh_token
        include_granted_scopes='true',
        prompt='consent',            # force a refresh_token on every connect
        state=state,
    )
    return auth_url


def exchange_code_for_token(code):
    """Exchanges the authorization code from the OAuth callback for
    credentials. Returns a dict ready to persist in MailboxOAuthToken."""
    from google_auth_oauthlib.flow import Flow

    flow = Flow.from_client_config(_client_config(), scopes=SCOPES,
                                    redirect_uri=os.environ.get('GOOGLE_OAUTH_REDIRECT_URI'))
    flow.fetch_token(code=code)
    creds = flow.credentials
    return _creds_to_dict(creds)


def _creds_to_dict(creds):
    return {
        'access_token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_expiry': creds.expiry,
        'scope': ' '.join(creds.scopes or SCOPES),
    }


def _credentials_from_token_row(token_row):
    from google.oauth2.credentials import Credentials

    return Credentials(
        token=token_row.access_token,
        refresh_token=token_row.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
        client_secret=os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
        scopes=(token_row.scope or '').split() or SCOPES,
    )


def get_mailbox_email(token_row):
    """Fetches the connected Gmail address (for display), refreshing the
    access token first if it has expired."""
    creds, refreshed = _refresh_if_needed(token_row)
    from googleapiclient.discovery import build

    service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
    profile = service.users().getProfile(userId='me').execute()
    return profile.get('emailAddress'), refreshed


def _refresh_if_needed(token_row):
    from google.auth.transport.requests import Request

    creds = _credentials_from_token_row(token_row)
    refreshed = None
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        refreshed = _creds_to_dict(creds)
    return creds, refreshed


def fetch_recent_emails(token_row, limit=10):
    """
    Fetches the `limit` most recent Gmail messages via the Gmail API
    (read-only scope) and returns their raw RFC822 bytes -- same shape as
    modules.mailbox_connector.fetch_recent_emails, so the rest of the
    fetch -> preview -> analyze pipeline is unchanged.

    Returns: {'status': 'success', 'emails': [raw_bytes, ...], 'count': int,
              'refreshed_token': dict_or_None}
           or {'status': 'error', 'message': str}
    """
    import base64
    try:
        creds, refreshed = _refresh_if_needed(token_row)
        from googleapiclient.discovery import build

        service = build('gmail', 'v1', credentials=creds, cache_discovery=False)
        listing = service.users().messages().list(userId='me', maxResults=limit).execute()
        message_ids = [m['id'] for m in listing.get('messages', [])]

        raw_emails = []
        for mid in message_ids:
            msg = service.users().messages().get(userId='me', id=mid, format='raw').execute()
            raw_emails.append(base64.urlsafe_b64decode(msg['raw']))

        return {'status': 'success', 'emails': raw_emails, 'count': len(raw_emails),
                'refreshed_token': refreshed}
    except Exception as e:
        return {'status': 'error', 'message': f'Gmail API request failed: {e}'}
