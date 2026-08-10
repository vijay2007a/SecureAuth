"""firebase_init.py — Shared Firebase Admin SDK initialisation.

This module is the single source of truth for initialising the Firebase
Admin SDK.  It is called by:

  - security.py  (token verification in AUTH_MODE=firebase)
  - store.py     (Firestore client setup)

It is safe to call multiple times — the function is idempotent.

Credential resolution order
---------------------------
1. GOOGLE_APPLICATION_CREDENTIALS  — path to a service-account JSON file
2. FIREBASE_PRIVATE_KEY + FIREBASE_CLIENT_EMAIL + FIREBASE_PROJECT_ID
   — individual env vars (typical for PaaS deployments such as Render)
3. Application Default Credentials (ADC) / GCE metadata server
   — works when running on Google Cloud or with
     ``gcloud auth application-default login`` locally

Private-key newline handling
-----------------------------
PaaS environments often escape real newlines as the two-character sequence
``\\n`` when the secret is stored as a single-line string.  We always
normalise by calling ``.replace("\\\\n", "\\n")`` so either format works.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


def init_firebase_app() -> None:
    """Initialise the Firebase Admin SDK.  Idempotent — safe to call many times."""
    try:
        import firebase_admin
        from firebase_admin import credentials
    except ImportError as exc:
        raise RuntimeError(
            "firebase-admin is not installed.  "
            "Add it to requirements.txt: firebase-admin>=6.0.0"
        ) from exc

    # Already initialised — nothing to do.
    if firebase_admin._apps:
        return

    project_id = os.getenv("FIREBASE_PROJECT_ID", "").strip()
    client_email = os.getenv("FIREBASE_CLIENT_EMAIL", "").strip()
    # Normalise \\n → real newlines so both raw multi-line and
    # single-line-escaped variants work.
    private_key = os.getenv("FIREBASE_PRIVATE_KEY", "").replace("\\n", "\n").strip()
    private_key_id = os.getenv("FIREBASE_PRIVATE_KEY_ID", "key1").strip()
    client_id = os.getenv("FIREBASE_CLIENT_ID", "").strip()
    cred_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "").strip()

    extra: dict = {"projectId": project_id} if project_id else {}

    if cred_path:
        # Path to a downloaded service-account JSON file.
        logger.info("Firebase Admin: initialising from GOOGLE_APPLICATION_CREDENTIALS file")
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred, extra)

    elif client_email and private_key and project_id:
        # Individual env vars — typical for Render / Railway / Fly.io.
        logger.info(
            "Firebase Admin: initialising from FIREBASE_* env vars "
            "(project=%s, email=%s)", project_id, client_email
        )
        service_account = {
            "type": "service_account",
            "project_id": project_id,
            "private_key_id": private_key_id,
            "private_key": private_key,
            "client_email": client_email,
            "client_id": client_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": (
                f"https://www.googleapis.com/robot/v1/metadata/x509/"
                f"{client_email.replace('@', '%40')}"
            ),
        }
        cred = credentials.Certificate(service_account)
        firebase_admin.initialize_app(cred, extra)

    else:
        # Application Default Credentials — works on GCE / Cloud Run or when
        # the developer has run ``gcloud auth application-default login``.
        logger.info(
            "Firebase Admin: initialising with Application Default Credentials"
        )
        firebase_admin.initialize_app(options=extra if extra else None)
