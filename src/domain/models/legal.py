from dataclasses import dataclass
from datetime import datetime


@dataclass
class TermsVersion:
    version_id: str
    content: str
    published_at: datetime
    is_active: bool


@dataclass
class LegalConsent:
    consent_id: str
    user_id: str
    terms_version_id: str
    accepted_at: datetime
    ip_address: str
    user_agent: str
