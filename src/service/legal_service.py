import uuid
from datetime import datetime
from src.domain.models.legal import LegalConsent
from src.domain.repositories.legal_repository import LegalRepository

class LegalService:
    def __init__(self, legal_repo: LegalRepository):
        self.legal_repo = legal_repo

    def record_consent(self, user_id: str, ip_address: str, user_agent: str) -> LegalConsent:
        latest_terms = self.legal_repo.get_latest_terms()
        if not latest_terms:
            raise Exception("No active terms of service found.")

        consent = LegalConsent(
            consent_id=str(uuid.uuid4()),
            user_id=user_id,
            terms_version_id=latest_terms.version_id,
            accepted_at=datetime.now(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        self.legal_repo.save_consent(consent)
        return consent
