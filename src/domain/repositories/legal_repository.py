from abc import ABC, abstractmethod
from typing import Optional
from src.domain.models.legal import LegalConsent, TermsVersion

class LegalRepository(ABC):
    @abstractmethod
    def save_consent(self, consent: LegalConsent) -> None:
        pass

    @abstractmethod
    def get_latest_terms(self) -> Optional[TermsVersion]:
        pass

    @abstractmethod
    def get_terms_by_id(self, version_id: str) -> Optional[TermsVersion]:
        pass
