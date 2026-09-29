from typing import Optional
from src.domain.repositories.legal_repository import LegalRepository
from src.domain.models.legal import LegalConsent, TermsVersion
from src.data.supabase.client import supabase_client
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class SupabaseLegalRepository(LegalRepository):
    def save_consent(self, consent: LegalConsent) -> None:
        if not supabase_client:
            logger.warning("Supabase client not initialized.")
            return

        try:
            consent_data = {
                "consent_id": consent.consent_id,
                "user_id": consent.user_id,
                "terms_version_id": consent.terms_version_id,
                "accepted_at": consent.accepted_at.isoformat(),
                "ip_address": consent.ip_address,
                "user_agent": consent.user_agent
            }
            supabase_client.table("legal_consents").insert(consent_data).execute()
        except Exception as e:
            logger.error(f"Error saving consent: {e}")

    def get_latest_terms(self) -> Optional[TermsVersion]:
        if not supabase_client:
            return None
            
        try:
            response = supabase_client.table("terms_versions").select("*").eq("is_active", True).order("published_at", desc=True).limit(1).execute()
            data = response.data
            if data:
                t = data[0]
                # Convert string to datetime
                published_at = datetime.fromisoformat(t["published_at"]) if isinstance(t["published_at"], str) else t["published_at"]
                return TermsVersion(
                    version_id=t["version_id"],
                    content=t["content"],
                    published_at=published_at,
                    is_active=t["is_active"]
                )
        except Exception as e:
            logger.error(f"Error getting terms: {e}")
            
        return None

    def get_terms_by_id(self, version_id: str) -> Optional[TermsVersion]:
        pass
