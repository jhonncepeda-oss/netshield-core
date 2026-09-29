from typing import Optional
from src.domain.repositories.device_repository import DeviceRepository
from src.domain.models.audit import Device
from src.data.supabase.client import supabase_client
import logging

logger = logging.getLogger(__name__)

class SupabaseDeviceRepository(DeviceRepository):
    def save_device(self, device: Device) -> None:
        if not supabase_client:
            logger.warning("Supabase client not initialized. Skipping device save.")
            return

        try:
            device_data = {
                "device_id": device.device_id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "os_version": device.os_version,
                "device_type": device.device_type
            }
            supabase_client.table("devices").upsert(device_data).execute()
        except Exception as e:
            logger.error(f"Error saving device to Supabase: {e}")

    def get_device(self, device_id: str) -> Optional[Device]:
        if not supabase_client:
            return None
        
        try:
            response = supabase_client.table("devices").select("*").eq("device_id", device_id).execute()
            data = response.data
            if data:
                d = data[0]
                return Device(
                    device_id=d["device_id"],
                    hostname=d["hostname"],
                    ip_address=d["ip_address"],
                    os_version=d["os_version"],
                    device_type=d["device_type"]
                )
        except Exception as e:
            logger.error(f"Error retrieving device from Supabase: {e}")
            
        return None
