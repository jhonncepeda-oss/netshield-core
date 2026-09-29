from abc import ABC, abstractmethod
from typing import Optional
from src.domain.models.audit import Device

class DeviceRepository(ABC):
    @abstractmethod
    def save_device(self, device: Device) -> None:
        pass

    @abstractmethod
    def get_device(self, device_id: str) -> Optional[Device]:
        pass
