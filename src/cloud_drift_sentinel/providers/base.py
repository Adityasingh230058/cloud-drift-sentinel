"""
Base Cloud Provider Interface.
"""

from abc import ABC, abstractmethod
from typing import List
from ..core.models import CloudResource


class BaseCloudProvider(ABC):
    """
    Abstract interface for cloud infrastructure inventory discovery.
    """
    provider_name: str = "base"

    @abstractmethod
    def collect_resources(self) -> List[CloudResource]:
        """
        Gathers all resources across services and returns a normalized list of CloudResource objects.
        """
        pass
