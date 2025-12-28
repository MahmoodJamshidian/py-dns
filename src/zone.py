from enum import Enum
from dataclasses import dataclass, field
from abc import ABC
from typing import *
import ipaddress

type DNSRecordType = Union[ARecord, AAAARecord, CNAMERecord, TXTRecord]
type IPAddress =     Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

class RecordType(Enum):
    A = "A"         # IPv4 addressing
    AAAA = "AAAA"   # IPv6 addressing
    CNAME = "CNAME" # Alias name
    TXT = "TXT"     # text
    PTR = "PTR"     # pointer to IP

class BaseRecord(ABC):
    ttl: Optional[int] = None
    record_type: RecordType = None

    @property
    def record_type(self) -> RecordType:
        return RecordType[self.record_type]

    def __post_init__(self):
        if self.ttl is not None:
            if not isinstance(self.ttl, int):
                raise TypeError("TTL must be int")
            if self.ttl < 0:
                raise ValueError("TTL must be >= 0")

    def __hash__(self):
        return hash(tuple(getattr(self, name) for name in set(self.__annotations__)))

@dataclass
class ARecord(BaseRecord):
    address: str
    ptr_record: bool = False

    record_type: RecordType = RecordType.A

    def __post_init__(self):
        super().__post_init__()
        try:
            ipaddress.IPv4Address(self.address)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv4 address: {self.address}")

@dataclass
class AAAARecord(BaseRecord):
    address: str
    ptr_record: bool = False

    record_type: RecordType = RecordType.AAAA

    def __post_init__(self):
        super().__post_init__()
        try:
            ipaddress.IPv6Address(self.address)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv6 address: {self.address}")

@dataclass
class CNAMERecord(BaseRecord):
    target: str

    record_type: RecordType = RecordType.CNAME

    def __post_init__(self):
        super().__post_init__()
        validate_hostname(self.target)

@dataclass
class TXTRecord(BaseRecord):
    text: str

    record_type: RecordType = RecordType.TXT

    def __post_init__(self):
        super().__post_init__()

        if len(self.text) > 255:
            raise ValueError("TXT record cant have more then 255 character")

@dataclass
class PTRRecord(BaseRecord):
    host: str
    address: str

    record_type: RecordType = RecordType.PTR

    def __init__(self, host: str, address: str):
        self.host = host

        ip: IPAddress = ipaddress.ip_address(address)

        self.address = ip.reverse_pointer

class IPComparableMixin:
    address: str

    def _ip(self) -> ipaddress._BaseAddress:
        return ipaddress.ip_address(self.address)

    def __eq__(self, other: Union[Self, Any]) -> bool:
        if isinstance(other, str):
            try:
                return self._ip() == ipaddress.ip_address(other)
            except ValueError:
                return False

        if isinstance(other, ipaddress._BaseAddress):
            return self._ip() == other

        if hasattr(other, "address"):
            try:
                return self._ip() == ipaddress.ip_address(other.address)
            except ValueError:
                return False

        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._ip())

@dataclass
class RecursionSource(IPComparableMixin):
    address: str

    def __post_init__(self):
        try:
            ipaddress.ip_address(self.address)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid address: {self.address}")

@dataclass
class RequestSource(IPComparableMixin):
    address: str

    def __post_init__(self):
        try:
            ipaddress.ip_address(self.address)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid address: {self.address}")

@dataclass
class Zone:
    namespace: str
    records: list[BaseRecord]
    recursion: list[RecursionSource]
    allow_sources: list[RequestSource]
    subsets: list[Self] = field(default_factory=list)
    parent: Self = None

    @property
    def host(self) -> str:
        return (self.namespace or "") + ("." if not self.parent else self.parent.host)

def validate_hostname(name: str):
    if not name:
        raise ValueError("Hostname cannot be empty")
    if " " in name:
        raise ValueError("Invalid hostname")