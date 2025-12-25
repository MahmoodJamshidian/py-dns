from .zone import *
import json
import aiofiles

type ZoneMapping = Mapping[str, Union[str, Iterable]]

async def load_records(records: list[Mapping], host: str, /, *, ptr_records: list[PTRRecord]) -> list[DNSRecordType]:
    records_ins: list[DNSRecordType] = []

    for record in records:
        type: str = record['type']

        try:
            rtype: RecordType = RecordType[type]
        except KeyError:
            raise ValueError("record type undefined") from None

        if isinstance(rtype, PTRRecord):
            raise Exception("cant define PTR record here (user ptr_record property in A and AAAA)")

        record_type: Type[BaseRecord] = next(filter(lambda t: t.record_type == rtype, (ARecord, AAAARecord, CNAMERecord, TXTRecord,)))

        record_params: set = set(record_type.__dict__["__annotations__"]) & set(("record_type",))

        params: dict = dict(filter(lambda param: param[0] in record_params, record.items()))

        record_ins: DNSRecordType = record_type(**params)

        if isinstance(record_ins, (ARecord, AAAARecord,)) and record_ins.ptr_record:
            ptr: PTRRecord = PTRRecord(host, record_ins.address)

            if ptr not in ptr_records:
                ptr_records.append(ptr)

        if record_ins not in records_ins:
            records_ins.append(record_ins)

    return record_ins

async def load_zone(zone: ZoneMapping, parent_zone: Zone = None, /, *, recursion_sources: list[RecursionSource], allow_sources: list[RequestSource], ptr_records: list[PTRRecord]) -> Zone:
    namespace: str = zone.get("namespace") or None

    if namespace is not None and not isinstance(namespace, str):
        raise Exception("namespace should be an string")

    if not parent_zone and namespace:
        raise Exception("subzone cant be root")

    if not parent_zone and not namespace.endswith("."):
        raise Exception("root identifier cant find in head zone namespace")

    if not namespace and zone.get("records"):
        raise Exception("root cant have a record")

    host: str = "." if not namespace else f"{namespace}.{parent_zone.host}"

    records: list[DNSRecordType] = await load_records(zone.get("records", []), host, ptr_records=ptr_records)

    recursion_sources_zone: list[RecursionSource] = []

    for addr in zone.get("recursion", []):
        for src in recursion_sources:
            if src == addr:
                break
        else:
            src = RecursionSource(addr)
            recursion_sources.append(src)

        recursion_sources_zone.append(src)

    allow_sources_zone: list[RecursionSource] = []

    for addr in zone.get("allow_sources", []):
        for src in allow_sources:
            if src == addr:
                break
        else:
            src = RequestSource(addr)
            allow_sources.append(src)

        allow_sources_zone.append(src)

    zone: Zone = Zone(parent_zone, namespace, records, recursion_sources_zone, allow_sources_zone)

    for subzone in zone.get("subzones", []):
        subz: Zone = await load_zone(
            subzone,
            zone,
            recursion_sources=recursion_sources,
            allow_sources=allow_sources,
            ptr_records=ptr_records
        )

        zone.subsets.append(subz)

    return zone

async def load_db(db_path: str) -> Zone:
    async with aiofiles.open(db_path, 'r') as f:
        data: dict = json.load(await f.read())

    if not isinstance(data, dict):
        raise Exception("cant load database, object file expected")

    recursion_sources: list[RecursionSource] = []
    allow_sources: list[RequestSource] = []
    ptr_records: list[PTRRecord] = []

    return await load_zone(data,
        recursion_sources=recursion_sources,
        allow_sources=allow_sources,
        ptr_records=ptr_records
    )