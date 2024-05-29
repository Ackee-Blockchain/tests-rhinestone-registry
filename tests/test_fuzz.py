from collections import defaultdict
from contextlib import contextmanager
from functools import reduce
import operator
from typing import Dict, NamedTuple, Set

from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.source.src.Registry import Registry
from pytypes.source.src.external.IExternalSchemaValidator import IExternalSchemaValidator
from pytypes.source.test.mocks.MockFactory import MockFactory
from pytypes.source.test.mocks.MockModule import MockModule
from pytypes.source.test.mocks.MockResolver import MockResolver
from pytypes.source.test.mocks.MockSchemaValidator import MockSchemaValidator
from pytypes.source.src.DataTypes import ModuleRecord, ResolverRecord, AttestationRecord, AttestationRequest, RevocationRequest, SchemaRecord

from pytypes.source.node_modules.solady.src.utils.SSTORE2 import SSTORE2


class TrustedAttesters(NamedTuple):
    threshold: uint
    attesters: List[Account]


ZERO_ATTESTATION = AttestationRecord(0, 0, 0, 0, Address.ZERO, Address.ZERO, Address.ZERO, bytes32(0))


class RhinestoneModuleRegistryTest(FuzzTest):
    registry: Registry
    factory: MockFactory

    attester_nonces: Dict[Account, uint]
    modules: Dict[bytes32, Dict[Account, ModuleRecord]]
    resolvers: Dict[bytes32, ResolverRecord]
    schemas: Dict[bytes32, SchemaRecord]
    attestations: Dict[Account, Dict[Account, AttestationRecord]]  # module -> attester -> attestation
    trusted_attesters: Dict[Account, TrustedAttesters]

    def pre_sequence(self) -> None:
        self.modules = defaultdict(dict)
        self.resolvers = {}
        self.schemas = {}
        self.attester_nonces = defaultdict(int)
        self.attestations = {}
        self.trusted_attesters = defaultdict(lambda: TrustedAttesters(0, []))

        self.registry = Registry.deploy()
        self.factory = MockFactory.deploy()

    def _random_attestation_request(self, resolver_uid: bytes32) -> AttestationRequest:
        module = random.choice(list(self.modules[resolver_uid])).address
        expiration = chain.blocks["pending"].timestamp + random_int(1, 300) if random.random() < 0.7 else 0
        data = random_bytes(0, 32)
        module_types = random.sample(range(32), random_int(0, 32))
        return AttestationRequest(
            module,
            expiration,
            data,
            module_types,
        )

    def _get_signable_hash(self, struct_hash: bytes32) -> bytes:
        domain_hash = keccak256(abi.encode(
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(b"RhinestoneRegistry"),
            keccak256(b"v1.0"),
            uint(chain.chain_id),
            self.registry.address,
        ))
        return keccak256(abi.encode_packed(b"\x19\x01", domain_hash, struct_hash))

    @flow(max_times=10)
    def flow_register_module(self):
        if len(self.resolvers) == 0:
            return

        resolver_uid = random.choice(list(self.resolvers))
        module = MockModule.deploy()
        metadata = random_bytes(0, 32)
        sender = random_account()

        tx = self.registry.registerModule(resolver_uid, module, metadata, from_=sender)

        self.modules[resolver_uid][module] = ModuleRecord(resolver_uid, Address.ZERO, metadata)
        self.attestations[module] = {}

    @flow(max_times=10)
    def flow_deploy_module(self):
        if len(self.resolvers) == 0:
            return

        resolver_uid = random.choice(list(self.resolvers))
        metadata = random_bytes(0, 32)
        sender = random_account()
        salt = bytes(sender.address) + random_bytes(12, 12)

        addr = self.registry.calcModuleAddress(salt, MockModule.get_creation_code(), from_=random_account())

        tx = self.registry.deployModule(salt, resolver_uid, MockModule.get_creation_code(), metadata, from_=sender)

        assert tx.return_value == addr
        module = Account(tx.return_value)
        self.modules[resolver_uid][module] = ModuleRecord(resolver_uid, sender.address, metadata)
        self.attestations[module] = {}

    @flow(max_times=10)
    def flow_deploy_module_via_factory(self):
        if len(self.resolvers) == 0:
            return

        resolver_uid = random.choice(list(self.resolvers))
        metadata = random_bytes(0, 32)
        sender = random_account()

        tx = self.registry.deployViaFactory(
            self.factory,
            abi.encode_call(MockFactory.deploy_, [MockModule.get_creation_code()]),
            metadata,
            resolver_uid,
            from_=sender,
        )

        module = Account(tx.return_value)
        self.modules[resolver_uid][module] = ModuleRecord(resolver_uid, Address.ZERO, metadata)
        self.attestations[module] = {}

    @flow(max_times=10)
    def flow_register_resolver(self):
        resolver = MockResolver.deploy(True)
        owner = random_account()

        tx = self.registry.registerResolver(resolver, from_=owner)

        self.resolvers[tx.return_value] = ResolverRecord(resolver, owner.address)

    @flow(max_times=10)
    def flow_register_schema(self):
        schema = random_string(0, 10)
        if random.random() < 0.75:
            schema_validator = MockSchemaValidator.deploy(True)
        else:
            schema_validator = IExternalSchemaValidator(Address.ZERO)

        tx = self.registry.registerSchema(schema, schema_validator, from_=random_account())

        self.schemas[tx.return_value] = SchemaRecord(tx.block.timestamp, schema_validator, schema)

    @flow()
    def flow_set_resolver(self):
        if len(self.resolvers) == 0:
            return

        resolver = MockResolver.deploy(True)
        resolver_uid = random.choice(list(self.resolvers))

        self.registry.setResolver(resolver_uid, resolver, from_=self.resolvers[resolver_uid].resolverOwner)

        self.resolvers[resolver_uid].resolver = resolver

    @flow()
    def flow_transfer_resolver(self):
        if len(self.resolvers) == 0:
            return

        resolver_uid = random.choice(list(self.resolvers))
        new_owner = random_account()

        self.registry.transferResolverOwnership(resolver_uid, new_owner, from_=self.resolvers[resolver_uid].resolverOwner)

        self.resolvers[resolver_uid].resolverOwner = new_owner.address

    @flow()
    def flow_attest(self):
        resolver_uids = [k for k, v in self.modules.items() if len(v) > 0]
        if len(self.modules) == 0 or len(self.schemas) == 0 or len(resolver_uids) == 0:
            return

        schema_uid = random.choice(list(self.schemas))
        resolver_uid = random.choice(resolver_uids)
        request = self._random_attestation_request(resolver_uid)
        attester = random_account()

        tx = self.registry.attest(schema_uid, request, from_=attester)
        e = next(e for e in tx.events if isinstance(e, Registry.Attested))

        self.attestations[Account(request.moduleAddr)][attester] = AttestationRecord(
            tx.block.timestamp,
            request.expirationTime,
            0,
            reduce(operator.or_, (1 << i for i in request.moduleTypes), 0),
            request.moduleAddr,
            attester.address,
            e.sstore2Pointer,
            schema_uid,
        )

    @flow()
    def flow_attest_many(self):
        resolver_uids = [k for k, v in self.modules.items() if len(v) > 0]
        if len(self.modules) == 0 or len(self.schemas) == 0 or len(resolver_uids) == 0:
            return

        schema_uid = random.choice(list(self.schemas))
        resolver_uid = random.choice(resolver_uids)
        requests = [self._random_attestation_request(resolver_uid) for _ in range(random_int(0, 10))]
        attester = random_account()

        with may_revert(SSTORE2.DeploymentFailed) as e:
            tx = self.registry.attest_(schema_uid, requests, from_=attester)

        if e.value is not None:
            assert any(
                requests[i].moduleAddr == requests[j].moduleAddr and requests[i].data == requests[j].data
                for i in range(len(requests))
                for j in range(i+1, len(requests))
            )
        else:
            for request, e in zip(requests, [e for e in tx.events if isinstance(e, Registry.Attested)]):
                self.attestations[Account(request.moduleAddr)][attester] = AttestationRecord(
                    tx.block.timestamp,
                    request.expirationTime,
                    0,
                    reduce(operator.or_, (1 << i for i in request.moduleTypes), 0),
                    request.moduleAddr,
                    attester.address,
                    e.sstore2Pointer,
                    schema_uid,
                )

    @flow()
    def flow_attest_with_signature(self):
        resolver_uids = [k for k, v in self.modules.items() if len(v) > 0]
        if len(self.modules) == 0 or len(self.schemas) == 0 or len(resolver_uids) == 0:
            return

        schema_uid = random.choice(list(self.schemas))
        resolver_uid = random.choice(resolver_uids)
        request = self._random_attestation_request(resolver_uid)
        attester = random_account()
        self.attester_nonces[attester] += 1

        struct_hash = keccak256(abi.encode(
            keccak256(b"AttestationRequest(address,uint48,bytes,uint256[])"),
            keccak256(abi.encode(request)),
            uint(self.attester_nonces[attester]),
        ))
        data = self._get_signable_hash(struct_hash)
        assert data == self.registry.getDigest(request, attester)

        tx = self.registry.attest__(schema_uid, attester, request, attester.sign_hash(data), from_=random_account())
        e = next(e for e in tx.events if isinstance(e, Registry.Attested))

        self.attestations[Account(request.moduleAddr)][attester] = AttestationRecord(
            tx.block.timestamp,
            request.expirationTime,
            0,
            reduce(operator.or_, (1 << i for i in request.moduleTypes), 0),
            request.moduleAddr,
            attester.address,
            e.sstore2Pointer,
            schema_uid,
        )

    @flow()
    def flow_attest_many_with_signature(self):
        resolver_uids = [k for k, v in self.modules.items() if len(v) > 0]
        if len(self.modules) == 0 or len(self.schemas) == 0 or len(resolver_uids) == 0:
            return

        schema_uid = random.choice(list(self.schemas))
        resolver_uid = random.choice(resolver_uids)
        requests = [self._random_attestation_request(resolver_uid) for _ in range(random_int(0, 10))]
        attester = random_account()

        struct_hash = keccak256(abi.encode(
            keccak256(b"AttestationRequest(address,uint48,bytes,uint256[])"),
            keccak256(abi.encode(requests)),
            uint(self.attester_nonces[attester] + 1),
        ))
        data = self._get_signable_hash(struct_hash)
        assert data == self.registry.getDigest_(requests, attester)

        with may_revert(SSTORE2.DeploymentFailed) as e:
            tx = self.registry.attest___(schema_uid, attester, requests, attester.sign_hash(data), from_=random_account())

        if e.value is not None:
            assert any(
                requests[i].moduleAddr == requests[j].moduleAddr and requests[i].data == requests[j].data
                for i in range(len(requests))
                for j in range(i+1, len(requests))
            )
        else:
            self.attester_nonces[attester] += 1

            for request, e in zip(requests, [e for e in tx.events if isinstance(e, Registry.Attested)]):
                self.attestations[Account(request.moduleAddr)][attester] = AttestationRecord(
                    tx.block.timestamp,
                    request.expirationTime,
                    0,
                    reduce(operator.or_, (1 << i for i in request.moduleTypes), 0),
                    request.moduleAddr,
                    attester.address,
                    e.sstore2Pointer,
                    schema_uid,
                )

    @flow()
    def flow_revoke(self):
        modules = [m for m, a in self.attestations.items() if len(a) > 0 and any(a[attester].revocationTime == 0 for attester in a)]
        if len(modules) == 0:
            return

        module = random.choice(modules)
        attestation = random.choice([a for a in self.attestations[module].values() if a.revocationTime == 0])

        tx = self.registry.revoke(RevocationRequest(module.address), from_=attestation.attester)

        self.attestations[module][Account(attestation.attester)].revocationTime = tx.block.timestamp

    @flow()
    def flow_revoke_many(self):
        attester = random_account()
        resolver_uids = [k for k, v in self.modules.items() if attester in v and any(self.attestations[m][attester].revocationTime == 0 for m in v)]

        if len(resolver_uids) == 0:
            modules = []
        else:
            resolver_uid = random.choice(resolver_uids)
            modules = [m for m in self.modules[resolver_uid] if self.attestations[m][attester].revocationTime == 0]
            modules = random.sample(modules, random_int(0, len(modules)))

        tx = self.registry.revoke_([RevocationRequest(m.address) for m in modules], from_=attester)

        for module in modules:
            self.attestations[module][attester].revocationTime = tx.block.timestamp

    @flow()
    def flow_revoke_with_signature(self):
        modules = [m for m, a in self.attestations.items() if len(a) > 0 and any(a[attester].revocationTime == 0 for attester in a)]
        if len(modules) == 0:
            return

        module = random.choice(modules)
        attestation = random.choice([a for a in self.attestations[module].values() if a.revocationTime == 0])
        attester = Account(attestation.attester)
        self.attester_nonces[attester] += 1

        struct_hash = keccak256(abi.encode(
            keccak256(b"RevocationRequest(address)"),
            keccak256(abi.encode(module.address)),
            uint(self.attester_nonces[attester]),
        ))
        data = self._get_signable_hash(struct_hash)
        request = RevocationRequest(module.address)
        assert data == self.registry.getDigest__(request, attester)

        tx = self.registry.revoke__(attester, request, attester.sign_hash(data), from_=random_account())

        self.attestations[module][attester].revocationTime = tx.block.timestamp

    @flow()
    def flow_revoke_many_with_signature(self):
        attester = random_account()
        self.attester_nonces[attester] += 1
        resolver_uids = [k for k, v in self.modules.items() if attester in v and any(self.attestations[m][attester].revocationTime == 0 for m in v)]

        if len(resolver_uids) == 0:
            modules = []
        else:
            resolver_uid = random.choice(resolver_uids)
            modules = [m for m in self.modules[resolver_uid] if self.attestations[m][attester].revocationTime == 0]
            modules = random.sample(modules, random_int(0, len(modules)))

        struct_hash = keccak256(abi.encode(
            keccak256(b"RevocationRequest(address)"),
            keccak256(abi.encode([m.address for m in modules])),
            uint(self.attester_nonces[attester]),
        ))
        data = self._get_signable_hash(struct_hash)
        requests = [RevocationRequest(m.address) for m in modules]
        assert data == self.registry.getDigest___(requests, attester)

        tx = self.registry.revoke___(attester, requests, attester.sign_hash(data), from_=random_account())

        for module in modules:
            self.attestations[module][attester].revocationTime = tx.block.timestamp

    @flow()
    def flow_trust_attesters(self):
        attesters = random.sample(list(chain.accounts) + [Account(0)], random_int(1, len(chain.accounts) + 1))
        threshold = random_int(0, len(attesters))
        truster = random_account()

        with may_revert(Registry.InvalidTrustedAttesterInput) as e:
            tx = self.registry.trustAttesters(threshold, attesters, from_=truster)

        if e.value is not None:
            assert any(a == Account(0) for a in attesters)
        else:
            assert all(a != Account(0) for a in attesters)

            self.trusted_attesters[truster] = TrustedAttesters(threshold, sorted(attesters, key=lambda a: a.address))

    @invariant()
    def invariant_attestations(self):
        for module, attestations in self.attestations.items():
            assert self.registry.findAttestations(module, list(chain.accounts)) == [
                attestations[a] if a in attestations else ZERO_ATTESTATION
                for a in chain.accounts
            ]

    @invariant()
    def invariant_find_resolver(self):
        for resolver_uid, resolver in self.resolvers.items():
            assert self.registry.findResolver(resolver_uid) == resolver

    @invariant()
    def invariant_find_schema(self):
        for schema_uid, schema in self.schemas.items():
            assert self.registry.findSchema(schema_uid) == schema

    @invariant()
    def invariant_find_module(self):
        for modules in self.modules.values():
            for module in modules:
                assert self.registry.findModule(module) == modules[module]

    @invariant()
    def invariant_attester_nonces(self):
        for a in chain.accounts:
            assert self.registry.attesterNonce(a) == self.attester_nonces[a]

    @invariant()
    def invariant_trusted_attesters(self):
        for a in chain.accounts:
            with may_revert(PanicCodeEnum.INDEX_ACCESS_OUT_OF_BOUNDS) as e:
                assert self.registry.findTrustedAttesters(a) == [at.address for at in self.trusted_attesters[a].attesters]

            if e.value is not None:
                assert self.trusted_attesters[a].attesters == []

    @invariant()
    def invariant_check(self):
        timestamp = chain.blocks["latest"].timestamp

        for acc in chain.accounts:
            trusted_attesters = self.trusted_attesters[acc]

            for modules in self.modules.values():
                for module in modules:
                    attestations = {
                        a
                        for a, attestation in self.attestations[module].items()
                        if attestation.revocationTime == 0 and
                        (attestation.expirationTime == 0 or attestation.expirationTime >= timestamp)
                    }

                    with assert_check(trusted_attesters, attestations):
                        self.registry.check(module, from_=acc)

                    with assert_check(trusted_attesters, attestations):
                        self.registry.checkForAccount(acc, module, from_=random_account())

                    module_type = random_int(0, 32)
                    attestations = {
                        a for a, attestation in self.attestations[module].items()
                        if attestation.revocationTime == 0 and
                        (attestation.expirationTime == 0 or attestation.expirationTime >= timestamp) and
                        (module_type == 0 or attestation.moduleTypes == 0 or attestation.moduleTypes & (1 << module_type))
                    }

                    with assert_check(trusted_attesters, attestations):
                        self.registry.check_(module, module_type, from_=acc)

                    with assert_check(trusted_attesters, attestations):
                        self.registry.checkForAccount_(acc, module, module_type, from_=random_account())

        for modules in self.modules.values():
            for module in modules:
                attestations = {
                    a
                    for a, attestation in self.attestations[module].items()
                    if attestation.revocationTime == 0 and
                    (attestation.expirationTime == 0 or attestation.expirationTime >= timestamp)
                }
                attesters = random.sample(chain.accounts, random_int(1, len(chain.accounts)))
                threshold = random_int(0, len(attesters))
                if threshold == 0:
                    threshold = len(attesters)

                with assert_check(TrustedAttesters(threshold, attesters), attestations):
                    self.registry.check__(module, attesters, threshold, from_=random_account())

                module_type = random_int(0, 32)
                attestations = {
                    a for a, attestation in self.attestations[module].items()
                    if attestation.revocationTime == 0 and
                    (attestation.expirationTime == 0 or attestation.expirationTime >= timestamp) and
                    (module_type == 0 or attestation.moduleTypes == 0 or attestation.moduleTypes & (1 << module_type))
                }

                with assert_check(TrustedAttesters(threshold, attesters), attestations):
                    self.registry.check___(module, module_type, attesters, threshold, from_=random_account())


@contextmanager
def assert_check(trusted_attesters: TrustedAttesters, attestations: Set[Account]):
    if len(trusted_attesters.attesters) == 0 or trusted_attesters.threshold == 0:
        with must_revert(Registry.NoTrustedAttestersFound):
            yield
    elif len(attestations & set(trusted_attesters.attesters)) < trusted_attesters.threshold:
        with must_revert(Registry.InsufficientAttestations):
            yield
    else:
        yield


@chain.connect()
@on_revert(lambda e: print(e.tx.call_trace if e.tx else 'Call reverted'))
def test_default():
    RhinestoneModuleRegistryTest().run(10, 1_000)
