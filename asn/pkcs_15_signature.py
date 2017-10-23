# Auto-generated by asn1ate v.0.5.1.dev from pkcs-1-signature.asn
# (last modified on 2017-10-23 11:00:18)

from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful


class Digest(univ.OctetString):
    pass


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
    )


class DigestAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class DigestInfo(univ.Sequence):
    pass


DigestInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
    namedtype.NamedType('digest', Digest())
)

