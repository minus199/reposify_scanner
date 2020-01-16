from typing import List, Set


class CpeMatch:
    vulnerable: bool
    cpe23Uri: str
    versionStartExcluding: str
    versionEndExcluding: str
    versionStartIncluding: str
    versionEndIncluding: str

    def __init__(self, vulnerable: bool, cpe23Uri: str, versionStartExcluding: str = None, versionEndExcluding: str = None, versionStartIncluding: str = None, versionEndIncluding: str = None) -> None:
        self.vulnerable = vulnerable
        self.cpe23Uri = cpe23Uri


class Node:
    operator: str
    cpe_match: List[CpeMatch]
    children: List['Node']

    def __init__(self, operator: str, cpe_match: List[CpeMatch], children: List['Node']) -> None:
        self.operator = operator
        self.cpe_match = cpe_match
        self.children = children

    @staticmethod
    def build(raw):
        children = raw.get('children')
        if (children is not None):
            return [Node.build(child) for child in children]

        return [Node(operator=raw['operator'], cpe_match=[CpeMatch(**m) for m in raw.get('cpe_match', [])], children=raw.get('children', None))]


class Configurations:
    CVE_data_version: str
    nodes: List[Node]

    def __init__(self, CVE_data_version: str, nodes: List[Node]) -> None:
        self.CVE_data_version = CVE_data_version
        self.nodes = nodes

    @staticmethod
    def build(raw):
        from functools import reduce
        return Configurations(CVE_data_version=raw['CVE_data_version'],
                              nodes=reduce(lambda acc, i: acc.__add__(Node.build(i)), raw['nodes'], []))


class CVEDataMeta:
    ID: str
    ASSIGNER: str

    def __init__(self, ID: str, ASSIGNER: str) -> None:
        self.ID = ID
        self.ASSIGNER = ASSIGNER


class DescriptionDatumElement:
    lang: str
    value: str

    def __init__(self, lang: str, value: str) -> None:
        self.lang = lang
        self.value = value


class CveDescription:
    description_data: List[DescriptionDatumElement]

    def __init__(self, description_data: List[DescriptionDatumElement]) -> None:
        self.description_data = description_data

    @staticmethod
    def build(raw):
        return CveDescription([DescriptionDatumElement(**r) for r in raw])


class ProblemtypeDatum:
    description: List[DescriptionDatumElement]

    def __init__(self, description: List[DescriptionDatumElement]) -> None:
        self.description = description


class Problemtype:
    problemtype_data: List[ProblemtypeDatum]

    def __init__(self, problemtype_data: List[ProblemtypeDatum]) -> None:
        self.problemtype_data = problemtype_data

    @staticmethod
    def build(raw):
        return Problemtype([ProblemtypeDatum(**r) for r in raw])


class ReferenceDatum:
    url: str
    name: str
    refsource: str
    tags: List[str]

    def __init__(self, url: str, name: str, refsource: str, tags: List[str]) -> None:
        self.url = url
        self.name = name
        self.refsource = refsource
        self.tags = tags


class References:
    reference_data: List[ReferenceDatum]

    def __init__(self, reference_data: List[ReferenceDatum]) -> None:
        self.reference_data = reference_data

    @staticmethod
    def build(raw):
        return References(reference_data=[ReferenceDatum(**r) for r in raw['reference_data']])


class Cve:
    data_type: str
    data_format: str
    data_version: str
    CVE_data_meta: CVEDataMeta
    problemtype: Problemtype
    references: References
    description: CveDescription

    def __init__(self, data_type: str, data_format: str, data_version: str,
                 CVE_data_meta: CVEDataMeta,
                 problemtype: Problemtype,
                 references: References,
                 description: CveDescription) -> None:
        self.data_type = data_type
        self.data_format = data_format
        self.data_version = data_version
        self.CVE_data_meta = CVE_data_meta
        self.problemtype = problemtype
        self.references = references
        self.description = description

    @staticmethod
    def build(raw):
        return Cve(CVE_data_meta=CVEDataMeta(**raw.pop('CVE_data_meta')),
                   problemtype=Problemtype(**raw.pop('problemtype')),
                   references=References.build(raw.pop('references')),
                   description=CveDescription(**raw.pop('description')),
                   **raw)


class CvssV2:
    version: str
    vectorString: str
    accessVector: str
    accessComplexity: str
    authentication: str
    confidentialityImpact: str
    integrityImpact: str
    availabilityImpact: str
    baseScore: float

    def __init__(self, version: str, vectorString: str, accessVector: str, accessComplexity: str, authentication: str, confidentialityImpact: str, integrityImpact: str, availabilityImpact: str, baseScore: float) -> None:
        self.version = version
        self.vectorString = vectorString
        self.accessVector = accessVector
        self.accessComplexity = accessComplexity
        self.authentication = authentication
        self.confidentialityImpact = confidentialityImpact
        self.integrityImpact = integrityImpact
        self.availabilityImpact = availabilityImpact
        self.baseScore = baseScore


class BaseMetricV2:
    cvssV2: CvssV2
    severity: str
    exploitabilityScore: float
    impactScore: float
    acInsufInfo: bool
    obtainAllPrivilege: bool
    obtainUserPrivilege: bool
    obtainOtherPrivilege: bool
    userInteractionRequired: bool

    def __init__(self, cvssV2: CvssV2, severity: str, exploitabilityScore: float, impactScore: float, acInsufInfo: bool, obtainAllPrivilege: bool, obtainUserPrivilege: bool, obtainOtherPrivilege: bool, userInteractionRequired: bool) -> None:
        self.cvssV2 = cvssV2
        self.severity = severity
        self.exploitabilityScore = exploitabilityScore
        self.impactScore = impactScore
        self.acInsufInfo = acInsufInfo
        self.obtainAllPrivilege = obtainAllPrivilege
        self.obtainUserPrivilege = obtainUserPrivilege
        self.obtainOtherPrivilege = obtainOtherPrivilege
        self.userInteractionRequired = userInteractionRequired

    @staticmethod
    def build(raw):
        return BaseMetricV2(cvssV2=CvssV2(**raw.pop('cvssV2')), **raw)


class CvssV3:
    version: str
    vectorString: str
    attackVector: str
    attackComplexity: str
    privilegesRequired: str
    userInteraction: str
    scope: str
    confidentialityImpact: str
    integrityImpact: str
    availabilityImpact: str
    baseScore: float
    baseSeverity: str

    def __init__(self, version: str, vectorString: str, attackVector: str, attackComplexity: str, privilegesRequired: str, userInteraction: str, scope: str, confidentialityImpact: str, integrityImpact: str, availabilityImpact: str, baseScore: float, baseSeverity: str) -> None:
        self.version = version
        self.vectorString = vectorString
        self.attackVector = attackVector
        self.attackComplexity = attackComplexity
        self.privilegesRequired = privilegesRequired
        self.userInteraction = userInteraction
        self.scope = scope
        self.confidentialityImpact = confidentialityImpact
        self.integrityImpact = integrityImpact
        self.availabilityImpact = availabilityImpact
        self.baseScore = baseScore
        self.baseSeverity = baseSeverity


class BaseMetricV3:
    cvssV3: CvssV3
    exploitabilityScore: float
    impactScore: float

    def __init__(self, cvssV3: CvssV3, exploitabilityScore: float, impactScore: float) -> None:
        self.cvssV3 = cvssV3
        self.exploitabilityScore = exploitabilityScore
        self.impactScore = impactScore

    @staticmethod
    def build(raw):
        return BaseMetricV3(cvssV3=CvssV3(**raw.pop('cvssV3')), **raw)


class Impact:
    baseMetricV3: BaseMetricV3
    baseMetricV2: BaseMetricV2

    def __init__(self, baseMetricV3: BaseMetricV3, baseMetricV2: BaseMetricV2) -> None:
        self.baseMetricV3 = baseMetricV3
        self.baseMetricV2 = baseMetricV2

    @staticmethod
    def build(raw):
        if (not raw):
            return None

        return Impact(
            baseMetricV3=BaseMetricV3.build(raw['baseMetricV3']),
            baseMetricV2=BaseMetricV2.build(raw['baseMetricV2']))


class CveItem:
    cve: Cve
    configurations: Configurations
    impact: Impact
    publishedDate: str
    lastModifiedDate: str

    def __init__(self, cve: Cve, configurations: Configurations, impact: Impact, publishedDate: str, lastModifiedDate: str) -> None:
        self.cve = cve
        self.configurations = configurations
        self.impact = impact
        self.publishedDate = publishedDate
        self.lastModifiedDate = lastModifiedDate
        self.__exploites = None

    def list_exploites(self):
        if (self.__exploites is None):
            self.__exploites = {
                'cpe': self.__traverse_exploits(self.configurations.nodes, set()),
                'description': "\n".join([d['value'] for d in self.cve.description.description_data]),
                'impact': {
                    'exploitabilityScore': self.impact.baseMetricV3.exploitabilityScore if self.impact else None,
                    'impactScore': self.impact.baseMetricV3.impactScore if self.impact else None
                }
            }
            
        return self.__exploites

    @staticmethod
    def __traverse_exploits(nodes: List[Node], acc: Set[CpeMatch]) -> Set[str]:
        for node in nodes:
            try:
                CveItem.__traverse_exploits(node.children, acc)
            except AttributeError:
                CveItem.__traverse_exploits(node, acc)
            except Exception as e:
                if (node.children is not None):
                    raise e

                acc.update([c.cpe23Uri for c in node.cpe_match])

        return acc

    @staticmethod
    def build(raw):
        return CveItem(cve=Cve.build(raw['cve']),
                       configurations=Configurations.build(
                           raw['configurations']),
                       impact=Impact.build(raw['impact']),
                       publishedDate=raw['publishedDate'], lastModifiedDate=raw['lastModifiedDate'])
