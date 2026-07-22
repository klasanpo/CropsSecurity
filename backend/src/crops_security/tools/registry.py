from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class ModuleManifest:
    id: str
    name: str
    short_name: str
    category: str
    subcategory: str
    description: str
    impact: str
    version: str
    status: str
    capabilities: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


SENSITIVE_DATA_FINDER = ModuleManifest(
    id="web.sensitive-data-finder",
    name="Detector de Dados Sensíveis",
    short_name="Sensitive Data Finder",
    category="Web",
    subcategory="Exposição de Informações",
    description=(
        "Localiza segredos, credenciais, dados pessoais e artefatos sensíveis "
        "em páginas e recursos textuais autorizados."
    ),
    impact="Baixo",
    version="1.3.0",
    status="available",
    capabilities=(
        "Segredos",
        "Dados pessoais",
        "Arquivos sensíveis",
        "Escopos com múltiplos alvos",
        "Exportação e reteste",
    ),
)

MODULES = {SENSITIVE_DATA_FINDER.id: SENSITIVE_DATA_FINDER}


def list_modules() -> list[dict[str, object]]:
    return [module.as_dict() for module in MODULES.values()]
