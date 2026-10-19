from sentinel.ingestion.certfr import CertFrConnector

# Registre des connecteurs disponibles : ajouter ici chaque nouvelle source.
CONNECTORS = {
    CertFrConnector.name: CertFrConnector,
}

__all__ = ["CONNECTORS", "CertFrConnector"]
