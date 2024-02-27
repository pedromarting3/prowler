from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_tenants_user_creation_disabled(Check):
    def execute(self) -> Check_Report_Azure:
        print(entra_client.users)
