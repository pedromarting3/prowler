from msgraph import GraphServiceClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Entra
class Entra(AzureService):
    async def __init__(self, azure_audit_info):
        super().__init__(GraphServiceClient, azure_audit_info)
        self.domains = await self.__get_domains__()
        self.client = self.clients[azure_audit_info.identity.subscriptions[0]]

    async def __get_domains__(self):

        try:
            domains = await self.client.domains.get()
            print(domains)
        except Exception as error:
            logger.error(
                f"ERROR: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
