import asyncio
from dataclasses import dataclass

from msgraph import GraphServiceClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService


########################## Entra
class Entra(AzureService):
    def __init__(self, azure_audit_info):
        super().__init__(GraphServiceClient, azure_audit_info)
        self.users = asyncio.get_event_loop().run_until_complete(self.__get_users__())
        self.organizations = asyncio.get_event_loop().run_until_complete(
            self.__get_organizations__()
        )
        self.roles = asyncio.get_event_loop().run_until_complete(self.__get_roles__())

    async def __get_users__(self):
        try:
            users = []

            for subscription, client in self.clients.items():
                users_list = await client.users.get()
                for user in users_list.value:
                    users.append(User(id=user.id, name=user.display_name))
            if users:
                return users
            else:
                return []
        except Exception as error:
            logger.error(
                f"ERROR: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return users

    async def __get_organizations__(self):
        try:
            organizations = []
            for subscription, client in self.clients.items():
                organizations_list = await client.organization.get()
                for organization in organizations_list.value:
                    organizations.append(
                        Organization(id=organization.id, name=organization.display_name)
                    )
            if organizations:
                return organizations
            else:
                return []
        except Exception as error:
            logger.error(
                f"ERROR: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return organizations

    async def __get_roles__(self):
        try:
            roles = []
            scopes = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/"
            client = GraphServiceClient(credentials=self.credentials, scopes=scopes)
            for subscription, client in self.clients.items():
                roles_list = await client.role_management.get()
                print(roles_list)
                for role in roles_list.value:
                    roles.append(Role(id=role.id, name=role.display_name))
            if roles:
                return roles
            else:
                return []
        except Exception as error:
            logger.error(
                f"ERROR: {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return roles


@dataclass
class User:
    id: str
    name: str


@dataclass
class Organization:
    id: str
    name: str


@dataclass
class Role:
    id: str
    name: str
