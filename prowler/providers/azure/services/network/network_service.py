from dataclasses import dataclass

import requests
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkWatcher

from prowler.lib.logger import logger
from prowler.providers.azure.lib.service.service import AzureService

credential = DefaultAzureCredential()
token = credential.get_token("https://management.azure.com/.default").token


########################## SQLServer
class Network(AzureService):
    def __init__(self, audit_info):
        super().__init__(NetworkManagementClient, audit_info)
        self.security_groups = self.__get_security_groups__()
        self.bastion_hosts = self.__get_bastion_hosts__()

    def __get_security_groups__(self):
        logger.info("SQL Server - Getting Network Security Groups...")
        security_groups = {}
        for subscription, client in self.clients.items():
            try:
                security_groups.update({subscription: []})
                security_groups_list = client.network_security_groups.list_all()
                available_locations = {}
                network_watchers = self.__get_network_watchers__(client, subscription)
                for security_group in security_groups_list:
                    subscription_id = security_group.id.split("/")[2]
                    if subscription_id not in available_locations:
                        available_locations[subscription_id] = (
                            self.__get_subscription_locations__(subscription_id)
                        )
                    subscription_locations = available_locations[subscription_id]
                    security_groups[subscription].append(
                        SecurityGroup(
                            id=security_group.id,
                            name=security_group.name,
                            location=security_group.location,
                            security_rules=security_group.security_rules,
                            network_watchers=network_watchers,
                            subscription_locations=subscription_locations,
                            flow_logs=self.__get_flow_logs__(subscription),
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return security_groups

    def __get_network_watchers__(self, client, subscription):
        logger.info("SQL Server - Getting Network Watchers...")
        client = self.clients[subscription]
        network_watchers = client.network_watchers.list_all()
        return network_watchers

    def __get_subscription_locations__(self, subscription_id):
        logger.info("SQL Server - Getting Subscription Locations...")
        subscription_locations = []
        url = f"https://management.azure.com/subscriptions/{subscription_id}/locations?api-version=2022-12-01"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            for location in data["value"]:
                subscription_locations.append(location["name"])

        return subscription_locations

    def __get_flow_logs__(self, subscription):
        logger.info("SQL Server - Getting Flow Logs...")
        client = self.clients[subscription]
        network_watchers = self.__get_network_watchers__(client, subscription)
        flow_logs = []
        resource_group = "NetworkWatcherRG"
        for network_watcher in network_watchers:
            flow_logs_nw = client.flow_logs.list(resource_group, network_watcher.name)
            for flow_log in flow_logs_nw:
                flow_logs.append(flow_log)
        return flow_logs

    def __get_bastion_hosts__(self):
        logger.info("SQL Server - Getting Bastion Hosts...")
        bastion_hosts = {}
        for subscription, client in self.clients.items():
            try:
                bastion_hosts.update({subscription: []})
                bastion_hosts_list = client.bastion_hosts.list()
                for bastion_host in bastion_hosts_list:
                    bastion_hosts[subscription].append(
                        BastionHost(
                            id=bastion_host.id,
                            name=bastion_host.name,
                            location=bastion_host.location,
                        )
                    )

            except Exception as error:
                logger.error(
                    f"Subscription name: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return bastion_hosts


@dataclass
class BastionHost:
    id: str
    name: str
    location: str


@dataclass
class SecurityGroup:
    id: str
    name: str
    location: str
    security_rules: list
    network_watchers: list[NetworkWatcher]
    subscription_locations: list
    flow_logs: list
