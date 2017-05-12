# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# Datadog.py based on Zabbix.py

import sys
import urllib.request
import urllib.parse
import urllib.error
import time
import socket

import requests
import re

from Nagstamon.Helpers import (HumanReadableDurationFromTimestamp,
                               webbrowser_open)
from Nagstamon.Config import conf
from Nagstamon.Objects import (GenericHost,
                               GenericService,
                               Result)
from Nagstamon.Servers.Generic import GenericServer

class DatadogServer(GenericServer):

    """
       special treatment for Datadog using its API
    """
    TYPE = 'Datadog'

    def __init__(self, **kwds):
        GenericServer.__init__(self, **kwds)

        # Prepare all urls needed by nagstamon -
        self.urls = {
                        "human_hosts": "https://app.datadoghq.com/infrastructure",
                        "human_services": "https://app.datadoghq.com/monitors#triggered",
                        "human_host": "https://app.datadoghq.com/dash/host_name/",
                        "human_service": "https://app.datadoghq.com/dash/host_name/",
                    }

        # Map Datadog monitor states with Nagios ones
        self.statemap = {
                            'OK': 'OK',
                            'Warn': 'WARNING',
                            'Alert': 'CRITICAL',
#                            'No Data': 'CRITICAL',
                        }

        # Entries for monitor default actions in context menu
        self.MENU_ACTIONS = ["Monitor", "Acknowledge", "Downtime"]
        self.username     = conf.servers[self.get_name()].username
        self.password     = conf.servers[self.get_name()].password

        self.params       = { 'api_key': conf.servers[self.get_name()].username, 'application_key': conf.servers[self.get_name()].password }

    def _login(self):
        validation = requests.get("https://app.datadoghq.com/api/v1/validate", params=self.params).json()
        if 'errors' in validation.keys():
            if conf.debug_mode is True:
                self.Debug(server=self.get_name(), debug="datadog login failure: " + str(validation['errors']))
            return False
        return True

    def _get_status(self):
        """
            Get status from Datadog Server
        """
        # create Nagios items dictionary with to lists for services and hosts
        # every list will contain a dictionary for every failed service/host
        # this dictionary is only temporarily
        # nagitems = {"services": [], "hosts": []}

        if not self._login():
            return Result(result='datadog login failure', error='login failure')

        # Query hosts
        payload = self.params.copy()
        payload['q'] = ''
        hosts = requests.get("https://app.datadoghq.com/api/v1/search", params=payload).json()['results']['hosts']

        # Query tags
        payload = self.params.copy()
        tags = requests.get("https://app.datadoghq.com/api/v1/tags/hosts", params=payload).json()['tags']

        # Host name map table
        host_name_tag = {}

        for host in hosts:
            new_host  = host

            for i in [tag for tag in tags if re.search(r'^name:.*', tag)]:
                if new_host in tags[i]:
                    host_name_tag[new_host] = i.replace('name:', '', 1)

            self.new_hosts[new_host] = GenericHost()
            self.new_hosts[new_host].name = host_name_tag.get(new_host, new_host)
            self.new_hosts[new_host].status = 'UP'
            self.new_hosts[new_host].last_check = 'n/a'
            self.new_hosts[new_host].duration = 'n/a'
            self.new_hosts[new_host].attempt = 'n/a'
            self.new_hosts[new_host].status_information = 'n/a'
            self.new_hosts[new_host].site = 'Datadog'
            self.new_hosts[new_host].address = new_host

        payload = self.params.copy()
        payload['group_states'] = 'all'
        monitors = requests.get("https://app.datadoghq.com/api/v1/monitor", params=payload).json()

        for monitor in monitors:
            monitor_name = monitor['name']
            for host in monitor['state']['groups']:
                monitor_host        = host.replace('host:', '', 1)
                monitor_host_status = monitor['state']['groups'][host]['status']

                new_service = monitor_name
                self.new_hosts[monitor_host].services[new_service] = GenericService()
                self.new_hosts[monitor_host].services[new_service].host = host_name_tag.get(monitor_host, monitor_host)
                self.new_hosts[monitor_host].services[new_service].name = new_service
                self.new_hosts[monitor_host].services[new_service].status = self.statemap.get(monitor_host_status, 'UNKNOWN')
                self.new_hosts[monitor_host].services[new_service].last_check = 'n/a'
                self.new_hosts[monitor_host].services[new_service].duration = 'n/a'
                self.new_hosts[monitor_host].services[new_service].attempt = '1/1'
                self.new_hosts[monitor_host].services[new_service].status_information = monitor_host_status
                self.new_hosts[monitor_host].services[new_service].passiveonly = False
                self.new_hosts[monitor_host].services[new_service].flapping = False
                self.new_hosts[monitor_host].services[new_service].site = 'Datadog'
                self.new_hosts[monitor_host].services[new_service].address = monitor_host
                self.new_hosts[monitor_host].services[new_service].command = 'Datadog'
                self.new_hosts[monitor_host].services[new_service].triggerid = 1234

        return Result()

    def _open_browser(self, url):
        webbrowser_open(url)

        if conf.debug_mode is True:
            self.Debug(server=self.get_name(), debug="Open web page " + url)

    def open_services(self):
        self._open_browser(self.urls['human_services'])

    def open_hosts(self):
        self._open_browser(self.urls['human_hosts'])

    def open_monitor(self, host, service=""):
        """
            open monitor from treeview context menu
        """

        if service == "":
            url = self.urls['human_host'] + host
        else:
            url = self.urls['human_host'] + host

        if conf.debug_mode is True:
            self.Debug(server=self.get_name(), host=host, service=service,
                       debug="Open host/service monitor web page " + url)
        webbrowser_open(url)

    def GetHost(self, host):
        """
            find out ip or hostname of given host to access hosts/devices which do not appear in DNS but
            have their ip saved in Nagios
        """

        # the fasted method is taking hostname as used in monitor
        if conf.connect_by_host is True:
            return Result(result=host)

        ip = ""

        try:
            if host in self.hosts:
                ip = self.hosts[host].address
            if conf.debug_mode is True:
                self.Debug(server=self.get_name(), host=host, debug="IP of %s:" % host + " " + ip)

            if conf.connect_by_dns is True:
                try:
                    address = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    address = ip
            else:
                address = ip
        except ZabbixError:
            result, error = self.Error(sys.exc_info())
            return Result(result=result, error=error)

        return Result(result=address)

    def _set_recheck(self, host, service):
        pass

    def get_start_end(self, host):
        return time.strftime("%Y-%m-%d %H:%M"), time.strftime("%Y-%m-%d %H:%M", time.localtime(time.time() + 7200))

    def _action(self, site, host, service, specific_params):
        params = {
            'site': self.hosts[host].site,
            'host': host,
        }
        params.update(specific_params)

        if self.zapi is None:
            self._login()
        events = []
        for e in self.zapi.event.get({'triggerids': params['triggerids'],
                                      'hide_unknown': True,
                                      'sortfield': 'clock',
                                      'sortorder': 'desc'}):
            events.append(e['eventid'])
        self.zapi.event.acknowledge({'eventids': events, 'message': params['message']})

    def _set_downtime(self, host, service, author, comment, fixed, start_time, end_time, hours, minutes):
        pass

    def _set_acknowledge(self, host, service, author, comment, sticky, notify, persistent, all_services=[]):
        triggerid = self.hosts[host].services[service].triggerid
        p = {
            'message': '%s: %s' % (author, comment),
            'triggerids': [triggerid],
        }
        self._action(self.hosts[host].site, host, service, p)

        # acknowledge all services on a host when told to do so
        for s in all_services:
            self._action(self.hosts[host].site, host, s, p)
