# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_Port_Scanner
# Purpose:     SpiderFoot plug-in for open/filtered ports discovery using NMAP.
#
# Author:      Manuel Barrera Lopez
#
# Created:     30/01/2022
# Copyright:   (c) Manuel Barrera Lopez 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin, subprocess, nmap

def analisys():
    nm=nmap.PortScanner()
    IP=str(input("Type the IP you want to analize. \n"))
    nm.scan(IP)
    Report=nm.csv()
    Results = open("Report.txt", "w")
    Results.write(Report)

class sfp_new_module(SpiderFootPlugin):

    meta = {
        'name': "Port Scanner",
        'summary': "Perform a open/filtered ports discovery using NMAP. VPN Recommended",
        'flags': [""],
        'useCases': ["Analisys"],
        'categories': ["Reconnoisance, Discovery, Services"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TCP_PORT_OPEN", "UDP_PORT_OPEN"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["TCP_PORT_OPEN", "UDP_PORT_OPEN"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            analisys()
            Ports =str(subprocess.check_output("cut -d ';' -f 5,6,7 Report.txt", shell=True))
            PortsCleanUp1 = Puertos.replace("\\n", "\n")
            PortsCleanUp2 = PortsCleanUp1.replace("b\'", "")
            PortsCleanUp3 = PortsCleanUp2.replace(";", " ")
            PortsCleanUp4 = PortsCleanUp3.replace("\'", "")
            data = PortsCleanUp4

            if not data:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        typ = "TCP_PORT_OPEN", "UDP_PORT_OPEN"

        evt = SpiderFootEvent(typ, data, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_Port_Scanner
