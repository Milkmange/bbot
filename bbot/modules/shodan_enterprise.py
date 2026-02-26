import shodan
from bbot.modules.base import BaseModule


class shodan_enterprise(BaseModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["OPEN_TCP_PORT", "TECHNOLOGY", "OPEN_UDP_PORT", "ASN", "VULNERABILITY"]
    flags = ["passive"]
    meta = {
        "created_date": "2023-08-04",
        "author": "@Control-Punk-Delete",
        "description": "Shodan Enterprise API integration module. Returns all services that have been found on the given host IP.",
    }
    deps_pip = ["shodan"]
    options = {"api_key": "", "history": False, "minify": False}
    options_desc = {
        "api_key": "Shodan API Key",
        "history": "(optional) True if you want to grab the historical (non-current) banners for the host, False otherwise.",
        "minify": "(optional) True to only return the list of ports and the general host information, no banners, False otherwise.",
    }
    per_host_only = True
    scope_distance_modifier = 1
    target_only = True

    async def setup(self):
        if not self.config.get("api_key"):
            return None, "No API key specified"

        self.api_key = self.config.get("api_key")
        self.history = self.config.get("history")
        self.minify = self.config.get("minify")
        return True

    async def handle_event(self, event):
        try:
            api = shodan.Shodan(self.api_key)

            host = api.host(ips=event.data, history=self.history, minify=self.minify)

            # ASN Extraction
            asn = {
                "asn": host["asn"][2:],
                "name": host["org"],
                "description": host["isp"],
                "country": host["country_code"],
            }
            await self.emit_event(
                asn,
                "ASN",
                parent=event,
                tags=[],
                context=f"Shodan make a request about host {event.data} request and find ASN",
            )

            if "data" in host:
                for data in host["data"]:
                    # TECHNOLOGY Extraction
                    if "cpe" in data:
                        for technology in data["cpe"]:
                            tech = {"technology": technology, "host": data["ip_str"], "port": data["port"]}
                            await self.emit_event(
                                tech,
                                "TECHNOLOGY",
                                parent=event,
                                tags=[],
                                context=f"Shodan make a request about host {event.data} request and find TECHNOLOGY: {technology}",
                            )

                    if "cpe23" in data:
                        for technology in data["cpe23"]:
                            tech = {"technology": technology, "host": data["ip_str"], "port": data["port"]}
                            await self.emit_event(
                                tech,
                                "TECHNOLOGY",
                                parent=event,
                                tags=[],
                                context=f"Shodan make a request about host {event.data} request and find TECHNOLOGY: {technology}",
                            )

                    # OPEN_TCP_PORT, OPEN_UDP_PORT Extraction
                    if "port" in data and "transport" in data:
                        if data["transport"] == "tcp":
                            await self.emit_event(
                                self.helpers.make_netloc(event.data, data["port"]), "OPEN_TCP_PORT", parent=event
                            )

                        elif data["transport"] == "udp":
                            await self.emit_event(
                                self.helpers.make_netloc(event.data, data["port"]), "OPEN_UDP_PORT", parent=event
                            )

                        else:
                            self.warning(f"[WARNING] unknown transport {data['transport']}")

                    # VULNERABILITY Extraction
                    if "vulns" in data:
                        for item in data["vulns"]:
                            cve = item
                            vuln = {
                                "host": data["ip_str"],
                                "severity": "LOW",
                                "description": f'{cve}. {data["vulns"][item].get("summary")}',
                                "name": cve,
                                "cve": cve,
                                "kev": data["vulns"][item].get("kev") or None,
                                "ranking_epss": data["vulns"][item].get("ranking_epss"),
                                "cvss": data["vulns"][item].get("cvss"),
                                "cvss_v2": data["vulns"][item].get("cvss_v2"),
                                "epss": data["vulns"][item].get("epss"),
                                "verified": data["vulns"][item].get("verified"),
                                "references": data["vulns"][item].get("references") or None,
                            }

                            await self.emit_event(
                                vuln,
                                "VULNERABILITY",
                                parent=event,
                                tags=["shodan"],
                                context=f"Shodan make a request about host {event.data} request and find {cve}",
                            )

            else:
                self.info("[INFO] No data to extract")

        except shodan.APIError as e:
            self.error(f"[ERROR] Shodan API key error: {e}")
