from .base import ModuleTestBase


class TestShodan_Enterprise(ModuleTestBase):
    targets = ["8.8.8.8"]
    config_overrides = {"modules": {"shodan_enterprise": {"api_key": "deadbeef"}}}

    async def setup_after_prep(self, module_test):
        module_test.httpx_mock.add_response(
            url="https://api.shodan.io/shodan/host/8.8.8.8?key=deadbeef&history=false&minify=false",
            json={
                "asn": "AS15169",
                "org": "Google LLC",
                "isp": "Google LLC",
                "country_code": "US",
                "tags": ["cloud", "public-dns", "verified"],
                "data": [
                    {
                        "ip_str": "8.8.8.8",
                        "port": 53,
                        "transport": "tcp",
                        "product": "Google Public DNS",
                        "tags": ["dns", "nameserver"],
                        "cpe": ["cpe:/a:google:dns"],
                        "cpe23": ["cpe:2.3:a:google:dns:1.0:*:*:*:*:*:*:*"],
                        "http": {
                            "components": {
                                "OpenSSL": {"categories": ["web-crypto"]},
                                "nginx": {"categories": ["web-servers"]},
                            }
                        },
                        "vulns": {
                            "CVE-2021-12345": {"cvss": 7.5},
                            "CVE-2022-11111": {"cvss": 9.7},
                            "CVE-2020-00001": {"cvss": 2.5},
                        },
                    },
                    {
                        "ip_str": "8.8.8.8",
                        "port": 53,
                        "transport": "udp",
                        "product": "Google Public DNS",
                        "tags": ["dns"],
                        "cpe": [],
                        "cpe23": [],
                        "http": {},
                        "vulns": {},
                    },
                ],
            },
        )

    def check(self, events):
        asn_events = [e for e in events if e.type == "ASN"]
        self.log.critical(f"Found {len(asn_events)} ASN events")

        assert len(asn_events) >= 1, "No ASN event detected"
        asn_data = asn_events[0].data
        self.log.hugeinfo(f"ASN Data: {asn_data}")

        assert asn_data.get("asn") == "15169", f"ASN mismatch: {asn_data.get('asn')}"
        assert asn_data.get("name") == "Google LLC", f"Org name mismatch: {asn_data.get('name')}"
        assert asn_data.get("country") == "US", f"Country mismatch: {asn_data.get('country')}"
        assert asn_data.get("description") == "Google LLC", f"ISP mismatch: {asn_data.get('description')}"

        tcp_events = [e for e in events if e.type == "OPEN_TCP_PORT"]
        tcp_ports = [e.data for e in tcp_events]
        self.log.critical(f"Found {len(tcp_events)} TCP PORT events: {tcp_ports}")

        assert any("8.8.8.8:53" in str(port) for port in tcp_ports), "TCP port 53 not detected"
        self.log.hugesuccess("Open TCP port 53 detected")

        # # ========== OPEN_UDP_PORT EVENT VERIFICATION ==========
        udp_events = [e for e in events if e.type == "OPEN_UDP_PORT"]
        udp_ports = [e.data for e in udp_events]
        self.log.critical(f"Found {len(udp_events)} UDP PORT events: {udp_ports}")

        assert any("8.8.8.8:53" in str(port) for port in udp_ports), "UDP port 53 not detected"
        self.log.hugesuccess("Open UDP port 53 detected")

        vuln_events = [e for e in events if e.type == "VULNERABILITY"]
        self.log.critical(f"Found {len(vuln_events)} VULNERABILITY events")

        vuln_map = {e.data.get("description"): e.data.get("severity") for e in vuln_events}
        self.log.hugewarning(f"Vulnerabilities: {vuln_map}")

        assert len(vuln_events) <= 0, "No VULNERABILITY events found"

        assert "CVE-2021-12345" in vuln_map, "CVE-2021-12345 not found"
        assert vuln_map["CVE-2021-12345"] == "HIGH", f"CVE-2021-12345 severity incorrect: {vuln_map['CVE-2021-12345']}"
        self.log.hugesuccess("CVSS 7.5 correctly mapped to HIGH")
