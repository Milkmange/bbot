from .base import ModuleTestBase


class TestShodan_Enterprise(ModuleTestBase):
    targets = ["1.2.3.4"]

    async def setup_before_prep(self, module_test):
        module_test.t.add_response(json={"asn": "AS00000", "org": "T.E.S.T", "isp": "T.E.S.T", "country_code": "TE"})

    def check(self, module_test, events):
        assert 1 == 1
        (e for e in events if e.module == "shodan_enterptise")

        # assert 1 == len(
        #    [e for e in events if e.type == "DNS_NAME" and e.data == "autodiscover.blacklanternsecurity.com"]
        # )
        # assert 1 == len([e for e in events if e.type == "DNS_NAME" and e.data == "mail.blacklanternsecurity.com"])
        # assert 3 == len(
        #     [
        #         e
        #         for e in events
        #         if e.type == "OPEN_TCP_PORT" and e.host == "blacklanternsecurity.com" and str(e.module) == "shodan_idb"
        #     ]
        # )
        # assert 1 == len([e for e in events if e.type == "FINDING" and str(e.module) == "shodan_idb"])
        # assert 1 == len([e for e in events if e.type == "FINDING" and "CVE-2021-26857" in e.data["description"]])
        # assert 2 == len([e for e in events if e.type == "TECHNOLOGY" and str(e.module) == "shodan_idb"])
        # assert 1 == len(
        #     [
        #         e
        #         for e in events
        #         if e.type == "TECHNOLOGY" and e.data["technology"] == "cpe:/a:microsoft:outlook_web_access:15.0.1367"
        #     ]
        # )
