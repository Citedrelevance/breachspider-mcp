

# Audit C4 (2026-11-02): identifying text inside the sent fields refuses the call; real product names do not.
def test_value_reason_identifying():
    from breachspider_mcp.safety import value_reason as r
    assert r("product", "EDS-518A at 192.168.1.20") == "contains an IP address"
    assert r("part_number", "SN 4C2D9988") == "contains a serial number"
    assert r("version", "3.5 serial 4C2D9988") == "contains a serial number"
    assert r("product", "EDS-518A owner jsmith") == "contains a user name"
    assert r("product", "x login: bob") == "contains a user name"


def test_value_reason_real_names_pass():
    from breachspider_mcp.safety import value_reason as r
    for f, v in (("version", "8.10.0.9"), ("version", "10.0.14393.5850"), ("product", "PowerFlex 755 Serial Adapter"),
                 ("product", "Sn 5420 Storage Router"), ("product", "Login Manager"), ("part_number", "SN74LS00"),
                 ("product", "Wireless Lan Controller 8.10.151.0"), ("product", "Easy Username Updater"),
                 ("part_number", "6ES7214-1AG40-0XB0"), ("version", "15.2(7)E4"), ("product", "Script.Aculo.Us")):
        assert r(f, v) == "", (f, v)
