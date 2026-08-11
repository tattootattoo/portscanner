from portscanner.protocols import sip


def test_build_options_request_structure():
    msg = sip._build_options_request("10.0.0.1", 5060)
    text = msg.decode()
    assert text.startswith("OPTIONS sip:probe@10.0.0.1:5060 SIP/2.0\r\n")
    assert "Max-Forwards: 0" in text  # prevents the request from being forwarded deeper into the network
    assert "Call-ID:" in text
    assert text.endswith("\r\n\r\n")


def test_classify_response_accepts_200_ok():
    reply = b"SIP/2.0 200 OK\r\nServer: TestPCSCF/1.0\r\nContent-Length: 0\r\n\r\n"
    result = sip._classify_response(reply)
    assert result is not None
    assert result.confidence == "confirmed"
    assert "200" in result.detail
    assert "TestPCSCF/1.0" in result.detail


def test_classify_response_accepts_error_status():
    reply = b"SIP/2.0 483 Too Many Forwards\r\nContent-Length: 0\r\n\r\n"
    result = sip._classify_response(reply)
    assert result is not None
    assert "483" in result.detail


def test_classify_response_rejects_non_sip():
    assert sip._classify_response(b"HTTP/1.1 200 OK\r\n\r\n") is None
    assert sip._classify_response(b"garbage data") is None


def test_sip_registered_for_tcp_hint_ports():
    from portscanner.models import Transport
    from portscanner.protocols.base import detectors_for
    for port in (5060, 5061):
        names = [d.name for d in detectors_for(Transport.TCP, port)]
        assert names[0] == "SIP/IMS"
