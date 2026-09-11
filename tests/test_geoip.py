from modules import geoip


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def test_lookup_ip_no_ip():
    result = geoip.lookup_ip(None)
    assert result['status'] == 'no_ip'


def test_lookup_ip_success(monkeypatch):
    fake_data = {
        'status': 'success', 'country': 'Russia', 'countryCode': 'RU', 'regionName': 'Moscow',
        'city': 'Moscow', 'zip': '101000', 'lat': 55.75, 'lon': 37.6, 'isp': 'Some Hosting',
        'org': 'Some Hosting Org', 'as': 'AS12345', 'asname': 'SOME-AS',
        'proxy': False, 'hosting': True,
    }
    monkeypatch.setattr(geoip.requests, 'get', lambda url, timeout=4: _FakeResponse(fake_data))

    result = geoip.lookup_ip('185.220.101.45')
    assert result['status'] == 'success'
    assert result['country'] == 'Russia'
    assert result['is_hosting_provider'] is True


def test_lookup_ip_failed_status(monkeypatch):
    monkeypatch.setattr(geoip.requests, 'get',
                         lambda url, timeout=4: _FakeResponse({'status': 'fail', 'message': 'invalid query'}))
    result = geoip.lookup_ip('not-an-ip')
    assert result['status'] == 'failed'


def test_lookup_ip_network_error(monkeypatch):
    def _raise(*args, **kwargs):
        raise ConnectionError('no network')
    monkeypatch.setattr(geoip.requests, 'get', _raise)

    result = geoip.lookup_ip('8.8.8.8')
    assert result['status'] == 'unavailable'


def test_brand_mismatch_hosting_provider_flagged():
    geo_result = {'status': 'success', 'is_hosting_provider': True, 'org': 'Generic Cloud Co', 'isp': 'Generic Cloud'}
    result = geoip.check_brand_mismatch('paypal.com', geo_result)
    assert result['mismatch_detected'] is True


def test_brand_mismatch_no_flag_when_geo_unavailable():
    result = geoip.check_brand_mismatch('paypal.com', {'status': 'unavailable'})
    assert result['mismatch_detected'] is False


def test_brand_mismatch_unexpected_country_flagged():
    geo_result = {'status': 'success', 'country_code': 'RU', 'country': 'Russia',
                  'isp': 'Some ISP', 'is_hosting_provider': False}
    result = geoip.check_brand_mismatch('paypal.com', geo_result, known_brand_countries=['US'])
    assert result['mismatch_detected'] is True
