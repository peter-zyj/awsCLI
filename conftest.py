import pytest

def pytest_addoption(parser):
    parser.addoption("--trs", action="store_true", default=False, help="trouble shooting switcher")
    parser.addoption("--skip_updown", action="store_true", default=False, help="skip setup and teardown")
    parser.addoption("--keyFile", action="store", default=None, help="specified AWS key file")

@pytest.fixture(scope='session')
def trs(request):
    toubleshoot_value = request.config.option.trs
    # if toubleshoot_value is None:
    #     pytest.skip()
    return toubleshoot_value

@pytest.fixture(scope='session')
def skip_updown(request):
    value = request.config.option.skip_updown
    return value

@pytest.fixture(scope='session')
def keyFile(request):
    value = request.config.option.keyFile
    return value