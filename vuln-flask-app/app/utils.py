import requests


def remote_request(url: str) -> str:
    resp = requests.get(url, timeout=10)
    return resp.text


def check_remote_target(target: str) -> bool:
    safe_targets = [
        "https://www.baidu.com/",
    ]
    for t in safe_targets:
        if target.startswith(t):
            return True
    return False


def safe_remote_request(url: str) -> str:
    if check_remote_target(url):
        return remote_request(url)
    else:
        raise Exception("unsafe host")
