"""Message-ID generation tests (§2.7).

Actuated variables:
  - uniqueness: N mints -> N distinct ids. make_msgid draws a 64-bit random plus
    time+pid, so a collision in 10^4 draws is astronomically unlikely; we assert
    full uniqueness rather than a tolerance (a real collision is a defect).
  - domain: mandatory, so the local FQDN is never leaked into a header/record.
"""

import re

import pytest

from gateway.message_id import generate_message_id

_MSGID = re.compile(r"^<[^<>@\s]+@example\.com>$")


def test_message_ids_are_unique():
    ids = [generate_message_id(domain="example.com") for _ in range(10000)]
    assert len(set(ids)) == len(ids)                 # no collisions across mints


def test_message_id_is_rfc5322_shaped_with_given_domain():
    for _ in range(50):
        m = generate_message_id(domain="example.com")
        assert _MSGID.match(m), m                     # <local@example.com>


def test_domain_is_required_never_leaks_local_fqdn():
    with pytest.raises(ValueError):
        generate_message_id(domain="")
