"""
tests/unit/test_graphql.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~
GraphQL scanner birim testleri.

Gerçek tespit (introspection açık, batch/alias abuse) canlı GraphQL endpoint'i
gerektirir (entegrasyon kapsamı). Bu birim testler import + yapısal + ağ hatası
dayanıklılığını (çökmeme + FP üretmeme) korur.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import requests

from websecure.scanners.graphql import GraphQLScanner

_TARGET = "http://target.test/graphql"


@pytest.fixture
def gql(mock_session):
    return GraphQLScanner(session=mock_session, results={}, debug=False)


class TestRobustness:
    def test_no_crash_and_no_fp_when_unreachable(self, gql, mock_session):
        """GraphQL endpoint ağ hatası verince: çökme yok VE bulgu yok."""
        err = requests.exceptions.ConnectionError("refused")
        mock_session.get.side_effect = err
        mock_session.post.side_effect = err
        with patch.object(gql, "report_finding") as rep:
            gql.run(_TARGET)  # no raise
        rep.assert_not_called()

    def test_no_crash_on_timeout(self, gql, mock_session):
        err = requests.exceptions.Timeout("timed out")
        mock_session.get.side_effect = err
        mock_session.post.side_effect = err
        gql.run(_TARGET)  # no raise


class TestStructure:
    def test_inherits_basescanner(self, gql):
        from websecure.scanners.base import BaseScanner
        assert isinstance(gql, BaseScanner)

    def test_run_callable(self, gql):
        assert callable(gql.run)
