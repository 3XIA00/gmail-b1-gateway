"""Data-root layout tests.

Actuated variable: the writer (server / authorize) and the reader (send) resolve
the SAME absolute path for a given data-root, so a frozen proposal / sealed token
is found by the later command. The regression this guards is silent drift between
two inline copies of the layout.
"""

from pathlib import Path

from gateway import paths


def test_layout_is_stable_and_rooted(tmp_path):
    root = str(tmp_path)
    assert paths.proposals_db(root) == str(tmp_path / "proposals" / "proposals.db")
    assert paths.payloads_db(root) == str(tmp_path / "proposals" / "payloads.db")
    assert paths.audit_db(root) == str(tmp_path / "audit" / "audit.db")
    assert paths.token_db(root) == str(tmp_path / "token" / "token.db")


def test_entrypoint_uses_the_shared_layout():
    # The summoned server must open exactly the files `send` later reads; assert
    # build_server sources its proposal/payload paths from this module, so the
    # two cannot drift.
    import inspect

    from gateway import entrypoint

    src = inspect.getsource(entrypoint.build_server)
    assert "paths.proposals_db" in src
    assert "paths.payloads_db" in src


def test_four_paths_are_distinct(tmp_path):
    root = str(tmp_path)
    all_paths = {paths.proposals_db(root), paths.payloads_db(root),
                 paths.audit_db(root), paths.token_db(root)}
    assert len(all_paths) == 4  # no two roles collide on one file
