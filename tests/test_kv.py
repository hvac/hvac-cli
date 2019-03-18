import copy
import logging
import hvac
from hvac_cli.kv import KVCLI, kvcli_factory, ReadSecretVersion, SecretVersion
import mock
import pytest


def test_kvcli_factory(mocker, caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')
    mocker.patch('hvac_cli.kv.kvcli_factory')
    mocker.patch('hvac_cli.kv.CLI.list_mounts', side_effect=ValueError)
    args = mock.MagicMock()
    args.kv_version = None
    with pytest.raises(ValueError):
        kvcli_factory(args, args)
    assert 'failed to read sys/mount to determine' in caplog.text


def test_sanitize_do_nothing():
    args = mock.MagicMock()
    args.no_workaround_6282 = None
    status = {'version': '1.1.0'}
    assert KVCLI.sanitize('a/b/c', status, args) == 'a/b/c'
    path = 'éà'
    assert KVCLI.sanitize(path, status, args) == path


def test_sanitize_user_friendly(caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')
    path = '|'.join(["-{:02x}-{}".format(i, chr(i)) for i in range(128)])
    expected = ('-00-_|-01-_|-02-_|-03-_|-04-_|-05-_|-06-_|-07-_|'
                '-08-_|-09-_|-0a-_|-0b-_|-0c-_|-0d-_|-0e-_|-0f-_|'
                '-10-_|-11-_|-12-_|-13-_|-14-_|-15-_|-16-_|-17-_|'
                '-18-_|-19-_|-1a-_|-1b-_|-1c-_|-1d-_|-1e-_|-1f-_|'
                '-20- |-21-!|-22-"|-23-_|-24-$|-25-_|-26-&|-27-\'|'
                '-28-_|-29-)|-2a-_|-2b-_|-2c-,|-2d--|-2e-.|-2f-/|'
                '-30-0|-31-1|-32-2|-33-3|-34-4|-35-5|-36-6|-37-7|'
                '-38-8|-39-9|-3a-:|-3b-;|-3c-<|-3d-=|-3e->|-3f-?|'
                '-40-@|-41-A|-42-B|-43-C|-44-D|-45-E|-46-F|-47-G|'
                '-48-H|-49-I|-4a-J|-4b-K|-4c-L|-4d-M|-4e-N|-4f-O|'
                '-50-P|-51-Q|-52-R|-53-S|-54-T|-55-U|-56-V|-57-W|'
                '-58-X|-59-Y|-5a-Z|-5b-_|-5c-_|-5d-]|-5e-^|-5f-_|'
                '-60-`|-61-a|-62-b|-63-c|-64-d|-65-e|-66-f|-67-g|'
                '-68-h|-69-i|-6a-j|-6b-k|-6c-l|-6d-m|-6e-n|-6f-o|'
                '-70-p|-71-q|-72-r|-73-s|-74-t|-75-u|-76-v|-77-w|'
                '-78-x|-79-y|-7a-z|-7b-{|-7c-||-7d-}|-7e-~|-7f-_')
    args = mock.MagicMock()
    args.no_workaround_6282 = None

    status = {'version': '1.1.0'}
    assert KVCLI.sanitize(path, status, args) == expected
    assert 'bug 6282 was fixed' in caplog.text
    assert 'issues/6282' in caplog.text
    assert 'replace control characters' in caplog.text
    caplog.clear()

    status = {'version': '1.0.3'}
    assert KVCLI.sanitize(path, status, args) == expected
    assert 'bug 6282 was fixed' not in caplog.text
    assert 'issues/6282' in caplog.text
    assert 'replace control characters' in caplog.text
    caplog.clear()

    expected = ('-00-_|-01-_|-02-_|-03-_|-04-_|-05-_|-06-_|-07-_|'
                '-08-_|-09-_|-0a-_|-0b-_|-0c-_|-0d-_|-0e-_|-0f-_|'
                '-10-_|-11-_|-12-_|-13-_|-14-_|-15-_|-16-_|-17-_|'
                '-18-_|-19-_|-1a-_|-1b-_|-1c-_|-1d-_|-1e-_|-1f-_|'
                '-20- |-21-!|-22-"|-23-#|-24-$|-25-_|-26-&|-27-\'|'
                '-28-(|-29-)|-2a-*|-2b-+|-2c-,|-2d--|-2e-.|-2f-/|'
                '-30-0|-31-1|-32-2|-33-3|-34-4|-35-5|-36-6|-37-7|'
                '-38-8|-39-9|-3a-:|-3b-;|-3c-<|-3d-=|-3e->|-3f-?|'
                '-40-@|-41-A|-42-B|-43-C|-44-D|-45-E|-46-F|-47-G|'
                '-48-H|-49-I|-4a-J|-4b-K|-4c-L|-4d-M|-4e-N|-4f-O|'
                '-50-P|-51-Q|-52-R|-53-S|-54-T|-55-U|-56-V|-57-W|'
                '-58-X|-59-Y|-5a-Z|-5b-[|-5c-\\|-5d-]|-5e-^|-5f-_|'
                '-60-`|-61-a|-62-b|-63-c|-64-d|-65-e|-66-f|-67-g|'
                '-68-h|-69-i|-6a-j|-6b-k|-6c-l|-6d-m|-6e-n|-6f-o|'
                '-70-p|-71-q|-72-r|-73-s|-74-t|-75-u|-76-v|-77-w|'
                '-78-x|-79-y|-7a-z|-7b-{|-7c-||-7d-}|-7e-~|-7f-_')

    status = {'version': '1.1.0'}
    args.no_workaround_6282 = True
    assert KVCLI.sanitize(path, status, args) == expected
    assert 'bug 6282 was fixed' not in caplog.text
    assert 'issues/6282' not in caplog.text
    assert 'replace control characters' in caplog.text
    caplog.clear()


def test_sanitize_bug_6213(caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')
    args = mock.MagicMock()
    args.no_workaround_6282 = None
    status = {'version': '1.1.0'}
    path = 'A B /C / D '
    assert KVCLI.sanitize(path, status, args) == 'A B/C/ D'
    assert 'issues/6213' in caplog.text


def mount_kv(vault_server, mount_point, kv_version):
    client = hvac.Client(url=vault_server['http'], token=vault_server['token'])
    client.sys.disable_secrets_engine(path=mount_point)
    client.sys.enable_secrets_engine(
        backend_type='kv', options={'version': kv_version}, path=mount_point)


@pytest.mark.parametrize("kv_version", ['1', '2'])
def test_kv_version(vault_server, kv_version):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, kv_version)

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = kv_version
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    version = None
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    assert kv.read_secret(secret_key, version) == secret_value
    kv.erase()
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, version)


def test_read_secret_version_v1(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '1')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    version = None
    with pytest.raises(SecretVersion):
        kv.create_or_update_secret(secret_key, secret_value, cas=1)
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    assert kv.read_secret(secret_key, version) == secret_value
    with pytest.raises(ReadSecretVersion):
        kv.read_secret(secret_key, '0')
    kv.erase()
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, version)


def test_read_secret_version_v2(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '2')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    KV_args.rewrite_key = True
    KV_args.no_workaround_6282 = None
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    assert kv.read_secret(secret_key, None) == secret_value
    assert kv.read_secret(secret_key, 1) == secret_value
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, 2)
    with pytest.raises(hvac.exceptions.InvalidRequest):
        kv.create_or_update_secret(secret_key, secret_value, cas=0)
    with pytest.raises(hvac.exceptions.InvalidRequest):
        kv.create_or_update_secret(secret_key, secret_value, cas=2)
    kv.create_or_update_secret(secret_key, secret_value, cas=1)
    assert kv.read_secret(secret_key, 2) == secret_value
    kv.erase()
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, None)


def test_metadata_v1(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '1')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    with pytest.raises(SecretVersion):
        kv.read_secret_metadata(secret_key)
    with pytest.raises(SecretVersion):
        kv.update_metadata(secret_key, None, None)


def test_metadata_v2(vault_server, caplog):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '2')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    kv.update_metadata(secret_key, None, None)
    metadata = kv.read_secret_metadata(secret_key)
    assert metadata['data']['max_versions'] == 0
    assert metadata['data']['cas_required'] is False
    max_versions = 5
    cas_required = True
    metadata = kv.update_metadata(secret_key, max_versions, cas_required)
    assert metadata['data']['max_versions'] == max_versions
    assert metadata['data']['cas_required'] == cas_required
    kv.delete_metadata_and_all_versions(secret_key)
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret_metadata(secret_key)

    caplog.clear()
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret_metadata('doesnotexist')
    assert 'failed to read metadata' in caplog.text


def test_delete_version_v1(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '1')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    with pytest.raises(SecretVersion):
        kv.delete(secret_key, versions='1')
    assert kv.delete(secret_key, versions=None) == 0
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, None)
    with pytest.raises(SecretVersion):
        kv.undelete(secret_key, versions='1')


def test_delete_version_v2(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '2')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    for i in ('1', '2', '3'):
        secret_value = {'field': i}
        kv.create_or_update_secret(secret_key, secret_value, cas=None)
        versions = kv.read_secret_metadata(secret_key)['data']['versions']
        assert not versions[i]['deletion_time']
        assert not versions[i]['destroyed']

    assert kv.delete(secret_key, versions=None) == 0
    versions = kv.read_secret_metadata(secret_key)['data']['versions']
    assert versions['3']['deletion_time']
    assert not versions['3']['destroyed']

    assert kv.delete(secret_key, versions=['1', '2']) == 0
    versions = kv.read_secret_metadata(secret_key)['data']['versions']
    for i in ('1', '2'):
        assert versions[i]['deletion_time']
        assert not versions[i]['destroyed']
        with pytest.raises(hvac.exceptions.InvalidPath):
            kv.read_secret(secret_key, i)

    assert kv.undelete(secret_key, versions=['1', '2']) == 0
    versions = kv.read_secret_metadata(secret_key)['data']['versions']
    for i in ('1', '2'):
        assert not versions[i]['deletion_time']
        assert not versions[i]['destroyed']
        assert kv.read_secret(secret_key, i) == {'field': i}


def test_patch_version_v1(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '1')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    with pytest.raises(SecretVersion):
        kv.patch(secret_key, secret_value)


def test_patch_version_v2(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '2')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    KV_args.rewrite_key = True
    KV_args.no_workaround_6282 = None
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {
        'override': 'before',
        'preserved': 'before',
    }
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    assert kv.read_secret(secret_key, None) == secret_value
    override_secret_value = {
        'override': 'after',
        'something': 'else',
    }
    kv.patch(secret_key, override_secret_value)
    expected = copy.copy(secret_value)
    expected.update(override_secret_value)
    assert kv.read_secret(secret_key, None) == expected


def test_destroy_version_v1(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '1')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    with pytest.raises(SecretVersion):
        kv.destroy(secret_key, versions='1')


def test_destroy_version_v2(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '2')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    for i in ('1', '2', '3'):
        secret_value = {'field': i}
        kv.create_or_update_secret(secret_key, secret_value, cas=None)
        versions = kv.read_secret_metadata(secret_key)['data']['versions']
        assert not versions[i]['deletion_time']
        assert not versions[i]['destroyed']

    assert kv.destroy(secret_key, versions=[1, 2]) == 0
    versions = kv.read_secret_metadata(secret_key)['data']['versions']
    for i in ('1', '2'):
        assert not versions[i]['deletion_time']
        assert versions[i]['destroyed']
        with pytest.raises(hvac.exceptions.InvalidPath):
            kv.read_secret(secret_key, i)


def test_rollback_version_v1(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '1')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    with pytest.raises(SecretVersion):
        kv.rollback(secret_key, version='1')


def test_rollback_version_v2(vault_server, caplog):
    caplog.set_level(logging.INFO, 'hvac_cli')
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '2')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.dry_run = None
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}
    for i in ('1', '2', '3'):
        secret_value = {'field': i}
        kv.create_or_update_secret(secret_key, secret_value, cas=None)

    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, '4')
    kv.rollback(secret_key, '2')
    assert kv.read_secret(secret_key, '4') == {'field': '2'}
    caplog.clear()
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.rollback(secret_key, '20')
    assert 'at version 20' in caplog.text


def test_dry_run_version_v1(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '1')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}

    CLI_args.dry_run = True
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, None)

    CLI_args.dry_run = None
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    assert kv.read_secret(secret_key, None) == secret_value

    CLI_args.dry_run = True
    assert kv.delete(secret_key, versions=None) == 0
    assert kv.read_secret(secret_key, None) == secret_value


def test_dry_run_version_v2(vault_server):
    mount_point = 'mysecrets'
    mount_kv(vault_server, mount_point, '2')

    CLI_args = mock.MagicMock()
    CLI_args.token = vault_server['token']
    CLI_args.address = vault_server['http']
    KV_args = mock.MagicMock()
    KV_args.kv_version = None
    KV_args.mount_point = mount_point
    KV_args.rewrite_key = True
    KV_args.no_workaround_6282 = None
    kv = kvcli_factory(CLI_args, KV_args)

    secret_key = 'my/key'
    secret_value = {'field': 'value'}

    CLI_args.dry_run = True
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, None)

    CLI_args.dry_run = None
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    kv.create_or_update_secret(secret_key, secret_value, cas=None)
    assert kv.read_secret(secret_key, None) == secret_value

    CLI_args.dry_run = True
    secret_patch = {'other': 'value'}
    kv.patch(secret_key, secret_patch)
    assert kv.read_secret(secret_key, None) == secret_value

    assert kv.delete(secret_key, versions=None) == 0
    assert kv.read_secret(secret_key, None) == secret_value

    assert kv.destroy(secret_key, versions='2') == 0
    assert kv.read_secret(secret_key, '2') == secret_value

    assert kv.delete_metadata_and_all_versions(secret_key) == 0
    assert kv.read_secret(secret_key, None) == secret_value

    existing_metadata = kv.read_secret_metadata(secret_key)['data']
    max_versions = 5
    cas_required = True
    metadata = kv.update_metadata(secret_key, max_versions, cas_required)['data']
    assert existing_metadata['max_versions'] == metadata['max_versions']
    assert existing_metadata['cas_required'] == metadata['cas_required']

    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, '3')
    assert kv.rollback(secret_key, '1') == 0
    with pytest.raises(hvac.exceptions.InvalidPath):
        kv.read_secret(secret_key, '3')
