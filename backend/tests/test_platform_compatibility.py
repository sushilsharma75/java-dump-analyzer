"""Run on Linux and Windows; cover paths, sharing locks and source encodings."""
import asyncio
import shutil
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.paths import analysis_directory, dump_directory
from app.analyzers.source import SourceIndex


def test_native_storage_defaults_and_overrides(tmp_path, monkeypatch):
    import tempfile

    monkeypatch.delenv('DUMP_TMP_DIR', raising=False)
    monkeypatch.delenv('ANALYSIS_DIR', raising=False)
    monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(tmp_path / 'user temp'))
    assert dump_directory() == tmp_path / 'user temp' / 'postmortem'
    assert analysis_directory() == tmp_path / 'user temp' / 'postmortem' / 'analyses'
    monkeypatch.setenv('DUMP_TMP_DIR', str(tmp_path / 'heap uploads'))
    monkeypatch.setenv('ANALYSIS_DIR', str(tmp_path / 'saved reports'))
    assert dump_directory() == tmp_path / 'heap uploads'
    assert analysis_directory() == tmp_path / 'saved reports'


@pytest.mark.skipif(not shutil.which('javac') or not shutil.which('java'), reason='JDK unavailable')
def test_java_source_in_unicode_path_with_crlf(tmp_path):
    root = tmp_path / 'source café 项目'
    folder = root / 'src' / 'sample'
    folder.mkdir(parents=True)
    # Many CRLF lines ensure incorrectly normalized offsets miss the final method.
    text = 'package sample;\r\n' + '// comment\r\n' * 40 + '''class Owner {
    String value;
    void first() { value = "café"; }
    void second() { value = "中文"; }
}
'''.replace('\n', '\r\n')
    path = folder / 'Owner.java'
    path.write_bytes(text.encode('utf-8'))
    index = SourceIndex(root)
    index.build()
    assert index.provenance['java_ast_files'] == 1  # do not silently use fallback
    assert index.relative_path(path) == 'src/sample/Owner.java'
    context = index.context('sample.Owner', method='second')
    assert context['resolution'] == 'javac'
    assert '中文' in '\n'.join(context['method']['lines'])
    field = index.find_field('sample.Owner', 'value')
    related = index.context('sample.Owner', line=field['line'])['related_field_methods']
    assert {m['method'] for m in related} == {'first', 'second'}


def test_rejected_heap_upload_closes_file_before_deleting(tmp_path, monkeypatch):
    from app import main

    monkeypatch.setattr(main, 'TMP_DIR', tmp_path)
    monkeypatch.setattr(main, 'MAX_SYNC_HEAP_DUMP_BYTES', 1)
    real_temp = main.tempfile.NamedTemporaryFile
    real_unlink = main.os.unlink
    created = []

    def track_temp(*args, **kwargs):
        temp = real_temp(*args, **kwargs)
        created.append(temp)
        return temp

    def check_closed(path, *args, **kwargs):
        if created and str(path) == created[0].name:
            assert created[0].closed, 'Windows requires closing the file before unlink'
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(main.tempfile, 'NamedTemporaryFile', track_temp)
    monkeypatch.setattr(main.os, 'unlink', check_closed)

    class Upload:
        filename = 'heap.hprof'

        async def read(self, size):
            return b'too large'

    with pytest.raises(HTTPException) as error:
        asyncio.run(main.analyze_heap_sync(Upload(), quick=False, source_session=None))
    assert error.value.status_code == 413
    assert created[0].closed and not Path(created[0].name).exists()
