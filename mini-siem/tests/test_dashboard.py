"""UI integration uses an isolated database, including persisted rule changes."""
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from streamlit.testing.v1 import AppTest
import database

def test_dashboard_with_sample_data():
    project = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as folder:
        db = Path(folder) / "dashboard.db"
        database.initialize(db)
        for name, expected in [("normal.log", 0), ("suspicious.log", 4)]:
            result = database.ingest(db, (project / "sample_logs" / name).read_bytes(), name)
            assert result["alerts"] == expected
        with patch.dict(os.environ, {"SIEM_DB":str(db)}):
            app = AppTest.from_file(str(project / "app.py")).run(timeout=30)
            assert not app.exception
            assert [metric.value for metric in app.metric] == ["26", "13", "13", "4"]
            next(w for w in app.selectbox if w.label == "Investigation status").select("Resolved")
            app.text_area[0].input("Reviewed against the synthetic lab scenario")
            next(b for b in app.button if b.label == "Save status").click()
            app.run(timeout=30)
            assert not app.exception
            assert any(a["status"] == "Resolved" for a in database.rows(db, "alerts"))
            next(w for w in app.number_input if w.label == "Failed login count").set_value(20)
            next(b for b in app.button if b.label == "Apply rules and reanalyze").click()
            app.run(timeout=30)
            assert not app.exception
            assert database.get_config(db).failure_threshold == 20

def test_empty_dashboard():
    project = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"SIEM_DB":str(Path(folder)/"empty.db")}):
        app = AppTest.from_file(str(project/"app.py")).run(timeout=30)
        assert not app.exception
        assert [metric.value for metric in app.metric] == ["0","0","0","0"]
