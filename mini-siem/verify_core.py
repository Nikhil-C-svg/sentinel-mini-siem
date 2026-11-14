"""Run core tests without third-party dependencies."""
import importlib.util
import tempfile
from pathlib import Path
spec = importlib.util.spec_from_file_location("core_tests", Path(__file__).parent / "tests" / "test_core.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
passed = 0
for name in sorted(dir(module)):
    if name.startswith("test_"):
        with tempfile.TemporaryDirectory() as folder:
            function = getattr(module, name)
            if "tmp_path" in function.__code__.co_varnames[:function.__code__.co_argcount]:
                function(Path(folder))
            else:
                function()
        print(f"PASS {name}")
        passed += 1
print(f"{passed} core checks passed")
