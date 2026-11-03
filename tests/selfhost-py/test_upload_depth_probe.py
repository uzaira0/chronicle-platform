"""The live probe must distinguish parser constraints from schema rejection."""
import json
import os
from pathlib import Path
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]


class UploadDepthProbeTests(unittest.TestCase):
    def test_generic_schema_rejection_cannot_prove_a_depth_bound(self):
        contract = json.loads((ROOT / "chronicle-server/src/test/resources/upload-probe-contract.json").read_text())
        limit = json.loads((ROOT / "generated/upload-limits.json").read_text())["MAX_REQUEST_SIZE_BYTES"]
        for bounded in (True, False):
            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                    code = 413 if len(body) > limit else 200 if body == b"[]" and "%2F" not in self.path else 400
                    response = {"code": contract["constraintErrorCode"]} if bounded and b'"padding"' in body else {}
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(response).encode())

                def log_message(self, *args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                result = subprocess.run(["bash", str(ROOT / "tests/security/file-upload-tests.sh")],
                    env=dict(os.environ, BASE_URL=f"http://127.0.0.1:{server.server_port}", API_KEY="synthetic",
                             TEST_STUDY_ID="fixture-study", TEST_PARTICIPANT_ID="fixture-participant", TEST_RANDOM_DEVICE_ID="fixture-device"),
                    text=True, capture_output=True, timeout=30)
                self.assertEqual(bounded, result.returncode == 0, result.stdout + result.stderr)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()
