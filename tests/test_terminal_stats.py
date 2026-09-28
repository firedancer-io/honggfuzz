"""Short real fuzzing sessions retain their final counters and actual phase."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TARGET = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
static volatile uint32_t observed;
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (getenv("HFUZZ_TERMINAL_TEST_SLOW")) usleep(100000);
    if (size) {
        if (data[0] < 85) observed += 1;
        else if (data[0] < 170) observed += 2;
        else observed += 3;
    }
    return 0;
}
"""


class TerminalStatsTest(unittest.TestCase):
    def run_session(self, mode, *options, slow=False):
        with tempfile.TemporaryDirectory(prefix="hfuzz-terminal-") as tmp:
            root = Path(tmp)
            source = root / "target.c"
            source.write_text(TARGET)
            target = root / "target"
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "TMPDIR": tmp,
                "USER": "ci_nouser",
            }
            subprocess.run(
                [
                    str(ROOT / "hfuzz_cc/hfuzz-clang"),
                    "-O1",
                    "-o",
                    str(target),
                    str(source),
                ],
                env=env,
                check=True,
                capture_output=True,
                timeout=30,
            )
            corpus, output, workspace = (
                root / name for name in ("corpus", "output", "workspace")
            )
            for directory in (corpus, output, workspace):
                directory.mkdir()
            for i in range(64 if slow else 3):
                (corpus / str(i)).write_bytes(bytes([i * 3]) * 32)
            sink = root / "metrics.jsonl"
            env.update(
                SOLFUZZ_VECTOR_ENABLE="1",
                SOLFUZZ_EXECUTION_EVENTS_ENABLE="1",
                SOLFUZZ_VECTOR_SINK_PATH=str(sink),
                SOLFUZZ_CH_ENABLE="0",
                SOLFUZZ_HARNESS_CH_ENABLE="0",
                FUZZCORP_TASK_ID="terminal-test-job",
                FUZZCORP_BUNDLE_ID="terminal-test-bundle",
                FUZZCORP_LINEAGE_NAME="terminal-test-lineage",
            )
            if slow:
                env["HFUZZ_TERMINAL_TEST_SLOW"] = "1"
            proc = subprocess.run(
                [
                    str(ROOT / "honggfuzz"),
                    "--run_time",
                    "2",
                    "-n",
                    "1",
                    "-v",
                    "--persistent",
                    "-f",
                    str(corpus),
                    "-o",
                    str(output),
                    "-W",
                    str(workspace),
                    *options,
                    "--",
                    str(target),
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                proc.returncode, 0, proc.stderr[-5000:] + proc.stdout[-5000:]
            )
            if mode == "replay":
                self.assertIn(
                    "Replay mode: mutations/crossover/metrics disabled", proc.stderr
                )
                self.assertFalse(sink.exists())
                return
            self.assertTrue(sink.is_file(), proc.stderr[-5000:])
            rows = [json.loads(line) for line in sink.read_text().splitlines()]
            executions = [row for row in rows if row["_table"] == "execution_events"]
            finals = [
                row
                for row in executions
                if row.get("fuzzer_state", "").endswith("_final")
            ]
            ends = [
                row
                for row in rows
                if row["_table"] == "session_events" and row["event_type"] == "end"
            ]
            self.assertEqual(len(finals), 1, rows)
            self.assertEqual(len(ends), 1, rows)
            final, end = finals[0], ends[0]
            self.assertEqual(final["fuzzer_state"], mode + "_final")
            self.assertGreater(final["total_executions"], 0)
            self.assertEqual(
                sum(row.get("execs_delta", 0) for row in executions),
                end["total_executions"],
            )
            for key in (
                "session_id",
                "task_id",
                "host_name",
                "bundle_id",
                "lineage_name",
                "total_executions",
                "total_crashes",
                "total_hangs",
                "num_coverage_lines",
                "num_coverage_branches",
                "corpus_size",
            ):
                self.assertEqual(final[key], end[key], key)
            self.assertEqual(final["corpus_size"], final["corpus_count"])
            self.assertNotIn("sched_total", final)
            if mode == "dynamic":
                samples = [
                    row for row in executions if row.get("fuzzer_state") == "dynamic"
                ]
                self.assertTrue(samples, executions)
                self.assertGreater(
                    final["total_executions"],
                    max(row["total_executions"] for row in samples),
                )
                self.assertGreater(final["num_coverage_branches"], 0)
                self.assertGreaterEqual(
                    final["coverage_edge_bucket"],
                    max(row["coverage_edge_bucket"] for row in samples),
                )
                self.assertGreater(final["corpus_count"], 0)
                self.assertLess(final["corpus_count"], final["total_executions"])
            else:
                self.assertFalse(
                    any(
                        row.get("fuzzer_state") in ("dynamic", "dynamic_final")
                        for row in executions
                    )
                )

    def test_dynamic_session_finishes_before_the_next_periodic_sample(self):
        self.run_session("dynamic")

    def test_interrupted_corpus_load_stays_dry_run(self):
        self.run_session("dry_run", slow=True)

    def test_replay_keeps_metrics_disabled(self):
        self.run_session("replay", "--replay")

    def test_minimization_is_not_dynamic(self):
        self.run_session("minimize", "--minimize")

    def test_static_mode_is_not_dynamic(self):
        self.run_session("static", "--noinst")


if __name__ == "__main__":
    unittest.main()
