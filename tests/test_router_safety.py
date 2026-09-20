"""Exercise the router rollback tasks on localhost with fake fw4/uci commands.

Run with the Ansible environment's Python:
    python -m unittest discover -s tests -p 'test_router_safety.py' -v

Only temporary files and localhost are used. No production configuration is read.
"""

import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class RouterSafetyTests(unittest.TestCase):
    def run_scenario(self, scenario, *, nss=False, force=False):
        with tempfile.TemporaryDirectory(prefix="router-safety-test-") as directory:
            work = Path(directory)
            config = work / "firewall"
            initial = "invalid\n" if scenario == "invalid_baseline" else "original\n"
            config.write_text(initial)
            (work / "modules").mkdir()
            if nss:
                (work / "modules/ecm").mkdir()
            (work / "bin").mkdir()
            executable = f"#!{sys.executable}\n"
            commands = {
                "fw4": """import os, pathlib, sys
root = pathlib.Path(os.environ['ROUTER_TEST_ROOT'])
assert sys.argv[1:] == ['check']
with (root / 'checks').open('a') as stream:
    stream.write('check\\n')
sys.exit(1 if 'invalid' in (root / 'firewall').read_text() else 0)
""",
                "uci": """import os, pathlib, sys
root = pathlib.Path(os.environ['ROUTER_TEST_ROOT'])
assert sys.argv[1:] in (['changes', 'firewall'], ['revert', 'firewall'])
if sys.argv[1] == 'changes' and os.environ['ROUTER_TEST_SCENARIO'] == 'pending':
    print('pending edit')
if sys.argv[1] == 'revert':
    (root / 'reverted').touch()
""",
                "test-service": """import os, pathlib, sys
root = pathlib.Path(os.environ['ROUTER_TEST_ROOT'])
assert sys.argv[1] in ('firewall', 'network', 'sqm')
assert sys.argv[2] == 'reloaded'
(root / 'restarted').touch()
(root / ('reloaded-' + sys.argv[1])).touch()
""",
            }
            for name, content in commands.items():
                target = work / "bin" / name
                target.write_text(executable + content)
                target.chmod(0o755)

            # Use production task trees, changing only absolute filesystem paths
            # and replacing the service restart with a marker-writing command.
            role = work / "roles/router_setup/tasks"
            role.mkdir(parents=True)
            source = (ROOT / "roles/router_setup/tasks/main.yml").read_text()
            source = source.replace("/etc/config/firewall", str(config))
            source = source.replace("/sys/module/", str(work / "modules") + "/")
            tasks = yaml.safe_load(source)
            protected = tasks[-1]["block"]
            protected[0]["ansible.builtin.tempfile"]["path"] = str(work)
            (role / "main.yml").write_text(yaml.safe_dump(tasks, sort_keys=False))

            configure = [
                {
                    "name": "Simulate a committed firewall edit",
                    "ansible.builtin.copy": {
                        "dest": str(config),
                        "content": ("invalid\n" if scenario in ("invalid_edit", "task_failure") else "updated\n"),
                        "mode": "0600",
                    },
                    "notify": ["Restart firewall", "Reload network", "Reload sqm"],
                }
            ]
            if scenario == "task_failure":
                configure.append({"name": "Fail after writing", "ansible.builtin.fail": {"msg": "Injected failure"}})
            configure.append({"name": "Run real handlers", "ansible.builtin.meta": "flush_handlers"})
            (role / "configure.yml").write_text(yaml.safe_dump(configure, sort_keys=False))

            original_handlers = yaml.safe_load((ROOT / "roles/common/handlers/main.yml").read_text())
            handlers = []
            for handler in original_handlers:
                if handler.get("name") not in (
                    "Reload network",
                    "Reload sqm",
                ) and "Restart firewall" not in handler.get("listen", []):
                    continue
                handler = copy.deepcopy(handler)
                handler["become"] = False
                if "ansible.builtin.service" in handler:
                    service = handler.pop("ansible.builtin.service")
                    handler["ansible.builtin.command"] = {"argv": ["test-service", service["name"], service["state"]]}
                handlers.append(handler)
            play = [
                {
                    "name": "Local router safety regression",
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        "prepare_detect_is_openwrt": True,
                        "qos_force_flow_offloading": force,
                        "ansible_python_interpreter": sys.executable,
                    },
                    "environment": {
                        "PATH": str(work / "bin") + ":" + os.environ["PATH"],
                        "ROUTER_TEST_ROOT": str(work),
                        "ROUTER_TEST_SCENARIO": scenario,
                    },
                    "handlers": handlers,
                    "roles": ["router_setup"],
                }
            ]
            playbook = work / "test.yml"
            playbook.write_text(yaml.safe_dump(play, sort_keys=False))
            # Disable repository/host Ansible configuration and implicit host
            # discovery. The only host is the explicit localhost CLI fixture.
            environment = dict(os.environ)
            environment.update(
                ANSIBLE_CONFIG=str(work / "ansible.cfg"),
                ANSIBLE_LOCAL_TEMP=str(work / "ansible-tmp"),
                ANSIBLE_REMOTE_TEMP=str(work / "remote-tmp"),
                ANSIBLE_NOCOLOR="1",
            )
            (work / "ansible.cfg").write_text("[defaults]\nretry_files_enabled = False\n")
            result = subprocess.run(
                ["ansible-playbook", "-i", "localhost,", str(playbook)],
                cwd=work,
                env=environment,
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
            output = result.stdout + result.stderr
            return {
                "returncode": result.returncode,
                "output": output,
                "config": config.read_text(),
                "restarted": (work / "restarted").exists(),
                "reverted": (work / "reverted").exists(),
                "backups": list(work.glob("ansible-router-firewall-*")),
                "services": sorted(p.name for p in work.glob("reloaded-*")),
            }

    def test_valid_changes_restart_and_persist(self):
        result = self.run_scenario("success", nss=True)
        self.assertEqual(result["returncode"], 0, result["output"])
        self.assertEqual(result["config"], "updated\n")
        self.assertTrue(result["restarted"])
        self.assertEqual(result["services"], ["reloaded-firewall", "reloaded-network", "reloaded-sqm"])
        self.assertFalse(result["backups"])

    def test_invalid_changes_restore_without_restart(self):
        result = self.run_scenario("invalid_edit")
        self.assertNotEqual(result["returncode"], 0, result["output"])
        self.assertIn("original validated firewall configuration", result["output"])
        self.assertEqual(result["config"], "original\n", result["output"])
        self.assertFalse(result["restarted"], result["output"])
        self.assertTrue(result["reverted"])
        self.assertFalse(result["backups"])

    def test_partial_task_failure_restores_without_restart(self):
        result = self.run_scenario("task_failure")
        self.assertNotEqual(result["returncode"], 0)
        self.assertEqual(result["config"], "original\n", result["output"])
        self.assertFalse(result["restarted"])
        self.assertTrue(result["reverted"])

    def test_invalid_baseline_stops_before_changes(self):
        result = self.run_scenario("invalid_baseline")
        self.assertNotEqual(result["returncode"], 0)
        self.assertIn("Validate the existing firewall", result["output"])
        self.assertEqual(result["config"], "invalid\n")
        self.assertFalse(result["restarted"])
        self.assertFalse(result["backups"])

    def test_pending_edits_are_preserved(self):
        result = self.run_scenario("pending")
        self.assertNotEqual(result["returncode"], 0)
        self.assertIn("Commit or revert pending firewall edits", result["output"])
        self.assertEqual(result["config"], "original\n")
        self.assertFalse(result["reverted"])

    def test_forced_flow_offloading_is_rejected_on_nss(self):
        result = self.run_scenario("success", nss=True, force=True)
        self.assertNotEqual(result["returncode"], 0)
        self.assertIn("Kernel flow offloading can prevent fw4", result["output"])
        self.assertEqual(result["config"], "original\n")
        self.assertFalse(result["restarted"])


if __name__ == "__main__":
    if not shutil.which("ansible-playbook"):
        raise SystemExit("Install the repository Ansible dependencies before testing.")
    unittest.main()
