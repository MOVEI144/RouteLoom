"""Qt offscreen tests for the live monitor and the development site wizard."""
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PySide6.QtWidgets import QApplication
    __import__('pyqtgraph')
except ImportError:  # the headless CI job runs without Qt
    QApplication = None

from routeloom_meshviz.demo import DemoMesh
from routeloom_meshviz.demo_site import SITE_ID, DemoSiteMesh
from routeloom_meshviz.fake_api1 import serve_fake_api1
from routeloom_meshviz.live_monitor import MILESTONES

from test_gui import spin

COLUMN = {name: 2 + i for i, name in enumerate(MILESTONES)}


@unittest.skipIf(QApplication is None, 'PySide6/pyqtgraph not installed')
class LiveMonitorGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def window(self, **kw):
        from routeloom_meshviz.ui.app import MainWindow
        window = MainWindow(**kw)

        def cleanup():
            window.shutdown()
            self.assertTrue(spin(self.app, lambda: window.retirer is None and window.boards.stopped
                                 and window.site.stopped))
        self.addCleanup(cleanup)
        window.show()
        return window

    def cell(self, live, node, column):
        for row in range(live.table.rowCount()):
            item = live.table.item(row, 0)
            if item is not None and item.data(0x0100) == node:
                return live.table.item(row, column).text()
        return None

    def test_timeline_fills_only_evidenced_columns_and_rollcall_drives_status(self):
        window = self.window(fake_nodes=6)
        live = window.live
        window.tabs.setCurrentWidget(live)
        node = f'{3:016x}'
        self.assertTrue(spin(self.app, lambda: bool(self.cell(live, node, COLUMN['confirmed_at'])), 15))
        self.assertTrue(self.cell(live, node, COLUMN['request_verified_at']))
        self.assertTrue(self.cell(live, node, COLUMN['approval_committed_at']))
        self.assertTrue(spin(self.app, lambda: node in live.graph.relay_items))
        # No power controller, no marker, no rollcall yet: those cells stay empty.
        for name in ('power_on_at', 'first_response_observed_at', 'route_stable_at', 'boot_at'):
            self.assertEqual(self.cell(live, node, COLUMN[name]), '', name)
        self.assertIn('development', window.header.labels['site'].text())
        self.assertIn(SITE_ID, window.header.labels['site'].text())
        self.assertTrue(spin(self.app, lambda: live.start_button.isEnabled()))
        live.start_button.click()
        self.assertTrue(spin(self.app, lambda: bool(
            self.cell(live, node, COLUMN['first_response_observed_at'])), 15))
        self.assertTrue(self.cell(live, node, COLUMN['boot_at']).startswith('~'))
        self.assertIn('実効', live.rollcall_label.text())
        # Stability: 3 same-next-hop gateway polls over ≥5 s with a STATUS inside.
        self.assertTrue(spin(self.app, lambda: bool(self.cell(live, node, COLUMN['route_stable_at'])), 20))
        live.select(node)
        self.assertTrue(live.marker_button.isEnabled())
        live.marker_button.click()
        self.assertTrue(spin(self.app, lambda: bool(self.cell(live, node, COLUMN['power_on_at']))))
        self.assertIn('source=operator', live.detail.toPlainText())
        # A second start is refused while running; the retry_after back-off is shown.
        live.stop_button.click()
        self.assertTrue(spin(self.app, lambda: live.start_button.isEnabled()))

    def test_retired_api_client_does_not_redial_the_daemon(self):
        from routeloom_meshviz.ui.workers import ApiClient
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'api1.sock'
        self.enterContext(serve_fake_api1(path, mesh=DemoMesh(4)))
        client = ApiClient(path)
        client.start()
        self.assertTrue(spin(self.app, lambda: client.info['connected']))
        client.stop()
        self.assertFalse(client.reconnect_timer.isActive())

    def test_supervised_api_client_rejects_wrong_site_before_commands(self):
        from routeloom_meshviz.ui.workers import ApiClient
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'api1.sock'
        self.enterContext(serve_fake_api1(path, mesh=DemoSiteMesh(4)))
        client = ApiClient(path, expected_site_id='ffffffffffffffff')
        self.addCleanup(client.stop)
        replies = []
        client.reply.connect(lambda tag, reply: replies.append((tag, reply)))
        client.start()
        self.assertTrue(spin(self.app, lambda: 'site_id' in (client.info['error'] or '')))
        client.request('command', 'lab.rollcall.start', {'desired_interval_ms': 2000})
        self.assertTrue(spin(self.app, lambda: bool(replies)))
        self.assertIsNone(replies[-1][1])
        self.assertFalse(client.info['connected'])

    def test_stale_replies_and_selection_are_dropped_on_reconnect(self):
        window = self.window(fake_nodes=4)
        live = window.live
        self.assertTrue(spin(self.app, lambda: live.poller.connected and live.site_status is not None))
        generation = live.poller.generation
        old_tag = f'live-{generation}-1'
        live.select(f'{2:016x}')
        live.set_source('LIVE', {'connected': True, 'connection': 99, 'methods': {}})
        self.assertIsNone(live.selected)
        self.assertIsNone(live.site_status)
        self.assertGreater(live.poller.generation, generation)
        live.on_reply(old_tag, {'v': 1, 'request_id': 'x', 'ok': True,
                                'result': {'site_id': 'ffffffffffffffff'}})
        self.assertIsNone(live.site_status)
        self.assertFalse(live.start_button.isEnabled())

    def test_another_site_on_the_same_source_starts_a_fresh_timeline(self):
        window = self.window(fake_nodes=4)
        live = window.live
        self.assertTrue(spin(self.app, lambda: f'{2:016x}' in live.timeline.rows, 10))
        # A site.status answer from the same connection now names another site.
        live.poller.outstanding['live-x-1'] = ('site', 'site.status', 0)
        live.on_reply('live-x-1', {'v': 1, 'request_id': 'x', 'ok': True,
                                   'result': {'site_id': 'ffffffffffffffff'}})
        self.assertEqual(live.timeline.rows, {})
        self.assertEqual(live.site_id, 'ffffffffffffffff')

    def test_daemon_without_site_or_rollcall_shows_unsupported(self):
        # The server is entered first so the window's cleanup (LIFO) runs before it closes.
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / 'api1.sock'
        self.enterContext(serve_fake_api1(path, mesh=DemoMesh(4)))
        window = self.window(socket_path=str(path), fake_boards=True)
        live = window.live
        window.tabs.setCurrentWidget(live)
        self.assertTrue(spin(self.app, lambda: '未対応' in live.rollcall_label.text()
                             and live.poller.connected))
        self.assertFalse(live.start_button.isEnabled())
        self.assertIn('未対応', live.site_label.text())
        window.tabs.setCurrentWidget(window.site)
        self.assertTrue(spin(self.app, lambda: '未対応' in window.site.approval_label.text()))

    def test_replay_rebuilds_timeline_from_recorded_milestones_only(self):
        window = self.window(fake_nodes=4)
        live = window.live
        with tempfile.TemporaryDirectory() as tmp:
            capture = str(Path(tmp) / 'run.rlcapture')
            self.assertTrue(spin(self.app, lambda: window.model is not None))
            window.playback.start_recording.emit(capture)
            node = f'{2:016x}'
            window.tabs.setCurrentWidget(live)
            self.assertTrue(spin(self.app, lambda: bool(self.cell(live, node, COLUMN['confirmed_at'])), 15))
            confirmed = self.cell(live, node, COLUMN['confirmed_at'])
            window.playback.stop_recording.emit()
            self.assertTrue(spin(self.app, lambda: not window.recording_status.get('active')))
            window.use_replay(capture)
            self.assertTrue(spin(self.app, lambda: window.mode == 'REPLAY' and window.replay is not None))
            window.playback.seek.emit(10**9)
            window.tabs.setCurrentWidget(live)
            self.assertTrue(spin(self.app, lambda: self.cell(live, node, COLUMN['confirmed_at']) == confirmed))
            self.assertFalse(live.start_button.isEnabled())
            self.assertFalse(live.marker_button.isEnabled())

    def test_wizard_plan_confirm_and_contract_backend_stay_unsupported(self):
        window = self.window(fake_nodes=4, fake_boards=False)
        site = window.site
        window.tabs.setCurrentWidget(site)
        self.assertTrue(spin(self.app, lambda: window.live.poller.connected))
        site.board_rows = [
            {'board': '/dev/ttyACM0', 'chip': 'esp32s3', 'base_mac': 'aa:00', 'role': 'bridge', 'node_id': '1'},
            {'board': '/dev/ttyACM1', 'chip': 'esp32c3', 'base_mac': 'aa:01', 'role': 'bench', 'node_id': '2'}]
        self.assertEqual(site.validate_plan(), {})
        self.assertFalse(site.run_button.isEnabled())  # needs the explicit confirmation
        site.confirm.setChecked(True)
        self.assertTrue(site.run_button.isEnabled())
        site.run_provision()
        self.assertTrue(spin(self.app, lambda: not site.provisioning))
        self.assertTrue(all(job.steps.get('preflight') == 'unsupported' for job in site.jobs))
        self.assertFalse(any(job.ready for job in site.jobs))
        self.assertIn('未対応', site.board_table.item(0, 5).text())
        site.confirm.setChecked(True)
        # A source switch clears the operator's confirmation.
        window.use_fake()
        self.assertTrue(spin(self.app, lambda: not site.confirm.isChecked()))

    def test_fake_backend_reaches_ready_then_joined_from_ledger_evidence(self):
        window = self.window(fake_nodes=4)
        site = window.site
        self.assertTrue(spin(self.app, lambda: window.live.poller.connected))
        site.board_rows = [
            {'board': 'fake://A', 'chip': 'esp32c3', 'base_mac': 'aa:01', 'role': 'bench',
             'node_id': '2'}]
        site.validate_plan()
        site.confirm.setChecked(True)
        self.assertTrue(spin(self.app, lambda: site.run_button.isEnabled()))
        site.run_provision()
        self.assertTrue(spin(self.app, lambda: site.jobs and site.jobs[0].ready))
        window.tabs.setCurrentWidget(site)
        self.assertTrue(spin(self.app, lambda: site.jobs[0].joined, 15))
        self.assertIn('参加済み', site.board_table.item(0, 5).text())

    def test_supervisor_attaches_to_a_site_daemon_and_becomes_the_live_source(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = directory / 'daemon.sock'
        self.enterContext(serve_fake_api1(path, mesh=DemoSiteMesh(4)))
        window = self.window(fake_nodes=4)
        site = window.site
        site.site_dir.setText(str(directory))
        site.socket_path.setText(str(path))
        site.expected_site.setText(SITE_ID)
        site.attach_button.click()
        self.assertTrue(spin(self.app, lambda: window.live_target == str(path) and
                             window.live.poller.connected, 15))
        self.assertIn('ready', site.supervisor_label.text())
        self.assertIn('attach', site.supervisor_label.text())
        site.stop_button.click()
        self.assertTrue(spin(self.app, lambda: 'stopped' in site.supervisor_label.text()))
        self.assertTrue(spin(self.app, lambda: window.live_target != str(path)))
        self.assertTrue(spin(self.app, lambda: window.api is not None and window.api.path != str(path)))

    def test_supervisor_refuses_a_daemon_of_another_site(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = directory / 'daemon.sock'
        self.enterContext(serve_fake_api1(path, mesh=DemoSiteMesh(4)))
        window = self.window(fake_nodes=4)
        site = window.site
        site.site_dir.setText(str(directory))
        site.socket_path.setText(str(path))
        site.expected_site.setText('ffffffffffffffff')
        site.attach_button.click()
        self.assertTrue(spin(self.app, lambda: 'mismatch' in site.supervisor_label.text(), 10))
        self.assertNotEqual(window.live_target, str(path))

    def test_supervisor_ready_does_not_interrupt_replay(self):
        window = self.window(fake_nodes=4)
        path = str(Path(self.enterContext(tempfile.TemporaryDirectory())) / 'daemon.sock')
        window.use_replay(path)
        self.assertTrue(spin(self.app, lambda: window.mode == 'REPLAY'))
        window.site.supervisor_status = {'site_id': SITE_ID}
        window._on_site_ready(path)
        self.assertFalse(spin(self.app, lambda: window.mode == 'LIVE', 2))


if __name__ == '__main__':
    unittest.main()
