"""Qt offscreen smoke tests for the Mesh Lab screens; skipped when PySide6 is absent."""
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

try:
    from PySide6.QtWidgets import QApplication
    import pyqtgraph  # noqa: F401
except ImportError:  # the headless CI job runs without Qt
    QApplication = None

from routeloom_meshviz import firmware_catalog as catalog
from routeloom_meshviz.demo import write_demo_capture
from routeloom_meshviz.model import State, reduce


def spin(app, until, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        app.processEvents()
        if until():
            return True
        time.sleep(0.01)
    return False


def dense_state(count=100, degree=4):
    """100 nodes and 400 directed neighbor observations in one scope."""
    ids = [f'{i:016x}' for i in range(1, count + 1)]
    nodes = [{'node': n, 'role': 'gateway' if n == ids[0] else 'peer', 'connected': True,
              'listed': True, 'hops': 0 if n == ids[0] else None, 'last_heard_ms': 1000}
             for n in ids]
    links = [{'observer': ids[i], 'peer': ids[(i + k) % count], 'rssi_dbm': -60}
             for i in range(count) for k in range(1, degree + 1)]
    routes = [{'observer': ids[0], 'destination': n, 'next_hop': ids[1 + i % 3], 'valid': True}
              for i, n in enumerate(ids[4:])]
    state = State()
    reduce(state, {'kind': 'snapshot', 'scope': 'bench', 'source': 's', 'source_epoch': '1',
                   'source_seq': 1, 'payload': {'complete': True, 'nodes': nodes, 'links': links,
                                                'routes': routes}})
    return state, ids


@unittest.skipIf(QApplication is None, 'PySide6/pyqtgraph not installed')
class GuiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def window(self, **kw):
        from routeloom_meshviz.ui.app import MainWindow
        window = MainWindow(**kw)
        self.addCleanup(window.shutdown)
        window.show()
        return window

    def test_fake_server_drives_topology_quality_and_trial(self):
        window = self.window(fake_nodes=10)
        window.tabs.setCurrentWidget(window.topology)
        self.assertTrue(spin(self.app, lambda: len(window.topology.node_items) == 10))
        self.assertIn('LIVE', window.header.labels['mode'].text())
        self.assertIn('gateway 01', window.header.labels['gateway'].text())
        # Gateway view only: the gateway tree is reported as unavailable, not drawn empty.
        self.assertIn('未取得', window.topology.tree_status.text())
        window.topology.select(f'{5:016x}')
        self.assertIn('hop: 不明', window.topology.detail.toPlainText())
        window.tabs.setCurrentWidget(window.quality)
        self.assertTrue(spin(self.app, lambda: window.quality.table.rowCount() == 10))
        trials = window.trials
        window.tabs.setCurrentWidget(trials)
        self.assertTrue(spin(self.app, lambda: trials.supported))
        trials.destination.setEditText(f'{3:016x}')
        trials.count.setValue(2)
        trials.interval.setValue(1)
        window.model_start_recording.emit(str(Path(self.tmp()) / 'live.rlcapture'))
        self.assertTrue(spin(self.app, lambda: window.recording_status.get('active')))
        trials.start()
        self.assertTrue(spin(self.app, lambda: trials.runner.finished, 15))
        self.assertEqual(trials.runner.summary()['success'], 2)
        self.assertIn('SDK 受領 2', trials.summary.text())
        window.model_stop_recording.emit()
        self.assertTrue(spin(self.app, lambda: not window.recording_status.get('active')))
        self.assertIsNone(window.recording_status.get('error'))
        # The recorded run replays read-only with the same ledger.
        window.use_replay(window.recording_status['path'])
        self.assertTrue(spin(self.app, lambda: window.playback.position is not None))
        window.replay_seek.emit(window.playback.position['last'])
        self.assertTrue(spin(self.app, lambda: window.playback.position['seq'] ==
                             window.playback.position['last']))
        window.tabs.setCurrentWidget(trials)
        self.assertTrue(spin(self.app, lambda: 'SDK 受領 2' in trials.summary.text()))
        self.assertFalse(trials.start_button.isEnabled())
        self.assertFalse(window.boards.flash_button.isEnabled())
        out = window.playback.export(self.tmp())
        self.assertTrue((out / 'trial_messages.csv').is_file())

    def tmp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return directory.name

    def test_replay_seek_speed_and_gateway_tree(self):
        path = Path(self.tmp()) / 'demo.rlcapture'
        write_demo_capture(path, count=12, duration_s=40)
        window = self.window(replay_path=str(path))
        self.assertTrue(spin(self.app, lambda: len(window.topology.node_items) == 12))
        self.assertIn('REPLAY', window.header.labels['mode'].text())
        self.assertIn('表示中', window.topology.tree_status.text())
        self.assertTrue(any(key[0] == 'tree' for key in window.topology.edge_items))
        first = window.playback.position['seq']
        window.playback.speed_box.setCurrentIndex(4)
        window.playback.play_button.setChecked(True)
        self.assertTrue(spin(self.app, lambda: window.playback.position['seq'] > first))
        window.playback.play_button.setChecked(False)
        window.replay_step.emit()
        # Seeking into the relay outage shows node 2 as not connected.
        target = window.playback.position['last'] // 2
        window.replay_seek.emit(target)
        self.assertTrue(spin(self.app, lambda: window.playback.position['seq'] == target))
        self.assertTrue(spin(self.app, lambda: window.topology.model.nodes.get(f'{2:016x}', {})
                             .get('state') == '通信なし'))
        self.assertFalse(window.trials.start_button.isEnabled())
        window.tabs.setCurrentWidget(window.quality)
        self.assertTrue(spin(self.app, lambda: len(window.quality.curves) > 0))

    def test_hundred_nodes_four_hundred_edges_update_quickly(self):
        from routeloom_meshviz.ui.topology import TopologyView
        view = TopologyView()
        self.addCleanup(view.deleteLater)
        view.resize(1000, 700)
        view.show()
        state, ids = dense_state()
        snapshot = {'state': state, 'now_unix_ms': 2000, 'now_mono_ns': 0}
        view.update_snapshot(snapshot)
        self.app.processEvents()
        self.assertEqual(len(view.node_items), 100)
        self.assertEqual(sum(1 for key in view.edge_items if key[0] == 'phys'), 400)
        durations = []
        for i in range(10):
            reduce(state, {'kind': 'node', 'scope': 'bench', 'source': 's', 'source_epoch': '1',
                           'source_seq': 2 + i, 'payload': {'node': ids[10 + i], 'connected': False,
                                                            'listed': True}})
            started = time.perf_counter()
            view.update_snapshot({'state': state, 'now_unix_ms': 3000, 'now_mono_ns': 0})
            self.app.processEvents()
            durations.append(time.perf_counter() - started)
        # Diff updates must not stall the GUI thread (design target p95 < 100 ms).
        self.assertLess(sorted(durations)[-1], 0.5, durations)
        positions = {n: (item.pos().x(), item.pos().y()) for n, item in view.node_items.items()}
        view.update_snapshot(snapshot)
        self.assertEqual(positions, {n: (i.pos().x(), i.pos().y()) for n, i in view.node_items.items()})

    def test_boards_reject_duplicates_and_flash_verified_bundle(self):
        window = self.window(fake_nodes=3)
        boards = window.boards
        window.tabs.setCurrentWidget(boards)
        self.assertEqual([r.port for r in boards.rows], ['fake://A', 'fake://B', 'fake://C'])
        boards.select_ports(['fake://A', 'fake://B', 'fake://C'])
        boards._probe_selected()
        self.assertTrue(spin(self.app, lambda: all(r.identity for r in boards.rows) and not boards.busy))
        boards.set_assignment('fake://A', 'reference_node', '2')
        boards.set_assignment('fake://C', 'reference_node', '0x02')
        boards.select_ports(['fake://A', 'fake://C'])
        self.assertIn('NodeId 0000000000000002 が重複', boards.preview.toPlainText())
        self.assertFalse(boards.flash_button.isEnabled())
        boards.set_assignment('fake://C', 'reference_node', '3')
        boards.load_bundle(self.bundle())
        self.assertIn('署名・hash 検証済み', boards.bundle_label.text())
        boards.quiesce.setChecked(True)
        boards.select_ports(['fake://A'])
        self.assertIn('書込み可', boards.preview.toPlainText())
        self.assertTrue(boards.flash_button.isEnabled())
        boards._flash_selected()
        self.assertTrue(spin(self.app, lambda: not boards.busy))
        self.assertEqual(boards.rows[0].state, 'Written')
        self.assertEqual(boards.backend.written['fake://A'], [0, 0x8000, 0x10000])
        # Board C reports unknown flash-encryption state: preview refuses and nothing is written.
        boards.select_ports(['fake://C'])
        self.assertIn('暗号化', boards.preview.toPlainText())
        self.assertFalse(boards.flash_button.isEnabled())
        # The S3 board cannot take a C3 image.
        boards.set_assignment('fake://B', 'reference_node', '4')
        boards.select_ports(['fake://B'])
        self.assertIn('chip 不一致', boards.preview.toPlainText())
        self.assertNotIn('fake://C', boards.backend.written)

    def test_recorder_skips_malformed_event_and_keeps_recording(self):
        from routeloom_meshviz.ui.workers import ModelWorker
        worker = ModelWorker()
        path = Path(self.tmp()) / 'r.rlcapture'
        statuses = []
        worker.recording.connect(statuses.append)
        worker.start_recording(str(path))
        worker.ingest([{'kind': 'node', 'scope': 'bad:scope', 'source': 'x', 'payload': {'node': '01'}},
                       {'kind': 'node', 'scope': 's', 'source': 'x', 'payload': {'node': '01'}}])
        self.assertIsNotNone(worker.capture)
        self.assertEqual(worker.state.gaps, [{'reason': 'invalid_event', 'source': 'x'}])
        self.assertIn('s:01', worker.state.nodes)
        worker.stop_recording()
        self.assertEqual(statuses[-1]['events'], 1)
        self.assertIsNone(statuses[-1]['error'])

    def bundle(self):
        from test_bundle import BundleTests
        root = Path(self.tmp())
        app, build, key, _ = BundleTests.fixture(root)
        bundle = root / 'bundle'
        catalog.package(app, build, bundle, key, 'esp32c3', 'reference_node', 'gui-1', 'a' * 40, 'b' * 64)
        return str(bundle)


if __name__ == '__main__':
    unittest.main()
