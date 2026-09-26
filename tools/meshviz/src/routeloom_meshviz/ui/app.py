"""Main window: header, five screens, source switching (fake/daemon/replay) and shutdown."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import time

from PySide6.QtCore import QMetaObject, QObject, QThread, QTimer, Qt, Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QTabWidget,
                               QVBoxLayout, QWidget)

from .. import views
from ..demo import DemoMesh
from ..fake_api1 import serve_fake_api1
from .boards import BoardsView
from .playback import PlaybackView
from .quality import QualityView
from .topology import TopologyView
from .trials import TrialsView
from .workers import ApiClient, FakeBoards, ModelWorker, RealBoards, ReplayWorker

RENDER_MS = 50
AGE_RENDER_NS = 1_000_000_000


class SourceRetirer(QThread):
    """Drain worker slots and close source resources without waiting in the GUI thread."""
    def __init__(self, threads, stack, parent):
        super().__init__(parent)
        self.threads = threads
        self.stack = stack

    def run(self):
        try:
            for thread, worker in reversed(self.threads):
                QMetaObject.invokeMethod(worker, 'stop', Qt.ConnectionType.BlockingQueuedConnection)
                thread.quit()
                thread.wait()
        finally:
            self.stack.close()


class Header(QWidget):
    """Always-visible LIVE/REPLAY, site, gateway/USB, recording, observation age and trial state."""
    def __init__(self):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(6, 2, 6, 2)
        self.labels = {}
        for key in ('mode', 'site', 'gateway', 'record', 'age', 'trial'):
            label = QLabel()
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            self.labels[key] = label
            layout.addWidget(label)
            layout.addWidget(QLabel('|'))
        layout.addStretch()

    def set(self, key, text):
        self.labels[key].setText(text)


class MainWindow(QMainWindow):
    api_request = Signal(str, str, dict)
    model_events = Signal(list)
    model_start_recording = Signal(str)
    model_stop_recording = Signal()
    replay_open = Signal(str)
    replay_seek = Signal(int)
    replay_speed = Signal(float)
    replay_playing = Signal(bool)
    replay_step = Signal()

    def __init__(self, *, socket_path=None, replay_path=None, fake_nodes=8, fake_boards=None):
        super().__init__()
        self.setWindowTitle('RouteLoom Mesh Lab')
        self.resize(1280, 820)
        self.fake_nodes = fake_nodes
        self.exit_stack = ExitStack()
        self.threads = []
        self.connections = []
        self.retirer = None
        self.after_retire = None
        self.shutdown_started = False
        self.close_requested = False
        self.api = self.model = self.replay = None
        self.mode = 'LIVE'
        self.pending = None
        self.dirty = False
        self.last_clock_render_ns = 0
        self.source_status = {}
        self.recording_status = {'active': False}
        self.header = Header()
        use_fake_boards = fake_boards if fake_boards is not None else socket_path is None
        self.boards = BoardsView(FakeBoards() if use_fake_boards else RealBoards())
        self.topology = TopologyView()
        self.quality = QualityView()
        self.trials = TrialsView()
        self.playback = PlaybackView()
        self.tabs = QTabWidget()
        for widget, title in ((self.boards, 'ボード'), (self.topology, 'トポロジ'),
                              (self.quality, '品質'), (self.trials, '試験'),
                              (self.playback, '記録と再生')):
            self.tabs.addTab(widget, title)
        self.tabs.currentChanged.connect(lambda _: self._render(force=True))
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.header)
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(central)
        self._menus()
        self.trials.send_request.connect(self.api_request.emit)
        self.trials.record.connect(self.model_events.emit)
        self.playback.start_recording.connect(self.model_start_recording.emit)
        self.playback.stop_recording.connect(self.model_stop_recording.emit)
        self.playback.open_capture.connect(self.use_replay)
        self.playback.back_to_live.connect(self._back_to_live)
        self.playback.seek.connect(self.replay_seek.emit)
        self.playback.speed.connect(self.replay_speed.emit)
        self.playback.playing.connect(self.replay_playing.emit)
        self.playback.step.connect(self.replay_step.emit)
        self.playback.export_finished.connect(self._maybe_close)
        self.boards.shutdown_finished.connect(self._maybe_close)
        # Coalesced rendering: workers post snapshots, the GUI paints at most 20 times/s.
        self.render_timer = QTimer(self)
        self.render_timer.timeout.connect(self._render)
        self.render_timer.start(RENDER_MS)
        self.live_target = socket_path
        if replay_path:
            self.use_replay(str(replay_path))
        elif socket_path:
            self.use_live(str(socket_path))
        else:
            self.use_fake()

    def _menus(self):
        menu = self.menuBar().addMenu('接続')
        for text, handler in (('fake API1 server（demo mesh）', self.use_fake),
                              ('daemon socket に接続…', self._ask_socket),
                              ('capture を再生…', self._ask_capture)):
            action = QAction(text, self)
            action.triggered.connect(handler)
            menu.addAction(action)

    def _ask_socket(self):
        path, _ = QFileDialog.getOpenFileName(self, 'routeloom-host の API socket', '/tmp')
        if path:
            self.use_live(path)

    def _ask_capture(self):
        path = QFileDialog.getExistingDirectory(self, '.rlcapture ディレクトリを開く')
        if path:
            self.use_replay(path)

    # --- sources ------------------------------------------------------------

    def _thread(self, worker):
        thread = QThread(self)
        worker.moveToThread(thread)
        thread.started.connect(worker.start)
        self.threads.append((thread, worker))
        thread.start()
        return thread

    def _stop_sources(self, after=None):
        self.trials.shutdown()
        self.trials.set_capabilities('REPLAY', {})
        self.boards.set_mode('REPLAY')
        self.playback.set_mode('REPLAY')
        self.after_retire = after
        if self.retirer is not None:
            return
        for connection in self.connections:
            QObject.disconnect(connection)
        self.connections.clear()
        self.api = self.model = self.replay = None
        self.pending = None
        self.recording_status = {'active': False}
        self.source_status = {}
        if not self.threads:
            self.exit_stack.close()
            self.exit_stack = ExitStack()
            if after is not None:
                after()
            return
        old_threads, self.threads = self.threads, []
        old_stack, self.exit_stack = self.exit_stack, ExitStack()
        self.retirer = SourceRetirer(old_threads, old_stack, self)
        self.retirer.finished.connect(self._on_sources_retired)
        self.retirer.start()

    def _on_sources_retired(self):
        for thread, worker in self.retirer.threads:
            worker.deleteLater()
            thread.deleteLater()
        self.retirer.deleteLater()
        self.retirer = None
        after, self.after_retire = self.after_retire, None
        if after is not None and not self.shutdown_started:
            after()
        self._maybe_close()

    def use_fake(self):
        if self.shutdown_started:
            return
        self._stop_sources(self._start_fake)

    def _start_fake(self):
        directory = Path(self.exit_stack.enter_context(tempfile.TemporaryDirectory(prefix='meshviz-')))
        socket_path = directory / 'api1.sock'
        self.exit_stack.enter_context(serve_fake_api1(socket_path, mesh=DemoMesh(self.fake_nodes)))
        self._start_live(str(socket_path), 'fake API1（demo mesh）')

    def use_live(self, path):
        if self.shutdown_started:
            return
        self.live_target = path
        self._stop_sources(lambda: self._start_live(path, f'daemon {path}'))

    def _back_to_live(self):
        if self.live_target:
            self.use_live(self.live_target)
        else:
            self.use_fake()

    def _start_live(self, path, label):
        self.mode = 'LIVE'
        self.source_label = label
        self.api = ApiClient(path)
        self.model = ModelWorker('LIVE')
        self.api.events.connect(self.model.ingest)
        self.connections.append(self.api.status.connect(self._on_source_status))
        self.connections.append(self.api.reply.connect(self.trials.on_reply))
        self.connections.append(self.api_request.connect(self.api.request))
        self.connections.append(self.model_events.connect(self.model.ingest))
        self.connections.append(self.model_start_recording.connect(self.model.start_recording))
        self.connections.append(self.model_stop_recording.connect(self.model.stop_recording))
        self.connections.append(self.model.snapshot.connect(self._on_snapshot))
        self.connections.append(self.model.recording.connect(self._on_recording))
        self._thread(self.model)
        self._thread(self.api)
        self._apply_mode()

    def use_replay(self, path):
        if self.shutdown_started:
            return
        self._stop_sources(lambda: self._start_replay(path))

    def _start_replay(self, path):
        self.mode = 'REPLAY'
        self.source_label = f'capture {path}'
        self.replay = ReplayWorker()
        self.connections.append(self.replay.snapshot.connect(self._on_snapshot))
        self.connections.append(self.replay.position.connect(self.playback.on_position))
        self.connections.append(self.replay.failed.connect(
            lambda error: self.header.set('gateway', f'capture を開けない: {error}')))
        self.connections.append(self.replay_open.connect(self.replay.open))
        self.connections.append(self.replay_seek.connect(self.replay.seek))
        self.connections.append(self.replay_speed.connect(self.replay.set_speed))
        self.connections.append(self.replay_playing.connect(self.replay.set_playing))
        self.connections.append(self.replay_step.connect(self.replay.step))
        self._thread(self.replay)
        self.replay_open.emit(path)
        self._apply_mode()
        self.tabs.setCurrentWidget(self.topology)

    def _apply_mode(self):
        self.boards.set_mode(self.mode)
        self.playback.set_mode(self.mode)
        self.trials.set_capabilities(self.mode, self.source_status.get('methods', {}) if self.mode == 'LIVE' else {})
        self.header.set('mode', f'<b>{self.mode}</b>')
        self.header.set('record', '記録: なし' if self.mode == 'LIVE' else '記録: 再生中は無効')
        self.header.set('trial', '試験: なし')
        self.header.set('gateway', self.source_label)

    # --- updates ------------------------------------------------------------

    def _on_source_status(self, status):
        self.source_status = status
        self.trials.set_capabilities(self.mode, status.get('methods', {}))
        source = status.get('source') or {}
        gateway = source.get('gateway')
        if not status.get('connected'):
            text = f'{self.source_label}: 未接続' + (f'（{status["error"]}）' if status.get('error') else '')
        else:
            text = (f'{self.source_label}: gateway {views.short_id(gateway) if gateway else "不明"} '
                    f'source {source.get("state", "不明")}'
                    + (f'（{status["error"]}）' if status.get('error') else ''))
        self.header.set('gateway', text)

    def _on_recording(self, status):
        self.recording_status = status
        self.playback.on_recording(status)
        if status.get('error'):
            self.header.set('record', f'記録: 停止（失敗: {status["error"]}）')
        elif status.get('active'):
            self.header.set('record', f'● 記録中 {status.get("events", 0)} events')
        else:
            self.header.set('record', '記録: なし')

    def _on_snapshot(self, snapshot):
        self.pending = snapshot
        self.dirty = True

    def _render(self, force=False):
        snapshot = self.pending
        clock_ns = time.monotonic_ns()
        refresh_age = self.mode == 'LIVE' and clock_ns - self.last_clock_render_ns >= AGE_RENDER_NS
        if snapshot is None or (not self.dirty and not force and not refresh_age):
            return
        self.last_clock_render_ns = clock_ns
        self.dirty = False
        if self.mode == 'LIVE':
            snapshot = {**snapshot, 'now_unix_ms': time.time_ns() // 1_000_000,
                        'now_mono_ns': clock_ns}
        state = snapshot['state']
        scope = (views.scopes(state) or ['不明'])[0]
        self.header.set('site', f'scope {scope}（site/profile: 未取得）')
        now = snapshot.get('now_unix_ms')
        heard = [n.get('last_heard_ms') for n in state.nodes.values()
                 if type(n.get('last_heard_ms')) is int and n.get('connected')]
        age = f'最新観測 {views.fmt_age(now, max(heard))} 前／最古 {views.fmt_age(now, min(heard))} 前' \
            if heard else '観測: なし'
        gaps = len(state.gaps)
        self.header.set('age', age + (f'　gap {gaps}' if gaps else ''))
        runner = self.trials.runner
        if self.mode == 'LIVE':
            self.header.set('trial', f'試験: {runner.state}' if runner else '試験: なし')
        nodes = sorted({key.split(':', 1)[1] for key in state.nodes if key.startswith(scope + ':')})
        self.trials.set_nodes(nodes)
        current = self.tabs.currentWidget()
        # Only the visible screen repaints; others refresh when shown.
        if current is self.topology:
            self.topology.update_snapshot(snapshot)
        elif current is self.quality:
            self.quality.update_snapshot(snapshot)
        elif current is self.trials:
            self.trials.show_recorded(snapshot.get('trial_events', []))

    def closeEvent(self, event):
        self.close_requested = True
        self.shutdown()
        if self.retirer is not None or not self.boards.stopped or self.playback.export_job is not None:
            event.ignore()
            return
        self.close_requested = False
        super().closeEvent(event)

    def shutdown(self):
        """Stop new trials/sends, drain the recorder, release sources, then boards/leases."""
        if self.shutdown_started:
            return
        self.shutdown_started = True
        self.render_timer.stop()
        self._stop_sources()
        self.boards.shutdown()

    def _maybe_close(self):
        if (self.close_requested and self.retirer is None and self.boards.stopped and
                self.playback.export_job is None):
            QTimer.singleShot(0, self.close)


def main(argv=None):
    import argparse
    import sys
    parser = argparse.ArgumentParser(prog='python -m routeloom_meshviz',
                                     description='RouteLoom Mesh Lab GUI')
    source = parser.add_mutually_exclusive_group()
    source.add_argument('--socket', help='routeloom-host API socket (live daemon)')
    source.add_argument('--replay', help='.rlcapture directory to replay')
    parser.add_argument('--nodes', type=int, default=8, help='demo mesh size for the fake server')
    parser.add_argument('--real-boards', action='store_true',
                        help='use real serial ports on the boards screen even with the fake server')
    args = parser.parse_args(argv)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    window = MainWindow(socket_path=args.socket, replay_path=args.replay, fake_nodes=args.nodes,
                        fake_boards=False if args.real_boards or args.socket else None)
    window.show()
    return app.exec()
