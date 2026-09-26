"""Record/replay controls: start/stop recording, open a capture, seek, speed, export."""
from datetime import datetime, timezone
from pathlib import Path

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtWidgets import (QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QLabel, QPushButton,
                               QSlider, QVBoxLayout, QWidget)

from ..playback import export_capture

SPEEDS = (0.1, 0.5, 1.0, 2.0, 10.0)


def utc(ms):
    if type(ms) is not int:
        return '不明'
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + 'Z'


class ExportJob(QThread):
    result = Signal(object, str)

    def __init__(self, path, directory, until):
        super().__init__()
        self.path, self.directory, self.until = path, directory, until

    def run(self):
        try:
            self.result.emit(export_capture(self.path, self.directory, until_seq=self.until), '')
        except Exception as exc:
            self.result.emit(None, str(exc))


class PlaybackView(QWidget):
    start_recording = Signal(str)
    stop_recording = Signal()
    open_capture = Signal(str)
    back_to_live = Signal()
    seek = Signal(int)
    speed = Signal(float)
    playing = Signal(bool)
    step = Signal()
    export_finished = Signal()

    def __init__(self):
        super().__init__()
        record_box = QGroupBox('記録（LIVE）')
        self.record_button = QPushButton('記録開始…')
        self.record_button.clicked.connect(self._choose_record)
        self.stop_button = QPushButton('記録停止')
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_recording.emit)
        self.record_status = QLabel('記録していません')
        self.record_status.setWordWrap(True)
        row = QHBoxLayout()
        row.addWidget(self.record_button)
        row.addWidget(self.stop_button)
        row.addStretch()
        box = QVBoxLayout(record_box)
        box.addLayout(row)
        box.addWidget(self.record_status)
        box.addWidget(QLabel('保存先は利用者が選ぶ .rlcapture ディレクトリ。最大約 1 秒分の未 commit 記録は障害時に失われ得る。'))
        replay_box = QGroupBox('再生（REPLAY：書込み・送信は無効）')
        self.open_button = QPushButton('capture を開く…')
        self.open_button.clicked.connect(self._choose_capture)
        self.live_button = QPushButton('LIVE に戻る')
        self.live_button.clicked.connect(self.back_to_live.emit)
        self.play_button = QPushButton('▶ 再生')
        self.play_button.setCheckable(True)
        self.play_button.toggled.connect(self._toggle_play)
        self.step_button = QPushButton('1 event 進む')
        self.step_button.clicked.connect(self.step.emit)
        self.speed_box = QComboBox()
        self.speed_box.addItems([f'{s:g}×' for s in SPEEDS])
        self.speed_box.setCurrentIndex(SPEEDS.index(1.0))
        self.speed_box.currentIndexChanged.connect(lambda i: self.speed.emit(SPEEDS[i]))
        self.slider = QSlider(Qt.Orientation.Horizontal)
        self.slider.setEnabled(False)
        self.slider.sliderReleased.connect(lambda: self.seek.emit(self.slider.value()))
        self.position_label = QLabel('capture 未選択')
        self.export_button = QPushButton('CSV／JSONL へ書き出し…')
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self._choose_export)
        controls = QHBoxLayout()
        for widget in (self.open_button, self.live_button, self.play_button, self.step_button,
                       QLabel('速度'), self.speed_box, self.export_button):
            controls.addWidget(widget)
        controls.addStretch()
        box = QVBoxLayout(replay_box)
        box.addLayout(controls)
        box.addWidget(self.slider)
        box.addWidget(self.position_label)
        self.export_status = QLabel()
        self.export_status.setWordWrap(True)
        box.addWidget(self.export_status)
        layout = QVBoxLayout(self)
        layout.addWidget(record_box)
        layout.addWidget(replay_box)
        layout.addStretch()
        self.capture_path = None
        self.position = None
        self.export_job = None

    def _choose_record(self):
        directory = QFileDialog.getExistingDirectory(self, '記録の保存先ディレクトリ')
        if directory:
            name = datetime.now().strftime('%Y-%m-%d-%H%M%S') + '.rlcapture'
            self.start_recording.emit(str(Path(directory) / name))

    def _choose_capture(self):
        path = QFileDialog.getExistingDirectory(self, '.rlcapture ディレクトリを開く')
        if path:
            self.open_capture.emit(path)

    def _choose_export(self):
        directory = QFileDialog.getExistingDirectory(self, '書き出し先ディレクトリ')
        if directory:
            self.export(directory)

    def export(self, directory):
        if self.capture_path is None or self.export_job is not None:
            return None
        until = self.position['seq'] if self.position else None
        self.export_button.setEnabled(False)
        self.export_status.setText('書き出し中…')
        job = ExportJob(self.capture_path, directory, until)
        self.export_job = job
        job.result.connect(lambda out, error: self._on_export_result(out, error, until))
        job.finished.connect(self._on_export_finished)
        job.start()
        return None

    def _on_export_result(self, out, error, until):
        self.export_status.setText(f'書き出し失敗: {error}' if error else
                                   f'書き出し完了: {out}（seq ≤ {until}）')

    def _on_export_finished(self):
        self.export_button.setEnabled(self.position is not None)
        self.export_job.deleteLater()
        self.export_job = None
        self.export_finished.emit()

    def _toggle_play(self, on):
        self.play_button.setText('❚❚ 一時停止' if on else '▶ 再生')
        self.playing.emit(on)

    def set_mode(self, mode):
        replay = mode == 'REPLAY'
        self.record_button.setEnabled(not replay and not self.stop_button.isEnabled())
        for widget in (self.play_button, self.step_button, self.slider, self.export_button,
                       self.live_button):
            widget.setEnabled(replay)

    def on_recording(self, status):
        active = status.get('active')
        self.stop_button.setEnabled(bool(active))
        self.record_button.setEnabled(not active)
        if status.get('error'):
            self.record_status.setText(f'記録停止（失敗）: {status["error"]} — {status.get("path")}')
        elif active:
            self.record_status.setText(f'● 記録中: {status["path"]}（{status.get("events", 0)} events）')
        else:
            self.record_status.setText(f'記録を閉じました: {status.get("path")}（{status.get("events", 0)} events）')

    def on_position(self, position):
        self.position = position
        self.capture_path = position['path']
        self.slider.blockSignals(True)
        self.slider.setRange(position['first'], position['last'])
        if not self.slider.isSliderDown():
            self.slider.setValue(position['seq'])
        self.slider.blockSignals(False)
        if not position['playing'] and self.play_button.isChecked():
            self.play_button.blockSignals(True)
            self.play_button.setChecked(False)
            self.play_button.setText('▶ 再生')
            self.play_button.blockSignals(False)
        self.position_label.setText(
            f'{position["path"]}　event {position["seq"]}/{position["last"]}　{utc(position["t_unix_ms"])}'
            + ('' if position['closed_cleanly'] else '　⚠ 正常に閉じられていない capture（末尾は UncleanEnd）'))
