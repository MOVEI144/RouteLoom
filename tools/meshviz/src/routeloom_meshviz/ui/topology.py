"""Network graph: node/edge items are kept and diffed, never rebuilt per update."""
import math

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import (QCheckBox, QGraphicsEllipseItem, QGraphicsItem, QGraphicsLineItem,
                               QGraphicsRectItem, QGraphicsScene, QGraphicsSimpleTextItem,
                               QGraphicsView, QHBoxLayout, QHeaderView, QLabel, QSplitter,
                               QTableWidget, QTableWidgetItem, QTextBrowser, QVBoxLayout, QWidget)

from .. import views

STATE_COLORS = {'接続': QColor('#4caf50'), '通信なし': QColor('#ff9800'),
                '消滅': QColor('#9e9e9e'), views.UNKNOWN: QColor('#e0e0e0')}
# Text marks accompany colours so the state never depends on colour alone.
STATE_MARKS = {'接続': '●', '通信なし': '▲', '消滅': '×', views.UNKNOWN: '?'}
RADIUS = 11
RING = 110
GOLDEN = (math.sqrt(5) - 1) / 2


class NodeItem(QGraphicsEllipseItem):
    def __init__(self, node_id, gateway, on_click):
        size = RADIUS * 2
        super().__init__(-RADIUS, -RADIUS, size, size)
        self.node_id = node_id
        self.on_click = on_click
        if gateway:
            # Gateway gets a square marker in addition to its label.
            self.box = QGraphicsRectItem(-RADIUS - 3, -RADIUS - 3, size + 6, size + 6, self)
            self.box.setPen(QPen(QColor('#1565c0'), 2))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setZValue(10)
        self.label = QGraphicsSimpleTextItem(self)
        self.label.setPos(RADIUS + 2, -RADIUS)
        self.moved = None

    def mousePressEvent(self, event):
        self.on_click(self.node_id)
        super().mousePressEvent(event)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged and self.moved:
            self.moved(self.node_id)
        return super().itemChange(change, value)


class TopologyView(QWidget):
    node_selected = Signal(str)

    def __init__(self):
        super().__init__()
        self.scene = QGraphicsScene(self)
        # Dynamic scenes with frequent edge moves are cheaper without a BSP index.
        self.scene.setItemIndexMethod(QGraphicsScene.ItemIndexMethod.NoIndex)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.view.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.BoundingRectViewportUpdate)
        self.layers = {}
        toolbar = QHBoxLayout()
        for key, text in (('phys', '物理 link'), ('route', '宛先への経路'), ('tree', 'gateway tree'),
                          ('state', '参加状態')):
            box = QCheckBox(text)
            box.setChecked(True)
            box.toggled.connect(self._relayer)
            self.layers[key] = box
            toolbar.addWidget(box)
        toolbar.addStretch()
        self.tree_status = QLabel()
        toolbar.addWidget(self.tree_status)
        legend = QLabel('実線=観測 link（太線=双方向確認済み、細線=片側のみ）　破線=論理 route の未観測区間　'
                        '点線=node→gateway の選択 route　●接続 ▲通信なし ×消滅 ?不明')
        legend.setWordWrap(True)
        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(['node', '参加状態', 'hop'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.cellClicked.connect(lambda row, _: self.select(self.table.item(row, 0).data(Qt.ItemDataRole.UserRole)))
        self.detail = QTextBrowser()
        splitter = QSplitter()
        splitter.addWidget(self.table)
        splitter.addWidget(self.view)
        splitter.addWidget(self.detail)
        splitter.setSizes([180, 640, 260])
        layout = QVBoxLayout(self)
        layout.addLayout(toolbar)
        layout.addWidget(legend)
        layout.addWidget(splitter, 1)
        self.node_items = {}
        self.edge_items = {}
        self.positions = {}
        self.model = views.TopologyModel()
        self.selected = None
        self.snapshot = None

    # --- layout -----------------------------------------------------------

    def _place(self, node_id, info, model):
        """Deterministic position chosen once; later updates never move existing nodes."""
        if node_id in self.positions:
            return self.positions[node_id]
        if node_id == model.gateway:
            point = QPointF(0, 0)
        else:
            depth = info.get('hops')
            if depth is None and node_id in model.tree_edges:
                depth = len(views.path_to_gateway(model, node_id)) - 1
            depth = depth if isinstance(depth, int) and depth > 0 else 3
            angle = 2 * math.pi * ((int(node_id, 16) if _is_hex(node_id) else hash(node_id)) * GOLDEN % 1)
            point = QPointF(RING * depth * math.cos(angle), RING * depth * math.sin(angle))
        self.positions[node_id] = point
        return point

    # --- updates ----------------------------------------------------------

    def update_snapshot(self, snapshot):
        self.snapshot = snapshot
        model = views.topology(snapshot['state'], now_mono_ns=snapshot.get('now_mono_ns'))
        self.model = model
        self._sync_nodes(model)
        self._sync_edges(model)
        self._sync_table(model)
        self.tree_status.setText('gateway tree: ' + ('表示中' if model.tree_edges else
                                 '未取得（各 node→gateway の route は現 API1 で未公開）'))
        self._show_detail()

    def _sync_nodes(self, model):
        show_state = self.layers['state'].isChecked()
        for node_id in list(self.node_items):
            if node_id not in model.nodes:
                self.scene.removeItem(self.node_items.pop(node_id))
        for node_id, info in model.nodes.items():
            item = self.node_items.get(node_id)
            if item is None:
                item = NodeItem(node_id, node_id == model.gateway, self.select)
                item.setPos(self._place(node_id, info, model))
                item.moved = self._node_moved
                self.scene.addItem(item)
                self.node_items[node_id] = item
            state = info['state'] if show_state else views.UNKNOWN
            item.setBrush(QBrush(STATE_COLORS.get(state, STATE_COLORS[views.UNKNOWN])))
            pen = QPen(QColor('#d32f2f') if node_id == self.selected else QColor('#424242'),
                       3 if node_id == self.selected else 1)
            item.setPen(pen)
            role = 'GW ' if node_id == model.gateway else ''
            mark = STATE_MARKS.get(info['state'], '?') if show_state else ''
            item.label.setText(f'{role}{info["label"]} {mark}')

    def _node_moved(self, node_id):
        self.positions[node_id] = self.node_items[node_id].pos()
        for key, line in self.edge_items.items():
            if node_id in key[1:3]:
                self._set_line(line, key[1], key[2])

    def _set_line(self, line, a, b):
        pa, pb = self.node_items[a].pos(), self.node_items[b].pos()
        line.setLine(pa.x(), pa.y(), pb.x(), pb.y())

    def _sync_edges(self, model):
        wanted = {}
        if self.layers['phys'].isChecked():
            for (a, b), edge in model.phys_edges.items():
                width = 2.5 if edge['bidirectional'] else 1
                wanted[('phys', a, b)] = QPen(QColor('#37474f' if edge['bidirectional'] else '#90a4ae'),
                                              width, Qt.PenStyle.SolidLine)
        if self.layers['route'].isChecked():
            for destination, next_hop in model.route_edges.items():
                if next_hop != destination:
                    # Only "via next_hop" is known; the remainder is an unobserved span.
                    wanted[('route', next_hop, destination)] = QPen(QColor('#1e88e5'), 1,
                                                                    Qt.PenStyle.DashLine)
        if self.layers['tree'].isChecked():
            for child, parent in model.tree_edges.items():
                wanted[('tree', child, parent)] = QPen(QColor('#2e7d32'), 2, Qt.PenStyle.DotLine)
        highlight = self._highlight(model)
        for key in list(self.edge_items):
            if key not in wanted or key[1] not in self.node_items or key[2] not in self.node_items:
                self.scene.removeItem(self.edge_items.pop(key))
        for key, pen in wanted.items():
            if key[1] not in self.node_items or key[2] not in self.node_items:
                continue
            line = self.edge_items.get(key)
            if line is None:
                line = QGraphicsLineItem()
                line.setZValue(1)
                self.scene.addItem(line)
                self.edge_items[key] = line
                self._set_line(line, key[1], key[2])
            if key in highlight:
                pen = QPen(QColor('#d32f2f'), pen.widthF() + 2, pen.style())
            line.setPen(pen)

    def _highlight(self, model):
        """Edges on the selected node's path only; the rest keep their normal weight."""
        if self.selected is None:
            return set()
        keys = set()
        path = views.path_to_gateway(model, self.selected)
        keys.update(('tree', a, b) for a, b in zip(path, path[1:]))
        next_hop = model.route_edges.get(self.selected)
        if next_hop:
            keys.add(('route', next_hop, self.selected))
            if model.gateway:
                keys.add(('phys',) + tuple(sorted((model.gateway, next_hop))))
        return keys

    def _sync_table(self, model):
        rows = sorted(model.nodes.values(), key=lambda n: (n['id'] != model.gateway, n['id']))
        self.table.setUpdatesEnabled(False)
        self.table.setRowCount(len(rows))
        for row, info in enumerate(rows):
            hop = views.fmt(info['hops'])
            texts = [('GW ' if info['id'] == model.gateway else '') + info['label'],
                     f'{STATE_MARKS.get(info["state"], "?")} {info["state"]}', hop]
            for column, text in enumerate(texts):
                cell = self.table.item(row, column)
                if cell is None:
                    cell = QTableWidgetItem()
                    self.table.setItem(row, column, cell)
                if cell.text() != text:
                    cell.setText(text)
            self.table.item(row, 0).setData(Qt.ItemDataRole.UserRole, info['id'])
        self.table.setUpdatesEnabled(True)

    def _relayer(self):
        if self.snapshot is not None:
            self.update_snapshot(self.snapshot)

    def select(self, node_id):
        self.selected = node_id
        self.node_selected.emit(node_id)
        if self.snapshot is not None:
            self.update_snapshot(self.snapshot)

    def _show_detail(self):
        if self.selected is None or self.snapshot is None:
            self.detail.setPlainText('node を選択すると詳細を表示します。')
            return
        model = self.model
        state = self.snapshot['state']
        node = state.nodes.get(f'{model.scope}:{self.selected}') or {}
        info = model.nodes.get(self.selected, {})
        now = self.snapshot.get('now_unix_ms')
        lines = [f'node {self.selected}',
                 f'役割: {views.fmt(node.get("role"))}',
                 f'参加状態: {info.get("state", views.UNKNOWN)}（Site membership は未取得）',
                 f'hop: {views.fmt(info.get("hops"))}（多 hop は route chain が揃う時だけ）',
                 f'gateway 選択 next hop: {views.fmt(model.route_edges.get(self.selected))}'
                 + ('（経路なし）' if self.selected in model.no_route else ''),
                 f'route metric: {views.fmt(node.get("route_metric"))}',
                 f'RSSI {self.selected[-4:]}→gateway: {views.fmt(node.get("rssi_dbm"), "dBm")}',
                 f'最終受信: {views.fmt_age(now, node.get("last_heard_ms"))} 前 '
                 f'({views.freshness(now, node.get("last_heard_ms"))})',
                 f'telemetry_stale: {views.fmt(node.get("telemetry_stale"))}']
        path = views.path_to_gateway(model, self.selected)
        if len(path) > 1:
            lines.append('gateway への選択 route: ' + ' → '.join(views.short_id(p) for p in path))
        lines.append('heap／reset／session 数: 未取得（health API 未公開）')
        self.detail.setPlainText('\n'.join(lines))


def _is_hex(text):
    return bool(text) and all(char in '0123456789abcdefABCDEF' for char in text)
