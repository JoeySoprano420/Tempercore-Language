import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QFileDialog, QSplitter, QListWidget
)
from PyQt5.QtCore import Qt
from interpreter_visual import run_tempercore_command, stack, heap

class TempercoreIDE(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Tempercore IDE")
        self.setGeometry(100, 100, 1200, 700)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.splitter = QSplitter(Qt.Horizontal)
        self.editor = QTextEdit()
        self.editor.setPlaceholderText("Write Tempercore code here...")
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.splitter.addWidget(self.editor)
        self.splitter.addWidget(self.console)

        self.layout.addWidget(self.splitter)

        vis_layout = QHBoxLayout()
        self.stack_view = QListWidget()
        self.stack_view.setFixedWidth(200)
        self.heap_view = QListWidget()
        self.heap_view.setFixedWidth(300)
        vis_layout.addWidget(QLabel("Stack:"))
        vis_layout.addWidget(self.stack_view)
        vis_layout.addWidget(QLabel("Heap:"))
        vis_layout.addWidget(self.heap_view)
        self.layout.addLayout(vis_layout)

        btn_layout = QHBoxLayout()
        self.run_btn = QPushButton("Run")
        self.load_btn = QPushButton("Load File")
        self.save_btn = QPushButton("Save File")
        btn_layout.addWidget(self.run_btn)
        btn_layout.addWidget(self.load_btn)
        btn_layout.addWidget(self.save_btn)
        self.layout.addLayout(btn_layout)

        self.run_btn.clicked.connect(self.run_code)
        self.load_btn.clicked.connect(self.load_file)
        self.save_btn.clicked.connect(self.save_file)

    def run_code(self):
        code = self.editor.toPlainText()
        self.console.clear()
        for line in code.splitlines():
            output = self.execute_line(line.strip())
            if output:
                self.console.append(output)
        self.update_stack_view()
        self.update_heap_view()

    def execute_line(self, line):
        try:
            from io import StringIO
            import contextlib

            output_buffer = StringIO()
            with contextlib.redirect_stdout(output_buffer):
                run_tempercore_command(line)
            return output_buffer.getvalue().strip()
        except Exception as e:
            return f"Error: {e}"

    def update_stack_view(self):
        self.stack_view.clear()
        for item in reversed(stack.stack):
            self.stack_view.addItem(str(item))

    def update_heap_view(self):
        self.heap_view.clear()
        current_heap = heap.dump()
        for key, value in current_heap.items():
            self.heap_view.addItem(f"{key} => {value}")

    def load_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open .tpc File", "", "Tempercore (*.tpc)")
        if path:
            with open(path, "r") as f:
                self.editor.setText(f.read())

    def save_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save .tpc File", "", "Tempercore (*.tpc)")
        if path:
            with open(path, "w") as f:
                f.write(self.editor.toPlainText())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ide = TempercoreIDE()
    ide.show()
    sys.exit(app.exec_())
