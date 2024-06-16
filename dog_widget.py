import sys
import threading
import time
from PyQt5.QtWidgets import QApplication, QLabel, QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QGraphicsDropShadowEffect, QTextEdit, QScrollBar
from PyQt5.QtCore import Qt, QSize, pyqtSignal, QObject
from PyQt5.QtGui import QMovie, QColor, QIcon, QTextCursor

class DogWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        main_layout = QVBoxLayout()
        gif_layout = QHBoxLayout()
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(2)

        self.label = QLabel(self)

        self.movie = QMovie("./assets/doggie.gif")
        self.movie.setScaledSize(QSize(120, 120))
        self.label.setMovie(self.movie)
        self.movie.start()

        gif_layout.addWidget(self.label)

        self.closeButton = QPushButton('X', self)
        self.closeButton.clicked.connect(self.close)
        self.closeButton.setFixedSize(25, 25)
        self.closeButton.setStyleSheet("background-color: red; color: white; border: none;")
        self.addShadowEffect(self.closeButton)

        self.cfgButton = QPushButton(self)
        self.cfgButton.setFixedSize(25, 25)
        self.cfgButton.setIcon(QIcon("./assets/gear_icon.png"))
        self.cfgButton.setStyleSheet("""
            background-color: gray;
            border: 1px solid black;
            border-radius: 3px;
        """)
        self.addShadowEffect(self.cfgButton)

        self.tlsButton = QPushButton(self)
        self.tlsButton.setFixedSize(25, 25)
        self.tlsButton.setIcon(QIcon("./assets/play_icon.png"))
        self.tlsButton.setStyleSheet("""
            background-color: green;
            border: 1px solid black;
            border-radius: 3px;
        """)
        self.tlsButton.clicked.connect(self.startMonitoring)
        self.addShadowEffect(self.tlsButton)

        buttons_layout.addWidget(self.tlsButton)
        buttons_layout.addWidget(self.cfgButton)
        buttons_layout.addWidget(self.closeButton)

        main_layout.addLayout(gif_layout)
        main_layout.addLayout(buttons_layout)
        self.setLayout(main_layout)

        self.setFixedSize(150, 180)

        self.dragging = False

    def addShadowEffect(self, button):
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(5)
        shadow.setXOffset(2)
        shadow.setYOffset(2)
        shadow.setColor(QColor(0, 0, 0, 160))
        button.setGraphicsEffect(shadow)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.dragging = True
            self.drag_start_position = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self.dragging:
            self.move(event.globalPos() - self.drag_start_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.dragging = False
            event.accept()

    def startMonitoring(self):
        # self.Func() < handler here, 
        #               pending to point all session logs to session.log to read them correctly 
        #               (instead of printing them in terminal as currently)
        self.textReader = TextReaderWidget()
        self.textReader.show()

class TextReaderWidget(QWidget):
    textChanged = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.initUI()

        self.thread = threading.Thread(target=self.readFile)
        self.thread.daemon = True
        self.thread.start()

    def initUI(self):
        self.setWindowTitle('yaradog.log')
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()
        self.textEdit = QTextEdit(self)
        self.textEdit.setReadOnly(True)

        self.lockButton = QPushButton('Lock Scroll', self)
        self.lockButton.setCheckable(True)
        self.lockButton.setChecked(True)
        self.lockButton.toggled.connect(self.toggleLock)

        layout.addWidget(self.textEdit)
        layout.addWidget(self.lockButton)
        self.setLayout(layout)

        self.textChanged.connect(self.updateText)
        self.autoScroll = True
        self.last_position = 0

    def readFile(self):
        while True:
            try:
                with open('session.log', 'r') as file:
                    file.seek(self.last_position)
                    new_content = file.read()
                    if new_content:
                        self.last_position = file.tell()
                        self.textChanged.emit(new_content)
                time.sleep(.3)
            except Exception as e:
                self.textChanged.emit(f"Error loading file: {e}")
                time.sleep(.3)

    def updateText(self, new_content):
        scroll_value = self.textEdit.verticalScrollBar().value()
        scroll_max = self.textEdit.verticalScrollBar().maximum()

        cursor = self.textEdit.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(new_content)

        if self.autoScroll:
            self.textEdit.moveCursor(QTextCursor.End)
        else:
            self.textEdit.verticalScrollBar().setValue(scroll_value)

    def toggleLock(self, checked):
        if checked:
            self.lockButton.setText('Unlock Scroll')
            self.autoScroll = True
        else:
            self.lockButton.setText('Lock Scroll')
            self.autoScroll = False

if __name__ == '__main__':
    app = QApplication(sys.argv)
    dog = DogWidget()
    dog.show()
    sys.exit(app.exec_())