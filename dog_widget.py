import sys
from PyQt5.QtWidgets import QApplication, QLabel, QWidget, QVBoxLayout, QPushButton, QHBoxLayout, QGraphicsDropShadowEffect
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QMovie, QColor

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

        self.movie = QMovie("doggie.gif")
        self.movie.setScaledSize(QSize(120, 120))
        self.label.setMovie(self.movie)
        self.movie.start()

        gif_layout.addWidget(self.label)

        self.closeButton = QPushButton('X', self)
        self.closeButton.clicked.connect(self.close)
        self.closeButton.setFixedSize(25, 25)
        self.closeButton.setStyleSheet("background-color: red; color: white; border: none;")
        self.addShadowEffect(self.closeButton)

        self.cfgButton = QPushButton('cfg', self)
        self.cfgButton.setFixedSize(25, 25)
        self.cfgButton.setStyleSheet("""
            background-color: gray;
            border: 1px solid black;
            border-radius: 3px;
            font-family: 'Courier New';
            font-size: 12px;
            color: black;
        """)
        self.addShadowEffect(self.cfgButton)

        self.tlsButton = QPushButton('tls', self)
        self.tlsButton.setFixedSize(25, 25) 
        self.tlsButton.setStyleSheet("""
            background-color: gray;
            border: 1px solid black;
            border-radius: 3px;
            font-family: 'Courier New';
            font-size: 12px;
            color: black;
        """)
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

if __name__ == '__main__':
    app = QApplication(sys.argv)
    dog = DogWidget()
    dog.show()
    sys.exit(app.exec_())
