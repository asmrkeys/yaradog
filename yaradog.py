from PyQt5.QtCore import Qt, QSize, pyqtSignal
from PyQt5.QtGui import QMovie, QColor, QIcon, QTextCursor
from PyQt5.QtWidgets import (
    QApplication, 
    QLabel, 
    QWidget, 
    QVBoxLayout,
    QPushButton, 
    QHBoxLayout, 
    QGraphicsDropShadowEffect, 
    QTextEdit
)
from monitoring.scanners import filesystem_scanner, stop_event
import ctypes
import sys
import threading
import time
import os

script_dir = os.path.dirname(os.path.abspath(__file__))

class Yaradog(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.textReader = None

    def initUI(self):
        # Set up the window properties
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowIcon(QIcon(os.path.join(script_dir, "assets/yaradog_icon.ico")))

        # Layouts
        mainLayout = QVBoxLayout()
        gifLayout = QHBoxLayout()
        buttonsLayout = QHBoxLayout()
        buttonsLayout.setSpacing(2)

        # GIF label
        self.label = QLabel(self)
        self.movie = QMovie(os.path.join(script_dir, "assets/doggie.gif"))
        self.movie.setScaledSize(QSize(120, 120))
        self.label.setMovie(self.movie)
        self.movie.start()
        gifLayout.addWidget(self.label)

        # Close button
        self.closeButton = QPushButton('X', self)
        self.closeButton.clicked.connect(self.close)
        self.closeButton.setFixedSize(25, 25)
        self.closeButton.setStyleSheet("background-color: red; color: white; border: none;")
        self.shadowEffect(self.closeButton)

        # Configuration button
        self.confButton = QPushButton(self)
        self.confButton.setFixedSize(25, 25)
        self.confButton.setIcon(QIcon(os.path.join(script_dir, "assets/gear_icon.png")))
        self.confButton.setStyleSheet("""
            background-color: gray;
            border: 1px solid black;
            border-radius: 3px;
        """)
        self.shadowEffect(self.confButton)

        # Play button
        self.playButton = QPushButton(self)
        self.playButton.setFixedSize(25, 25)
        self.playButton.setIcon(QIcon(os.path.join(script_dir, "assets/play_icon.png")))
        self.playButton.setStyleSheet("""
            background-color: green;
            border: 1px solid black;
            border-radius: 3px;
        """)
        self.playButton.clicked.connect(self.startFilesystemScanner)
        self.shadowEffect(self.playButton)

        buttonsLayout.addWidget(self.playButton)
        buttonsLayout.addWidget(self.confButton)
        buttonsLayout.addWidget(self.closeButton)

        mainLayout.addLayout(gifLayout)
        mainLayout.addLayout(buttonsLayout)
        self.setLayout(mainLayout)

        self.setFixedSize(150, 180)

        self.dragging = False

    def shadowEffect(self, button):
        # Apply shadow effect to buttons
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(5)
        shadow.setXOffset(2)
        shadow.setYOffset(2)
        shadow.setColor(QColor(0, 0, 0, 160))
        button.setGraphicsEffect(shadow)

    def mousePressEvent(self, event):
        # Start dragging the window
        if event.button() == Qt.LeftButton:
            self.dragging = True
            self.dragStartPosition = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        # Move the window while dragging
        if self.dragging:
            self.move(event.globalPos() - self.dragStartPosition)
            event.accept()

    def mouseReleaseEvent(self, event):
        # Stop dragging the window
        if event.button() == Qt.LeftButton:
            self.dragging = False
            event.accept()

    def startFilesystemScanner(self):
        # Save the log and start the monitoring process
        self.logSave()
        threading.Thread(target=filesystem_scanner, daemon=True).start()
        if self.textReader:
            self.textReader.close()  # Close any previous instance
        self.textReader = TextReaderWidget()
        self.textReader.show()

    def logSave(self):
        # Save the current log file to a backup and clear the log
        logFilePath = os.path.join(script_dir, 'monitoring/logs/session.log')
        backupDir = os.path.join(script_dir, 'monitoring/logs/saved/')
        backupFilePath = os.path.join(backupDir, 'session.log')

        if not os.path.exists(backupDir):
            os.makedirs(backupDir)

        if os.path.exists(logFilePath):
            with open(logFilePath, 'r') as file:
                lines = file.readlines()
                with open(backupFilePath, 'a') as backupFile:
                    backupFile.writelines(lines)
            # Clear the log file
            open(logFilePath, 'w').close()

    def closeEvent(self, event):
        # Handle the window close event
        stop_event.set()  # Signal to stop the monitoring loop
        if self.textReader:
            self.textReader.close()  # Close the text reader window
        event.accept()  # Accept the close event

class TextReaderWidget(QWidget):
    textChanged = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.initUI()
    
        self.file_position_lock = threading.Lock()
        self.lastPosition = 0

        self.thread = threading.Thread(target=self.readFile)
        self.thread.daemon = True
        self.thread.start()

    def initUI(self):
        # Initialize the UI elements
        self.setWindowTitle('yaradog.log')
        self.setGeometry(100, 100, 400, 300)
        self.setWindowIcon(QIcon(os.path.join(script_dir, "assets/yaradog_icon.ico")))

        layout = QVBoxLayout()
        self.textEdit = QTextEdit(self)
        self.textEdit.setReadOnly(True)

        self.lockButton = QPushButton('Unlock Scroll', self)
        self.lockButton.setCheckable(True)
        self.lockButton.setChecked(True)
        self.lockButton.toggled.connect(self.toggleLock)

        layout.addWidget(self.textEdit)
        layout.addWidget(self.lockButton)
        self.setLayout(layout)

        self.textChanged.connect(self.updateText)
        self.autoScroll = True

    def readFile(self):
        logFilePath = os.path.join(script_dir, 'monitoring/logs/session.log')

        # Ensure the log file exists
        if not os.path.exists(logFilePath):
            with open(logFilePath, 'w') as file:
                file.write("")

        # Loop to continuously read the log file
        while not stop_event.is_set():  # Check if the stop event is set
            try:
                with open(logFilePath, 'r') as file:
                    with self.file_position_lock:
                        file.seek(self.lastPosition)
                        newContent = file.read()
                        if newContent:
                            self.lastPosition = file.tell()
                            self.textChanged.emit(newContent)

                # Sleep for a short while before checking the file again
                time.sleep(0.3)
            except Exception as e:
                # Emit error message if an exception occurs
                self.textChanged.emit(f"Error loading file: {e}")
                time.sleep(0.3)

    def updateText(self, newContent):
        # Update the QTextEdit with new content
        scrollValue = self.textEdit.verticalScrollBar().value()
        scrollMax = self.textEdit.verticalScrollBar().maximum()

        cursor = self.textEdit.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(newContent)

        if self.autoScroll:
            self.textEdit.moveCursor(QTextCursor.End)
        else:
            self.textEdit.verticalScrollBar().setValue(scrollValue)

    def toggleLock(self, checked):
        # Toggle the auto-scroll functionality
        if checked:
            self.lockButton.setText('Unlock Scroll')
            self.autoScroll = True
        else:
            self.lockButton.setText('Lock Scroll')
            self.autoScroll = False

    def closeEvent(self, event):
        # Handle the window close event
        stop_event.set()  # Signal to stop the monitoring loop
        event.accept()  # Accept the close event

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(os.path.join(script_dir, "assets/yaradog_icon.ico")))
    app_id = 'asmrkeys.yaradog.ipd.0.5.5'
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
    yaradog = Yaradog()
    yaradog.show()
    sys.exit(app.exec_())
