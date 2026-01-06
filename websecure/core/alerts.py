import sys
import threading
import time

try:
    import winsound
except ImportError:
    winsound = None

class AlertManager:
    """
    Manages audio alerts for different event severities.
    Uses threading to prevent blocking the main scan loop.
    """
    
    @staticmethod
    def _beep(freq, dur):
        if winsound:
            try:
                winsound.Beep(freq, dur)
            except Exception:
                pass

    @staticmethod
    def _play_pattern(pattern):
        """
        Executes a sequence of (frequency, duration) tuples.
        """
        if not winsound:
            return
        
        for freq, dur in pattern:
            AlertManager._beep(freq, dur)
            time.sleep(0.05) # Small gap between notes

    @staticmethod
    def play_critical():
        """
        Critical: High pitched triple beep (Alarm).
        """
        def run():
            # 2500Hz x 3
            AlertManager._play_pattern([(2500, 150), (2500, 150), (2500, 150)])
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def play_high():
        """
        High: Two urgent beeps.
        """
        def run():
            # 1500Hz x 2
            AlertManager._play_pattern([(1500, 250), (1500, 250)])
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def play_medium():
        """
        Medium: Two moderate beeps.
        """
        def run():
            # 800Hz x 2
            AlertManager._play_pattern([(800, 200), (800, 200)])
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def play_low():
        """
        Low: Single low notification beep.
        """
        def run():
            # 400Hz x 1
            AlertManager._play_pattern([(400, 150)])
        threading.Thread(target=run, daemon=True).start()


    @staticmethod
    def play_success():
        """
        Success chime: Ascending Major Triad (C5 - E5 - G5)
        """
        def run():
            # C5 (523), E5 (659), G5 (784)
            AlertManager._play_pattern([(523, 150), (659, 150), (784, 300)])
        
        threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    # Test
    print("Testing Critical...")
    AlertManager.play_critical()
    time.sleep(1)
    print("Testing High...")
    AlertManager.play_high()
    time.sleep(1)
    print("Testing Success...")
    AlertManager.play_success()
    time.sleep(1)
