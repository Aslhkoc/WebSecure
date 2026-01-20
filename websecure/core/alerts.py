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
        """Critical: Police Siren Effect (Whoop-Whoop)."""
        def run():
            if winsound:
                for _ in range(3):
                    for f in range(1000, 2500, 100):
                        winsound.Beep(f, 30)
                    for f in range(2500, 1000, -100):
                        winsound.Beep(f, 30)
        
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def play_high():
        """High: Machine Gun / Rapid Fire."""
        def run():
             AlertManager._play_pattern([(1500, 50), (0, 50), (1500, 50), (0, 50), (1500, 50), (0, 50), (1500, 50)])
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def play_medium():
        """Medium: Descending 'Uh-oh'."""
        def run():
            AlertManager._play_pattern([(1000, 400), (600, 600)])
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def play_low():
        """Low: Sonar Ping."""
        def run():
            AlertManager._play_pattern([(2000, 50)])
        threading.Thread(target=run, daemon=True).start()


    @staticmethod
    def play_success():
        """Success: Level Up!"""
        def run():
            # C, E, G, C(high)
            pat = [(523, 100), (659, 100), (783, 100), (1046, 400)]
            AlertManager._play_pattern(pat)
        
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
