import matplotlib
matplotlib.use('Agg')
import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import spectrogram
import matplotlib.animation as animation
from flask import Flask, send_file
import io
import tempfile

app = Flask(__name__)

@app.route('/')
def dashboard():
    # Generate initial signal
    fs = 44100
    t = np.arange(0, 1, 1/fs)

    # Create figure and axis
    fig, ax = plt.subplots()
    frequencies, times, Sxx = spectrogram(np.sin(2 * np.pi * 1000 * t), fs)
    cax = ax.pcolormesh(times, frequencies, 10 * np.log10(Sxx), shading='gouraud')
    fig.colorbar(cax, ax=ax, label='Power [dB]')
    ax.set_title("Spectrogram of Intercepted Signal")
    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Frequency [Hz]")

    # Animation function
    def animate(i):
        new_signal = (np.sin(2 * np.pi * (1000 + i) * t) + 
                      0.5 * np.sin(2 * np.pi * (5000 + i) * t) + 
                      0.2 * np.random.randn(len(t)))
        frequencies, times, Sxx = spectrogram(new_signal, fs)
        cax.set_array(10 * np.log10(Sxx).flatten())
        return cax,

    # Create animation
    ani = animation.FuncAnimation(fig, animate, frames=100, interval=100, blit=True)

    # Save the animation to a temporary file
    with tempfile.NamedTemporaryFile(suffix='.gif', delete=False) as tmpfile:
        ani.save(tmpfile.name, writer='imagemagick')
        tmpfile.seek(0)
        img = io.BytesIO(tmpfile.read())

    return send_file(img, mimetype='image/gif')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)