import streamlit as st
import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import spectrogram
import dns.resolver
import io
import tempfile

def check_dns():
    try:
        dns.resolver.resolve('www.example.com', 'A')
        return False  # No DNS error
    except dns.resolver.NXDOMAIN:
        return True  # DNS error detected

def generate_spectrogram(signal, fs):
    frequencies, times, Sxx = spectrogram(signal, fs)
    fig, ax = plt.subplots()
    cax = ax.pcolormesh(times, frequencies, 10 * np.log10(Sxx), shading='gouraud')
    fig.colorbar(cax, ax=ax, label='Power [dB]')
    ax.set_title("Spectrogram of Intercepted Signal")
    ax.set_xlabel("Time [s]")
    ax.set_ylabel("Frequency [Hz]")
    return fig

def main():
    st.title("Interactive Spectrogram with DNS Check")
    fs = 44100
    t = np.arange(0, 1, 1/fs)

    if check_dns():
        signal = np.random.randn(len(t))  # Random noise on DNS error
    else:
        signal = np.sin(2 * np.pi * 1000 * t)  # Traditional sine wave

    fig = generate_spectrogram(signal, fs)
    st.pyplot(fig)

if __name__ == '__main__':
    main()