/**
 * Voice accessibility layer — shared by the phone-check page and the
 * email analysis result page, built on the browser's built-in Web Speech
 * API (no server round-trip, no API key, works offline once the page is
 * loaded). Two pieces, both optional/progressive-enhancement:
 *
 *   1. MailFoxVoice.speak(text)         — reads a verdict out loud
 *      (SpeechSynthesis). Used for "read the result aloud" buttons.
 *   2. MailFoxVoice.attachDictation(el) — lets the user speak into a
 *      button instead of typing, e.g. reading a suspicious phone number
 *      or message aloud (SpeechRecognition). Fills the given input/textarea.
 *
 * Aimed at users (e.g. elderly users, or anyone checking a suspicious call
 * away from a keyboard) who find speaking/listening easier than typing/
 * reading. Every entry point checks browser support first and simply
 * hides itself if the browser doesn't have the API — this must never be
 * the only way to use a page.
 */
(function (global) {
  'use strict';

  var synth = global.speechSynthesis;
  var SpeechRecognitionCtor = global.SpeechRecognition || global.webkitSpeechRecognition;

  function speak(text, opts) {
    if (!synth || !text) return false;
    synth.cancel(); // don't stack multiple readbacks
    var utter = new SpeechSynthesisUtterance(text);
    utter.rate = (opts && opts.rate) || 0.95; // slightly slower than default — accessibility default
    utter.pitch = 1;
    synth.speak(utter);
    return true;
  }

  function stopSpeaking() {
    if (synth) synth.cancel();
  }

  /**
   * Wires a "speak instead of typing" mic button to a text input/textarea.
   * buttonEl: the button the user clicks to start/stop dictation.
   * targetEl: the input/textarea to fill with the recognized text.
   */
  function attachDictation(buttonEl, targetEl) {
    if (!SpeechRecognitionCtor || !buttonEl || !targetEl) {
      if (buttonEl) buttonEl.classList.add('d-none'); // hide the affordance if unsupported
      return;
    }

    var recognition = new SpeechRecognitionCtor();
    recognition.lang = 'en-US';
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;
    var listening = false;

    function setListening(state) {
      listening = state;
      buttonEl.classList.toggle('voice-listening', state);
      buttonEl.setAttribute('aria-pressed', state ? 'true' : 'false');
      buttonEl.innerHTML = state
        ? '<i class="fa-solid fa-microphone-lines"></i> Listening…'
        : '<i class="fa-solid fa-microphone"></i> Speak instead';
    }
    setListening(false);

    buttonEl.addEventListener('click', function () {
      if (listening) {
        recognition.stop();
        return;
      }
      try {
        recognition.start();
        setListening(true);
      } catch (e) {
        setListening(false);
      }
    });

    recognition.addEventListener('result', function (event) {
      var transcript = event.results[0][0].transcript;
      targetEl.value = transcript;
      targetEl.dispatchEvent(new Event('input', { bubbles: true }));
    });

    recognition.addEventListener('end', function () {
      setListening(false);
    });

    recognition.addEventListener('error', function () {
      setListening(false);
    });
  }

  global.MailFoxVoice = {
    speak: speak,
    stopSpeaking: stopSpeaking,
    attachDictation: attachDictation,
    supported: {
      speech: !!synth,
      recognition: !!SpeechRecognitionCtor,
    },
  };
})(window);