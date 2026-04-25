import React, { useState } from 'react';

export default function FeedbackForm() {
  const [status, setStatus] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus('sending');

    const form = e.target;
    const formData = new FormData(form);
    
    // Add Web3Forms access key
    // Replace this with your actual key from https://web3forms.com/
    formData.append("access_key", "YOUR_WEB3FORMS_ACCESS_KEY_HERE");
    
    // We want the response in JSON
    formData.append("replyto", "no-reply@vulniz.com");

    try {
      const response = await fetch("https://api.web3forms.com/submit", {
        method: "POST",
        body: formData
      });
      
      const data = await response.json();
      
      if (data.success) {
        setStatus('success');
        form.reset();
        setTimeout(() => setStatus(''), 5000);
      } else {
        setStatus('error');
      }
    } catch (err) {
      setStatus('error');
    }
  };

  return (
    <div className="card animate-in" style={{ marginTop: '2rem', marginBottom: '2rem' }}>
      <div className="card__title">
        <span className="card__title-icon">💬</span>
        Send Feedback
      </div>
      <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: 1.5 }}>
        Have suggestions, found a bug, or just want to say hi? Send me a message directly!
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <input 
          type="text" 
          name="name" 
          placeholder="Your Name (Optional)" 
          className="scan-form__input"
          style={{ width: '100%' }}
        />
        
        <textarea 
          name="message" 
          required 
          placeholder="Your message here..." 
          className="scan-form__input"
          style={{ width: '100%', minHeight: '100px', resize: 'vertical' }}
        ></textarea>

        {/* Hidden Honeypot to prevent spam */}
        <input type="checkbox" name="botcheck" className="hidden" style={{ display: 'none' }} />

        <button 
          type="submit" 
          className="btn btn--primary" 
          disabled={status === 'sending'}
          style={{ alignSelf: 'flex-start' }}
        >
          {status === 'sending' ? 'Sending...' : '📤 Send Message'}
        </button>

        {status === 'success' && (
          <div style={{ color: '#4ade80', fontSize: '0.85rem', marginTop: '0.5rem' }}>
            ✓ Message sent successfully! Thank you for your feedback.
          </div>
        )}
        {status === 'error' && (
          <div style={{ color: '#f87171', fontSize: '0.85rem', marginTop: '0.5rem' }}>
            ⚠ Failed to send message. Please try again later.
          </div>
        )}
      </form>
    </div>
  );
}
