// FAQ Page - Load dynamic configuration values
document.addEventListener('DOMContentLoaded', () => {
  fetch('/api/config')
    .then(res => res.json())
    .then(config => {
      const sessionEl = document.getElementById('sessionTimeout');
      const fileEl = document.getElementById('fileRetention');
      const maxFileSizeEl = document.getElementById('maxFileSize');
      const maxMessageSizeEl = document.getElementById('maxMessageSize');
      
      if (sessionEl) sessionEl.textContent = Math.round(config.sessionTimeout / 60000);
      if (fileEl) fileEl.textContent = Math.round(config.fileRetention / 60000);
      if (maxFileSizeEl) maxFileSizeEl.textContent = config.maxFileSizeFormatted;
      if (maxMessageSizeEl) maxMessageSizeEl.textContent = config.bodyLimitFormatted;
    })
    .catch(err => console.error('Failed to load config:', err));
});
