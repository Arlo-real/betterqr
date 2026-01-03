// Redirect to HTTPS if crypto.subtle is not available (required for encryption)
if (!window.crypto || !window.crypto.subtle) {
  if (window.location.protocol === 'http:') {
    window.location.href = window.location.href.replace('http:', 'https:');
  } else {
    alert('Your browser does not support the Web Crypto API. Please use a modern browser.');
  }
}

let connectionCode = null;
let encryptionKey = null;
let connectedSender = false;
let ws = null;  // WebSocket connection
let wsToken = null;  // WebSocket authentication token
let dhKeyPair = null;  // Store DH key pair
let displayedMessageIds = new Set();

// PGP Wordlist - will be loaded from pgp-wordlist.json
let PGP_WORDLIST = null;

async function loadPGPWordlist() {
  if (PGP_WORDLIST) return; // Already loaded
  try {
    const response = await fetch('/pgp-wordlist.json');
    const data = await response.json();
    PGP_WORDLIST = data.pgp_wordlist || data;
  } catch (error) {
    console.error('Error loading PGP wordlist:', error);
  }
}

// Preload wordlist when page loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', loadPGPWordlist);
} else {
  loadPGPWordlist();
}

/**
 * Decode PGP words back to hex code
 * Uses RFC 1751 format with word pairs (first=odd, second=even)
 * @param {string} input - Connection code or space/dash-separated PGP words
 * @returns {string} Decoded hex code (uppercase)
 * @throws {Error} If a word is unknown or forgotten
 */
async function decodePgpIfNeeded(input) {
  const trimmed = input.toLowerCase().trim();
  
  // Check if it looks like PGP words (multiple words separated by spaces or dashes)
  const words = trimmed.split(/[\s-]+/).filter(w => w);
  
  if (words.length === 1) {
    // Single word/code, return as-is uppercase
    return trimmed.toUpperCase();
  }
  
  // Ensure wordlist is loaded
  if (!PGP_WORDLIST) {
    await loadPGPWordlist();
  }
  
  if (!PGP_WORDLIST) {
    throw new Error('Failed to load PGP wordlist');
  }
  
  // Try to decode as PGP words
  try {
    const bytes = [];
    
    for (let i = 0; i < words.length; i++) {
      const word = words[i];
      let foundByte = null;
      let expectedParity = null;
      
      // Search through wordlist to find which byte this word corresponds to
      for (const [hexByte, wordPair] of Object.entries(PGP_WORDLIST)) {
        if (!wordPair || wordPair.length !== 2) {
          throw new Error(`Invalid wordlist entry for ${hexByte}`);
        }
        
        const oddWord = wordPair[0].toLowerCase();
        const evenWord = wordPair[1].toLowerCase();
        
        if (word === oddWord) {
          foundByte = parseInt(hexByte, 16);
          expectedParity = 1; // odd byte
          break;
        } else if (word === evenWord) {
          foundByte = parseInt(hexByte, 16);
          expectedParity = 0; // even byte
          break;
        }
      }
      
      if (foundByte === null) {
        // Word not found - likely forgotten or mistyped
        throw new Error(`Unknown PGP word at position ${i}: "${word}". Word was forgotten or mistyped.`);
      }
      
      // Verify the byte matches expected parity
      if ((foundByte % 2) !== expectedParity) {
        throw new Error(`Invalid word at position ${i}: "${word}" is for ${expectedParity === 1 ? 'odd' : 'even'} bytes.`);
      }
      
      bytes.push(foundByte);
    }
    
    // Convert bytes back to hex
    return bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
  } catch (e) {
    // If it's our validation error, throw it; otherwise return original
    if (e.message.includes('Unknown PGP word') || e.message.includes('Invalid word')) {
      throw e;
    }
    return trimmed.toUpperCase();
  }
}

// Get code from URL if scanned
const urlParams = new URLSearchParams(window.location.search);
const scannedCode = urlParams.get('code');
if (scannedCode) {
  document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('codeInput').value = scannedCode;
    // Automatically connect when code is provided in URL
    setTimeout(() => {
      connectToSender();
    }, 500);
  });
}

// Set up event listeners when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Clear and focus the code input field on page load (for fresh connections on reload)
  // But only if there's no code in the URL
  const codeInput = document.getElementById('codeInput');
  const urlParams = new URLSearchParams(window.location.search);
  const hasCodeInUrl = urlParams.has('code');
  
  if (codeInput) {
    if (!hasCodeInUrl) {
      codeInput.value = '';
      codeInput.focus();
    }
    
    // Connect on Enter key press
    codeInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        connectToSender();
      }
    });
  }
  
  // Connect button
  const connectBtn = document.getElementById('connectBtn');
  if (connectBtn) {
    connectBtn.addEventListener('click', connectToSender);
  }
});

// Set up WebSocket connection for real-time updates
function setupWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}`;
  
  ws = new WebSocket(wsUrl);
  
  ws.onopen = () => {
    console.log('WebSocket connected');
    // Subscribe to session as receiver with auth token
    if (connectionCode && wsToken) {
      ws.send(JSON.stringify({
        type: 'subscribe',
        code: connectionCode,
        role: 'receiver',
        token: wsToken
      }));
      
      // After reconnecting, check for any messages that may have been queued
      if (encryptionKey) {
        fetchAndDisplayMessages();
      }
    }
  };
  
  ws.onmessage = async (event) => {
    try {
      const data = JSON.parse(event.data);
      console.log('WebSocket message:', data);
      
      if (data.type === 'sender-key-available' && data.initiatorPublicKey) {
        // Sender's public key is now available (but we already have it from join)
        // This can happen if sender reconnects
        console.log('Sender key update received');
      } else if (data.type === 'message-available') {
        // New message available, fetch it
        await fetchAndDisplayMessages();
      } else if (data.type === 'keys-available' && data.initiatorPublicKey) {
        // Keys were already available when we subscribed
        console.log('Keys already available');
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  };
  
  ws.onclose = () => {
    console.log('WebSocket disconnected, attempting reconnect...');
    if (connectionCode && connectedSender) {
      setTimeout(setupWebSocket, 2000);
    }
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };
}

// Generate ECDH key pair in browser
async function generateDHKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,  // extractable
    ['deriveBits']
  );
  return keyPair;
}

// Export public key to hex string for transmission
async function exportPublicKey(publicKey) {
  const exported = await crypto.subtle.exportKey('raw', publicKey);
  return Array.from(new Uint8Array(exported))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Import public key from hex string
async function importPublicKey(hexString) {
  const bytes = new Uint8Array(hexString.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  return await crypto.subtle.importKey(
    'raw',
    bytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
}

// Compute shared secret using ECDH
async function computeSharedSecret(privateKey, otherPublicKey) {
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: otherPublicKey },
    privateKey,
    256
  );
  return new Uint8Array(sharedBits);
}

// Derive encryption key from shared secret using HKDF
async function deriveKeyFromSharedSecret(sharedSecret) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );
  
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),  // Zero salt - acceptable per RFC 5869 for uniformly random IKM
      info: new TextEncoder().encode('BetterQR-Encryption-Key')
    },
    keyMaterial,
    256
  );
  
  return new Uint8Array(derivedBits);
}

async function connectToSender() {
  const connectBtn = document.getElementById('connectBtn');
  
  try {
    showError('');
    let code = document.getElementById('codeInput').value.trim();
    if (!code) {
      showError('Please enter a connection code');
      return;
    }

    // Disable connect button to prevent double-click
    if (connectBtn) {
      connectBtn.disabled = true;
      connectBtn.innerHTML = 'Connecting...';
    }

    // Decode PGP words if needed
    try {
      code = await decodePgpIfNeeded(code);
    } catch (e) {
      showError(e.message);
      if (connectBtn) {
        connectBtn.disabled = false;
        connectBtn.innerHTML = 'Connect';
      }
      return;
    }

    const status = document.getElementById('connectionStatus');
    status.style.display = 'block';
    status.innerHTML = '<span>Establishing secure connection...</span>';

    // Generate our DH key pair in the browser
    dhKeyPair = await generateDHKeyPair();
    const ourPublicKeyHex = await exportPublicKey(dhKeyPair.publicKey);
    console.log('Receiver: Generated DH key pair');

    // Join the session and send our public key
    const response = await fetch('/api/session/join', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, responderDhPublicKey: ourPublicKeyHex })
    });

    if (response.status === 429) {
      await showRateLimitError();
      return;
    }

    if (!response.ok) {
      const error = await response.json();
      // More specific error messages
      if (response.status === 409) {
        throw new Error('Another receiver is already connected. Please ask the sender to create a new session.');
      }
      throw new Error(error.error || 'Connection failed');
    }

    const data = await response.json();
    connectionCode = data.code;
    wsToken = data.wsToken;  // Store WebSocket auth token

    // The sender's public key should be available immediately (since sender created the session)
    if (data.initiatorPublicKey) {
      // Sender is already connected, establish key immediately
      const senderPublicKey = await importPublicKey(data.initiatorPublicKey);
      const sharedSecret = await computeSharedSecret(dhKeyPair.privateKey, senderPublicKey);
      encryptionKey = await deriveKeyFromSharedSecret(sharedSecret);
      console.log('Receiver: Encryption key established via DH');
    } else {
      throw new Error('Sender public key not available. Session may have expired.');
    }

    // Verify key exchange completed successfully
    if (!encryptionKey) {
      throw new Error('Key exchange failed - encryption key not established');
    }

    connectedSender = true;
    
    // Display security fingerprint
    const keyHash = await hashBuffer(encryptionKey);
    const keyWords = await hashToWords(keyHash);
    const keyHashDisplay = document.getElementById('keyHashDisplay');
    if (keyHashDisplay) {
      keyHashDisplay.innerHTML = `<strong>Security Fingerprint:</strong><br><span class="key-words">${keyWords}</span>`;
      keyHashDisplay.style.display = 'block';
    }
    
    // Hide the connection section
    document.getElementById('codeInputSection').style.display = 'none';
    
    // Show the messages section
    const messagesSection = document.getElementById('messagesSection');
    if (messagesSection) {
      messagesSection.style.display = 'block';
    }
    
    status.innerHTML = '<span style="color: #22543d;">Connected to sender</span>';
    status.classList.add('connected');
    
    setTimeout(() => {
      status.style.display = 'none';
    }, 3000);

    // Set up WebSocket for real-time message notifications
    setupWebSocket();
    
    // Check for any existing messages
    await fetchAndDisplayMessages();
    
  } catch (error) {
    showError('Connection failed: ' + error.message);
    console.error(error);
    
    // Re-enable connect button on error
    if (connectBtn) {
      connectBtn.disabled = false;
      connectBtn.innerHTML = 'Connect';
    }
  }
}

// Fetch and display messages
async function fetchAndDisplayMessages() {
  if (!encryptionKey) {
    console.warn('Cannot fetch messages: encryption key not established yet');
    return;
  }

  try {
    const response = await fetch(`/api/message/retrieve/${connectionCode}`);
    
    if (response.status === 429) {
      await showRateLimitError();
      return;
    }
    
    const data = await response.json();

    if (data.messages && data.messages.length > 0) {
      console.log('Messages received:', data.messages);
      
      // Filter out already displayed messages
      const newMessages = data.messages.filter(msg => {
        const msgId = msg.timestamp || msg.data?.timestamp;
        return msgId && !displayedMessageIds.has(msgId);
      });
      
      if (newMessages.length > 0) {
        // Track these message IDs as displayed
        newMessages.forEach(msg => {
          const msgId = msg.timestamp || msg.data?.timestamp;
          if (msgId) displayedMessageIds.add(msgId);
        });
        displayMessages(newMessages);
      }
    }
  } catch (error) {
    console.error('Error fetching messages:', error);
  }
}

async function displayMessages(messages) {
  const messagesSection = document.getElementById('messagesSection');
  const messagesList = document.getElementById('messagesList');
  messagesSection.style.display = 'block';

  for (const msgWrapper of messages) {
    // Handle both direct msg.type and msg.data.type formats
    const msg = msgWrapper.data || msgWrapper;
    const msgDiv = document.createElement('div');
    msgDiv.className = 'message';

    if (msg.type === 'text') {
      // Decrypt the text message
      let decrypted = '';
      
      if (msg.ciphertext && msg.iv && encryptionKey) {
        decrypted = await decryptText(msg.ciphertext, msg.iv, encryptionKey);
      } else if (msg.text) {
        // Fallback to plain text if no encryption
        decrypted = msg.text;
      } else {
        decrypted = '[Unable to decrypt message]';
      }

      msgDiv.innerHTML = `
        <div class="message-type">Text Message</div>
        <div class="message-text">${escapeHtml(decrypted)}</div>
      `;
    } else if (msg.type === 'files') {
      let filesHtml = '';
      if (msg.files && msg.files.length > 0) {
        filesHtml = await Promise.all(msg.files.map(async (f) => {
          let displayName = f.originalName;
          // Decrypt the file name if encrypted
          if (f.encryptedName && f.nameIv && encryptionKey) {
            displayName = await decryptText(f.encryptedName, f.nameIv, encryptionKey);
          }
          return `
            <div class="file-item-container">
              <a href="#" class="file-item file-download-link" data-filename="${f.filename}" data-name="${displayName}" data-iv="${f.iv || ''}" data-size="${f.size || 0}" style="cursor: pointer;">${escapeHtml(displayName)}</a>
            </div>
          `;
        })).then(results => results.join(''));
      } else {
        filesHtml = '<p style="color: #999;">No files</p>';
      }
      
      msgDiv.innerHTML = `
        <div class="message-type">Files</div>
        <div class="message-files">
          ${filesHtml}
        </div>
      `;
    }

    // Insert at the beginning to show newest messages first
    messagesList.insertBefore(msgDiv, messagesList.firstChild);
  }
}

async function decryptText(ciphertext, iv, encryptionKey) {
  try {
    if (!ciphertext || !iv) return '[No message content]';
    
    const ciphertextBuffer = hexToArray(ciphertext);
    const ivBuffer = hexToArray(iv);
    
    const key = await crypto.subtle.importKey(
      'raw',
      encryptionKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBuffer
      },
      key,
      ciphertextBuffer
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (e) {
    console.error('Text decryption error:', e);
    return '[Decryption failed]';
  }
}

async function decryptFileData(encryptedBuffer, iv, encryptionKey) {
  try {
    if (!encryptedBuffer || !iv) return null;
    
    const ivBuffer = hexToArray(iv);
    
    const key = await crypto.subtle.importKey(
      'raw',
      encryptionKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBuffer
      },
      key,
      encryptedBuffer
    );
    
    return decrypted;
  } catch (e) {
    console.error('File decryption error:', e);
    return null;
  }
}

function hexToArray(hex) {
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}

async function downloadFile(filename, originalName, iv, hash, fileSize) {
  try {
    console.log('[RECEIVER] Downloading file:', originalName, 'Size:', fileSize);
    if (!iv) {
      alert('Missing IV for file decryption - file cannot be decrypted');
      return;
    }
    
    if (!encryptionKey) {
      alert('Encryption key not available - unable to decrypt file');
      return;
    }
    
    // Warn user if file is large (> 50MB)
    if (fileSize > 52428800) {
      const fileSizeMB = (fileSize / 1048576).toFixed(2);
      const proceed = confirm(`This file is ${fileSizeMB} MB. Downloading and decrypting large files may take a moment. Please be patient.\n\nContinue?`);
      if (!proceed) return;
    }
    
    // Fetch the encrypted file from the server
    const response = await fetch(`/api/file/download/${encodeURIComponent(filename)}`);
    
    if (response.status === 429) {
      await showRateLimitError();
      return;
    }
    
    if (!response.ok) {
      alert(`Failed to download file: ${response.statusText}`);
      return;
    }
    
    // Get the file as an array buffer
    const encryptedBuffer = await response.arrayBuffer();
    
    // Decrypt the file
    const decryptedBuffer = await decryptFileData(encryptedBuffer, iv, encryptionKey);
    if (!decryptedBuffer) {
      alert('Failed to decrypt file');
      return;
    }
    
    // Verify hash if provided
    if (hash) {
      const hashArray = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', decryptedBuffer)));
      const computedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      if (computedHash !== hash) {
        alert('Warning: Hash verification failed! The file may have been corrupted or tampered with.');
      }
    }
    
    // Create a download link for the decrypted file
    const blob = new Blob([decryptedBuffer]);
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = originalName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Error downloading file:', error);
    alert(`Error downloading file: ${error.message}`);
  }
}

function showError(message) {
  const errorDiv = document.getElementById('error');
  errorDiv.textContent = message;
  errorDiv.style.display = message ? 'block' : 'none';
}

async function showRateLimitError() {
  const errorDiv = document.getElementById('error');
  
  // Fetch available images and pick one at random
  let imageSrc = '/429/Calm down you must.png'; // fallback
  try {
    const response = await fetch('/api/429-images');
    const data = await response.json();
    if (data.images && data.images.length > 0) {
      const randomImage = data.images[Math.floor(Math.random() * data.images.length)];
      imageSrc = `/429/${encodeURIComponent(randomImage)}`;
    }
  } catch (e) {
    console.error('Failed to fetch 429 images:', e);
  }
  
  errorDiv.innerHTML = `
    <div style="text-align: center;">
      <img src="${imageSrc}" alt="Rate Limited" style="max-width: 300px; margin-bottom: 15px; border-radius: 8px;">
      <p><strong>Too Many Requests</strong></p>
      <p>You're being rate limited. Please wait a moment before trying again.</p>
    </div>
  `;
  errorDiv.style.display = 'block';
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function hashBuffer(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashToWords(hashHex) {
  // Load EFF wordlist
  const response = await fetch('/eff_wordlist.json');
  const data = await response.json();
  const wordlist = data.eff_wordlist;
  const listLength = wordlist.length;
  
  // Convert hex hash to bytes
  const hashBytes = [];
  for (let i = 0; i < hashHex.length; i += 2) {
    hashBytes.push(parseInt(hashHex.substr(i, 2), 16));
  }
  
  // Take first 6 bytes (48 bits) of hash and split into 3 chunks
  const words = [];
  for (let i = 0; i < 3; i++) {
    const byte1 = hashBytes[i * 2] || 0;
    const byte2 = hashBytes[i * 2 + 1] || 0;
    const twoBytes = (byte1 << 8) | byte2;
    const index = twoBytes % listLength;
    words.push(wordlist[index]);
  }
  
  return words.join(' ');
}

// Event delegation for file download links
document.addEventListener('click', function(e) {
  const link = e.target.closest('.file-download-link');
  if (link) {
    e.preventDefault();
    const filename = link.dataset.filename;
    const name = link.dataset.name;
    const iv = link.dataset.iv;
    const hash = link.dataset.hash;
    const size = parseInt(link.dataset.size) || 0;
    downloadFile(filename, name, iv, hash, size);
  }
});
