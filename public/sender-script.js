// Redirect to HTTPS if crypto.subtle is not available (required for encryption)
if (!window.crypto || !window.crypto.subtle) {
  if (window.location.protocol === 'http:') {
    window.location.href = window.location.href.replace('http:', 'https:');
  } else {
    alert('Your browser does not support the Web Crypto API. Please use a modern browser.');
  }
}

let selectedFiles = []; // Will store: {name, size, file}
let sentMessages = []; // Store sent messages for history
let connectionCode = null;
let encryptionKey = null;
let connectedReceiver = false;
let ws = null;  // WebSocket connection
let wsToken = null;  // WebSocket authentication token
let dhKeyPairPending = null;  // Store DH key pair while waiting for receiver's key
let receiverKeyResolver = null;  // Resolver for waiting on receiver's key
let maxFileSize = 5 * 1024 * 1024 * 1024; // Default 5GB, will be updated from server

// Fetch and display max file size on page load
async function displayMaxFileSize() {
  try {
    const response = await fetch('/api/config');
    const config = await response.json();
    maxFileSize = config.maxFileSize; // Store for validation
    const maxSizeElement = document.getElementById('maxSizeInfo');
    if (maxSizeElement && config.maxFileSizeFormatted) {
      maxSizeElement.textContent = `(Maximum message size: ${config.maxFileSizeFormatted})`;
    }
  } catch (error) {
    console.error('Error fetching max file size:', error);
    const maxSizeElement = document.getElementById('maxSizeInfo');
    if (maxSizeElement) {
      maxSizeElement.textContent = '(Max size configured on server)';
    }
  }
}

// Call on page load
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', displayMaxFileSize);
} else {
  displayMaxFileSize();
}

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
  document.getElementById('codeInput').value = scannedCode;
  // Automatically connect when code is provided in URL
  setTimeout(() => {
    connectToReceiver();
  }, 500);
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
        connectToReceiver();
      }
    });
  }
  
  // Connect button
  const connectBtn = document.getElementById('connectBtn');
  if (connectBtn) {
    connectBtn.addEventListener('click', connectToReceiver);
  }
  
  // Send button
  const sendBtn = document.getElementById('sendBtn');
  if (sendBtn) {
    sendBtn.addEventListener('click', sendMessage);
  }
    
  // File upload area - click to open file picker
  const fileUploadArea = document.getElementById('fileUploadArea');
  if (fileUploadArea) {
    fileUploadArea.addEventListener('click', () => {
      document.getElementById('fileInput').click();
    });
  }
  
  // File input change handler
  const fileInput = document.getElementById('fileInput');
  if (fileInput) {
    fileInput.addEventListener('change', handleFileSelect);
  }
});

// Drag and drop support
document.addEventListener('dragover', (e) => {
  e.preventDefault();
  document.querySelector('.file-upload-label').style.background = '#f0f0f0';
});

document.addEventListener('dragleave', (e) => {
  e.preventDefault();
  document.querySelector('.file-upload-label').style.background = '#f8f8f8';
});

document.addEventListener('drop', (e) => {
  e.preventDefault();
  handleFileSelect({ dataTransfer: e.dataTransfer });
});

function handleFileSelect(event) {
  const files = event.dataTransfer ? event.dataTransfer.files : event.target.files;
  for (let file of files) {
    if (!validateFileSize(file)) {
      continue;
    }
    if (!selectedFiles.find(f => f.name === file.name && f.size === file.size)) {
      // Store metadata only, not the full file content
      const fileMetadata = { name: file.name, size: file.size, file: file };
      selectedFiles.push(fileMetadata);
    }
  }
  renderFilesList();
}

function renderFilesList() {
  const list = document.getElementById('filesList');
  list.innerHTML = '';
  
  selectedFiles.forEach((file, idx) => {
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
      <div style="flex: 1;">
        <div>${file.name} <span class="file-size">(${formatFileSize(file.size)})</span></div>
      </div>
      <button class="remove-file" onclick="removeFile(${idx})">Remove</button>
    `;
    list.appendChild(item);
  });
}

function removeFile(idx) {
  selectedFiles.splice(idx, 1);
  renderFilesList();
}

const MAX_FILE_SIZE = 5 * 1024 * 1024 * 1024; // 5GB in bytes (deprecated - use maxFileSize instead)

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(unsafe) {
  return unsafe
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function validateFileSize(file) {
  if (file.size > maxFileSize) {
    showError(`File "${file.name}" is too large. Maximum size is ${formatFileSize(maxFileSize)}. File is ${formatFileSize(file.size)}.`);
    return false;
  }
  return true;
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
// Per RFC 5869 Section 3.1: when IKM (ECDH shared secret) is already 
// uniformly random, a zero salt is acceptable as HKDF will use a 
// hash-length string of zeros, which still provides proper extraction.
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
      info: new TextEncoder().encode('ReverseQR-Encryption-Key')
    },
    keyMaterial,
    256
  );
  
  return new Uint8Array(derivedBits);
}

// Set up WebSocket connection for real-time updates
function setupWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}`;
  
  ws = new WebSocket(wsUrl);
  
  ws.onopen = () => {
    console.log('WebSocket connected');
    // Subscribe to session as sender with auth token
    if (connectionCode && wsToken) {
      ws.send(JSON.stringify({
        type: 'subscribe',
        code: connectionCode,
        role: 'sender',
        token: wsToken
      }));
    }
  };
  
  ws.onmessage = async (event) => {
    try {
      const data = JSON.parse(event.data);
      console.log('WebSocket message:', data);
      
      if (data.type === 'receiver-key-available' && data.initiatorPublicKey) {
        // Receiver's public key is now available
        if (dhKeyPairPending && receiverKeyResolver) {
          await completeKeyExchange(dhKeyPairPending, data.initiatorPublicKey);
          receiverKeyResolver();
          receiverKeyResolver = null;
          dhKeyPairPending = null;
        }
      } else if (data.type === 'keys-available' && data.initiatorPublicKey) {
        // Keys were already available when we subscribed
        if (dhKeyPairPending && receiverKeyResolver) {
          await completeKeyExchange(dhKeyPairPending, data.initiatorPublicKey);
          receiverKeyResolver();
          receiverKeyResolver = null;
          dhKeyPairPending = null;
        }
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  };
  
  ws.onclose = () => {
    console.log('WebSocket disconnected');
    // Only reconnect if we're still connected to a session
    if (connectionCode && connectedReceiver) {
      setTimeout(setupWebSocket, 2000);
    }
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };
}

// Wait for receiver's public key via WebSocket
async function waitForReceiverPublicKey(code, dhKeyPair) {
  return new Promise((resolve, reject) => {
    dhKeyPairPending = dhKeyPair;
    receiverKeyResolver = resolve;
    
    // Set up WebSocket if not already connected
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setupWebSocket();
    } else {
      // Already connected, just subscribe with auth token
      ws.send(JSON.stringify({
        type: 'subscribe',
        code: code,
        role: 'sender',
        token: wsToken
      }));
    }

    // Timeout after 60 seconds
    setTimeout(() => {
      if (receiverKeyResolver) {
        receiverKeyResolver = null;
        dhKeyPairPending = null;
        reject(new Error('Timeout waiting for receiver public key'));
      }
    }, 60000);
  });
}

// Complete the key exchange and display security fingerprint
async function completeKeyExchange(dhKeyPair, receiverPublicKeyHex) {
  try {
    console.log('completeKeyExchange: Starting with receiver public key hex:', receiverPublicKeyHex ? 'present' : 'missing');
    
    // Import receiver's public key and compute shared secret
    const receiverPublicKey = await importPublicKey(receiverPublicKeyHex);
    const sharedSecret = await computeSharedSecret(dhKeyPair.privateKey, receiverPublicKey);
    console.log('Sender: Computed shared secret via DH');

    // Derive encryption key from shared secret
    encryptionKey = await deriveKeyFromSharedSecret(sharedSecret);
    console.log('Sender: Encryption key established via DH');

    // Hash the encryption key and display as 3-word code
    const keyHash = await hashBuffer(encryptionKey);
    console.log('Sender: Key hash computed:', keyHash);
    
    const keyWords = await hashToWords(keyHash);
    console.log('Sender: Key words generated:', keyWords);
    
    const keyHashDisplay = document.getElementById('keyHashDisplay');
    console.log('keyHashDisplay element found:', !!keyHashDisplay);
    
    if (keyHashDisplay) {
      keyHashDisplay.innerHTML = `<strong>Security Fingerprint:</strong><br><span class="key-words">${keyWords}</span>`;
      keyHashDisplay.style.display = 'block';
      console.log('Security fingerprint displayed:', keyWords);
    } else {
      console.warn('keyHashDisplay element not found');
    }

    const status = document.getElementById('connectionStatus');
    if (status) {
      status.innerHTML = '<span style="color: #22543d;">Connected to receiver</span>';
      status.classList.add('connected');
    }
  } catch (error) {
    console.error('Error in completeKeyExchange:', error);
    throw error;
  }
}

async function connectToReceiver() {
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
    const dhKeyPair = await generateDHKeyPair();
    const ourPublicKeyHex = await exportPublicKey(dhKeyPair.publicKey);
    console.log('Sender: Generated DH key pair');

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
        throw new Error('Another sender is already connected. Please ask the receiver to send a new code.');
      }
      throw new Error(error.error || 'Connection failed');
    }

    const data = await response.json();
    connectionCode = data.code;
    wsToken = data.wsToken;  // Store WebSocket auth token

    // If receiver's public key is not immediately available, wait via WebSocket
    if (!data.initiatorPublicKey) {
      status.innerHTML = '<span>Waiting for receiver to join...</span>';
      console.log('Sender: Waiting for receiver public key');
      
      // Wait for receiver's public key via WebSocket
      await waitForReceiverPublicKey(connectionCode, dhKeyPair);
    } else {
      // Receiver is already connected, establish key immediately
      await completeKeyExchange(dhKeyPair, data.initiatorPublicKey);
    }

    // Verify key exchange completed successfully before marking as connected
    if (!encryptionKey) {
      throw new Error('Key exchange failed - encryption key not established');
    }

    connectedReceiver = true;
    // Hide the connection section
    document.getElementById('codeInputSection').style.display = 'none';
    // Show the message section
    document.getElementById('messageSection').style.display = 'block';
    // Clear and focus the text input
    const textInput = document.getElementById('textInput');
    if (textInput) {
      textInput.focus();
    }
    setTimeout(() => {
      status.style.display = 'none';
    }, 3000);
  } catch (error) {
    showError('Connection failed: ' + error.message);
    console.error(error);
    
    // Clear code input if another sender is already connected (code is invalid)
    if (error.message.includes('Another sender is already connected')) {
      const codeInput = document.getElementById('codeInput');
      if (codeInput) {
        codeInput.value = '';
        codeInput.focus();
      }
    }
    
    // Re-enable connect button on error
    const connectBtn = document.getElementById('connectBtn');
    if (connectBtn) {
      connectBtn.disabled = false;
      connectBtn.innerHTML = 'Connect';
    }
  }
}

async function encryptData(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV is optimal for AES-GCM per NIST
  const cipher = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    data
  );

  // For GCM mode, the auth tag is included in the cipher
  return {
    ciphertext: new Uint8Array(cipher),
    iv: iv
  };
}

async function deriveKeyFromSecret(secret) {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  return await crypto.subtle.importKey(
    'raw',
    data,
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );
}

async function sendMessage() {
  try {
    if (!connectedReceiver) {
      showError('Not connected to receiver');
      return;
    }

    // Verify key exchange was completed successfully
    if (!encryptionKey) {
      showError('Secure connection not established. Key exchange may have failed. Please reconnect.');
      return;
    }

    const text = document.getElementById('textInput').value;
    if (!text.trim() && selectedFiles.length === 0) {
      showError('Please enter a message or select files');
      return;
    }

    const sendBtn = document.getElementById('sendBtn');
    sendBtn.disabled = true;
    sendBtn.innerHTML = '<span class="spinner"></span><span class="spinner"></span><span class="spinner"></span> Sending...';

    // Send text message if present
    if (text) {
      const textFormData = new FormData();
      textFormData.append('code', connectionCode);
      textFormData.append('messageType', 'text');
      
      // Encrypt the text using AES-256-GCM
      const encoder = new TextEncoder();
      const textData = encoder.encode(text);
      
      // Import the encryptionKey for use with Web Crypto API
      const key = await crypto.subtle.importKey(
        'raw',
        encryptionKey,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );
      
      const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV is optimal for AES-GCM per NIST
      const ivHex = arrayToHex(iv);
      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv
        },
        key,
        textData
      );
      
      const ciphertextHex = arrayToHex(new Uint8Array(encrypted));
      
      textFormData.append('ciphertext', ciphertextHex);
      textFormData.append('iv', ivHex);
      textFormData.append('authTag', '');
      
      const textResponse = await fetch('/api/message/send', {
        method: 'POST',
        body: textFormData
      });

      if (textResponse.status === 429) {
        await showRateLimitError();
        return;
      }

      if (!textResponse.ok) {
        const error = await textResponse.json();
        throw new Error(error.error || 'Send text failed');
      }
    }
    
    // Send files if present
    if (selectedFiles.length > 0) {
      const formData = new FormData();
      formData.append('code', connectionCode);
      formData.append('messageType', 'files');
      
      const key = await crypto.subtle.importKey(
        'raw',
        encryptionKey,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );
      
      for (let fileMetadata of selectedFiles) {
        const fileBuffer = await fileMetadata.file.arrayBuffer();
        const fileUint8Array = new Uint8Array(fileBuffer);
        const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV is optimal for AES-GCM per NIST
        const ivHex = arrayToHex(iv);
        
        // Encrypt the file name
        const fileNameKey = await crypto.subtle.importKey(
          'raw',
          encryptionKey,
          { name: 'AES-GCM' },
          false,
          ['encrypt']
        );
        const fileNameIv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV is optimal for AES-GCM per NIST
        const fileNameIvHex = arrayToHex(fileNameIv);
        const fileNameEncoder = new TextEncoder();
        const fileNameData = fileNameEncoder.encode(fileMetadata.name);
        const encryptedFileName = await crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: fileNameIv
          },
          fileNameKey,
          fileNameData
        );
        const encryptedFileNameHex = arrayToHex(new Uint8Array(encryptedFileName));
        
        const encrypted = await crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: iv
          },
          key,
          fileUint8Array
        );
        
        // Create a new File object with encrypted data
        const encryptedBlob = new Blob([new Uint8Array(encrypted)], { type: 'application/octet-stream' });
        // Use generic filename to avoid transmitting original filename
        const genericFilename = `encrypted_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const encryptedFile = new File(
          [encryptedBlob],
          genericFilename,
          { type: 'application/octet-stream' }
        );
        
        formData.append('files', encryptedFile);
        formData.append('fileIvs[]', ivHex);
        formData.append('fileNames[]', encryptedFileNameHex);
        formData.append('fileNameIvs[]', fileNameIvHex);
      }
      
      const response = await fetch('/api/message/send', {
        method: 'POST',
        body: formData
      });

      if (response.status === 429) {
        await showRateLimitError();
        return;
      }

      if (!response.ok) {
        let errorMessage = 'Send files failed';
        try {
          const contentType = response.headers.get('content-type');
          if (contentType && contentType.includes('application/json')) {
            const error = await response.json();
            errorMessage = error.error || errorMessage;
          } else {
            errorMessage = `Server error: ${response.status} ${response.statusText}`;
          }
        } catch (parseError) {
          errorMessage = `Server error: ${response.status} ${response.statusText}`;
        }
        throw new Error(errorMessage);
      }
    }

    showSuccess('Message sent securely!');
    
    // Add to sent messages history
    if (text) {
      sentMessages.push({
        type: 'text',
        text: text,
        files: [],
        timestamp: Date.now()
      });
    }
    
    if (selectedFiles.length > 0) {
      sentMessages.push({
        type: 'files',
        text: '',
        files: selectedFiles.map(f => ({
          name: f.name,
          size: f.size
        })),
        timestamp: Date.now()
      });
    }
    
    displaySentMessages();
    
    document.getElementById('textInput').value = '';
    
    // Clear file contents from memory to free RAM, but keep hashes
    selectedFiles.forEach(f => {
      if (f.file) {
        f.file = null; // Release file reference
      }
    });
    selectedFiles = [];
    renderFilesList();

    sendBtn.disabled = false;
    sendBtn.innerHTML = 'Send Securely';
  } catch (error) {
    showError('Send failed: ' + error.message);
    document.getElementById('sendBtn').disabled = false;
    document.getElementById('sendBtn').innerHTML = 'Send Securely';
    console.error(error);
  }
}

function displaySentMessages() {
  const messagesList = document.getElementById('messagesList');
  if (sentMessages.length === 0) {
    messagesList.innerHTML = '';
    return;
  }
  
  messagesList.innerHTML = '<div class="sent-messages-title">Sent Messages</div>';
  
  // Display messages in reverse order (newest first)
  [...sentMessages].reverse().forEach((msg, idx) => {
    const msgDiv = document.createElement('div');
    msgDiv.className = 'sent-message';
    
    if (msg.type === 'text' && msg.text) {
      msgDiv.innerHTML = `
        <div class="message-type">Text</div>
        <div class="message-content">${escapeHtml(msg.text).replace(/\n/g, '<br>')}</div>
      `;
    } else if (msg.files && msg.files.length > 0) {
      const filesHtml = msg.files.map(f => `
        <div class="sent-file">
          <div>${escapeHtml(f.name)} <span class="file-size">(${formatFileSize(f.size)})</span></div>
        </div>
      `).join('');
      msgDiv.innerHTML = `
        <div class="message-type">Files</div>
        <div class="sent-files">${filesHtml}</div>
      `;
    }
    
    messagesList.appendChild(msgDiv);
  });
}

function stringToHex(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  return Array.from(data).map(b => b.toString(16).padStart(2, '0')).join('');
}

function arrayToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashText(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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
  // Each chunk is used with modulo to get wordlist index
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

function showError(message) {
  const errorDiv = document.getElementById('error');
  errorDiv.textContent = message;
  errorDiv.style.display = message ? 'block' : 'none';
}

async function showRateLimitError() {
  const errorDiv = document.getElementById('error');
  
  // Fetch available images and pick one at random
  let imageSrc = '/429/Calm down you must.webp'; // fallback
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

function showSuccess(message) {
  const successDiv = document.getElementById('success');
  successDiv.textContent = message;
  successDiv.style.display = 'block';
  setTimeout(() => {
    successDiv.style.display = 'none';
  }, 5000);
}
