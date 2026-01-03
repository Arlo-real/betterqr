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
let dhKeyPair = null;  // Our DH key pair
let ws = null;  // WebSocket connection
let wsToken = null;  // WebSocket authentication token
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

// Set up WebSocket connection
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
      
      if (data.type === 'receiver-key-available' && data.responderPublicKey) {
        // Receiver's public key is now available
        await handleReceiverKeyAvailable(data.responderPublicKey);
      } else if (data.type === 'keys-available' && data.responderPublicKey) {
        // Keys were already available when we subscribed
        await handleReceiverKeyAvailable(data.responderPublicKey);
      }
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  };
  
  ws.onclose = () => {
    console.log('WebSocket disconnected, attempting reconnect...');
    setTimeout(setupWebSocket, 2000);
  };
  
  ws.onerror = (error) => {
    console.error('WebSocket error:', error);
  };
}

// Handle when receiver's public key becomes available
async function handleReceiverKeyAvailable(receiverPublicKeyHex) {
  if (encryptionKey) {
    // Already have encryption key, ignore duplicate
    return;
  }
  
  console.log('Sender: Got receiver public key via WebSocket, computing shared secret');
  
  // Import receiver's public key and compute shared secret
  const receiverPublicKey = await importPublicKey(receiverPublicKeyHex);
  const sharedSecret = await computeSharedSecret(dhKeyPair.privateKey, receiverPublicKey);
  
  // Derive encryption key from shared secret using HKDF
  encryptionKey = await deriveKeyFromSharedSecret(sharedSecret);
  console.log('Sender: Encryption key established via DH');
  
  // Display the security fingerprint and hide loading status
  try {
    const keyHash = await hashBuffer(encryptionKey);
    const keyWords = await hashToWords(keyHash);
    const keyHashDisplay = document.getElementById('keyHashDisplay');
    if (keyHashDisplay) {
      keyHashDisplay.innerHTML = `<strong>Security Fingerprint:</strong><br><span class="key-words">${keyWords}</span>`;
      keyHashDisplay.style.display = 'block';
    }
    // Hide the loading status
    const status = document.querySelector('.status');
    if (status) {
      status.style.display = 'none';
    }
    // Hide the QR code, connection code, and link after successful connection
    const qrSection = document.querySelector('.qr-section');
    if (qrSection) {
      qrSection.style.display = 'none';
    }
    // Enable the send button now that receiver is connected
    const sendBtn = document.getElementById('sendBtn');
    if (sendBtn) {
      sendBtn.disabled = false;
      sendBtn.innerHTML = 'Send Securely';
    }
    // Focus the text input if it's empty, otherwise keep user's cursor position
    const textInput = document.getElementById('textInput');
    if (textInput && !textInput.value) {
      textInput.focus();
    }
  } catch (hashError) {
    console.error('Error displaying key hash:', hashError);
  }
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

async function initializeSender() {
  try {
    // Generate our DH key pair in the browser
    dhKeyPair = await generateDHKeyPair();
    const ourPublicKeyHex = await exportPublicKey(dhKeyPair.publicKey);
    console.log('Sender: Generated DH key pair');

    // Create session and send our public key to server
    const response = await fetch('/api/session/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ initiatorDhPublicKey: ourPublicKeyHex })
    });
    
    if (response.status === 429) {
      await showRateLimitError();
      return;
    }
    
    const data = await response.json();

    connectionCode = data.code;
    wsToken = data.wsToken;  // Store WebSocket auth token
    document.getElementById('pgpCode').textContent = data.pgpCode;

    // Display QR URL in plain text
    const qrUrl = `${data.baseUrl}/join?code=${data.code}`;
    document.getElementById('qrUrl').textContent = qrUrl;

    // Display QR code (server-generated as data URL)
    const qrImage = document.getElementById('qrCode');
    qrImage.src = data.qrCode;

    // Set up WebSocket for real-time updates
    setupWebSocket();
  } catch (error) {
    showError('Failed to create session: ' + error.message);
    console.error(error);
  }
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
      info: new TextEncoder().encode('BetterQR-Encryption-Key')
    },
    keyMaterial,
    256
  );
  
  return new Uint8Array(derivedBits);
}

function copyCode() {
  const codeElement = document.getElementById('pgpCode');
  const text = codeElement.textContent;
  navigator.clipboard.writeText(text).then(() => {
    const button = event.target;
    button.textContent = 'Copied!';
    button.classList.add('copied');
    setTimeout(() => {
      button.textContent = 'Copy Code';
      button.classList.remove('copied');
    }, 2000);
  });
}

function showError(message) {
  const errorDiv = document.getElementById('error');
  errorDiv.textContent = message;
  errorDiv.style.display = message ? 'block' : 'none';
}

function showSuccess(message) {
  const successDiv = document.getElementById('success');
  if (successDiv) {
    successDiv.textContent = message;
    successDiv.style.display = 'block';
    setTimeout(() => {
      successDiv.style.display = 'none';
    }, 5000);
  }
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
  
  // Hide other sections
  const qrSection = document.querySelector('.qr-section');
  if (qrSection) qrSection.style.display = 'none';
  const status = document.querySelector('.status');
  if (status) status.style.display = 'none';
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

// File handling functions
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
  if (!list) return;
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

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function validateFileSize(file) {
  if (file.size > maxFileSize) {
    showError(`File "${file.name}" is too large. Maximum size is ${formatFileSize(maxFileSize)}. File is ${formatFileSize(file.size)}.`);
    return false;
  }
  return true;
}

function arrayToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sendMessage() {
  try {
    if (!encryptionKey) {
      showError('Not connected to receiver yet. Wait for them to scan the QR code.');
      return;
    }

    const text = document.getElementById('textInput').value.trim();
    if (!text && selectedFiles.length === 0) {
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
      
      const iv = crypto.getRandomValues(new Uint8Array(16));
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
        const iv = crypto.getRandomValues(new Uint8Array(16));
        const ivHex = arrayToHex(iv);
        
        // Encrypt the file name
        const fileNameKey = await crypto.subtle.importKey(
          'raw',
          encryptionKey,
          { name: 'AES-GCM' },
          false,
          ['encrypt']
        );
        const fileNameIv = crypto.getRandomValues(new Uint8Array(16));
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
  if (!messagesList) return;
  
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
        <div class="message-content">${escapeHtml(msg.text)}</div>
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

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
  initializeSender();
  
  // Set up copy code button event listener
  const copyCodeBtn = document.getElementById('copyCodeBtn');
  if (copyCodeBtn) {
    copyCodeBtn.addEventListener('click', copyCode);
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
  const label = document.querySelector('.file-upload-label');
  if (label) label.style.background = '#f0f0f0';
});

document.addEventListener('dragleave', (e) => {
  e.preventDefault();
  const label = document.querySelector('.file-upload-label');
  if (label) label.style.background = '#f8f8f8';
});

document.addEventListener('drop', (e) => {
  e.preventDefault();
  handleFileSelect({ dataTransfer: e.dataTransfer });
});
