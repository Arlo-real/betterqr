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
    let dhKeyPair = null;  // Our DH key pair
    let ws = null;  // WebSocket connection
    let wsToken = null;  // WebSocket authentication token

    // Set up WebSocket connection
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
          // while the connection was down
          if (encryptionKey) {
            fetchAndDisplayMessages();
          }
        }
      };
      
      ws.onmessage = async (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log('WebSocket message:', data);
          
          if (data.type === 'sender-key-available' && data.responderPublicKey) {
            // Sender's public key is now available
            await handleSenderKeyAvailable(data.responderPublicKey);
          } else if (data.type === 'message-available') {
            // New message available, fetch it
            await fetchAndDisplayMessages();
          } else if (data.type === 'keys-available' && data.responderPublicKey) {
            // Keys were already available when we subscribed
            await handleSenderKeyAvailable(data.responderPublicKey);
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

    // Handle when sender's public key becomes available
    async function handleSenderKeyAvailable(senderPublicKeyHex) {
      if (encryptionKey) {
        // Already have encryption key, ignore duplicate
        return;
      }
      
      console.log('Receiver: Got sender public key via WebSocket, computing shared secret');
      
      // Import sender's public key and compute shared secret
      const senderPublicKey = await importPublicKey(senderPublicKeyHex);
      const sharedSecret = await computeSharedSecret(dhKeyPair.privateKey, senderPublicKey);
      
      // Derive encryption key from shared secret using HKDF
      encryptionKey = await deriveKeyFromSharedSecret(sharedSecret);
      console.log('Receiver: Encryption key established via DH');
      
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
      } catch (hashError) {
        console.error('Error displaying key hash:', hashError);
      }
    }

    // Fetch and display messages (called when WebSocket notifies us)
    async function fetchAndDisplayMessages() {
      // Verify key exchange was completed before fetching messages
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

    async function initializeReceiver() {
      try {
        // Generate our DH key pair in the browser
        dhKeyPair = await generateDHKeyPair();
        const ourPublicKeyHex = await exportPublicKey(dhKeyPair.publicKey);
        console.log('Receiver: Generated DH key pair');

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
          info: new TextEncoder().encode('ReverseQR-Encryption-Key')
        },
        keyMaterial,
        256
      );
      
      return new Uint8Array(derivedBits);
    }

    let displayedMessageIds = new Set();

    async function displayMessages(messages) {
      const messagesSection = document.getElementById('messagesSection');
      const messagesList = document.getElementById('messagesList');
      messagesSection.style.display = 'block';

      // Only clear on first display (when messagesList is empty)
      if (messagesList.children.length === 0) {
        messagesList.innerHTML = '';
      }

      for (const msgWrapper of messages) {
        // Handle both direct msg.type and msg.data.type formats
        const msg = msgWrapper.data || msgWrapper;
        const msgDiv = document.createElement('div');
        msgDiv.className = 'message';

        if (msg.type === 'text') {
          // Decrypt the text message - must have ciphertext
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

    function decryptMessage(ciphertext, iv, authTag) {
      // This is now called with encrypted data that needs decryption
      // Since we're using Web Crypto API on the client, we need async handling
      // For now, return a promise that will be handled in displayMessages
      try {
        if (!ciphertext) return '[No message content]';
        // Return hex string for async decryption
        return ciphertext;
      } catch (e) {
        console.error('Decryption error:', e);
        return '[Decryption failed]';
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

    function verifyHash(data, expectedHash) {
      if (!expectedHash) return false;
      
      // Data can be either string or Uint8Array
      let buffer;
      if (typeof data === 'string') {
        buffer = new TextEncoder().encode(data);
      } else if (data instanceof Uint8Array) {
        buffer = data;
      } else {
        return false;
      }
      
      // Compute SHA256 of the data
      return crypto.subtle.digest('SHA-256', buffer).then(hashBuffer => {
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex === expectedHash;
      });
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
      errorDiv.style.display = 'block';
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

    // Initialize on page load
    window.addEventListener('DOMContentLoaded', () => {
      initializeReceiver();
      
      // Set up copy code button event listener
      const copyCodeBtn = document.getElementById('copyCodeBtn');
      if (copyCodeBtn) {
        copyCodeBtn.addEventListener('click', copyCode);
      }
    });

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
