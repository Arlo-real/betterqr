const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const QRCode = require('qrcode');
const multer = require('multer');
const WebSocket = require('ws');
const rateLimit = require('express-rate-limit');
const { execSync } = require('child_process');
require('dotenv').config({ path: path.join(__dirname, '../.env') });

const ConnectionManager = require('./connectionManager');
const EncryptionManager = require('./encryptionManager');
const { encodeToPgp, decodeFromPgp } = require('./pgpWordlist');

const app = express();

// Trust proxy to correctly identify client IP from X-Forwarded-For header (set by nginx)
// Required for accurate rate limiting when behind a reverse proxy
app.set('trust proxy', 1);

// Parse size strings like "100mb", "1gb", etc. into bytes
function parseSize(sizeStr) {
  if (typeof sizeStr === 'number') return sizeStr;
  if (!sizeStr) return null;
  
  const match = sizeStr.toString().toLowerCase().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb|tb)?$/);
  if (!match) {
    // Try parsing as plain number
    const num = parseInt(sizeStr);
    return isNaN(num) ? null : num;
  }
  
  const value = parseFloat(match[1]);
  const unit = match[2] || 'b';
  
  const multipliers = {
    'b': 1,
    'kb': 1024,
    'mb': 1024 * 1024,
    'gb': 1024 * 1024 * 1024,
    'tb': 1024 * 1024 * 1024 * 1024
  };
  
  return Math.floor(value * multipliers[unit]);
}

// Configuration
const BASE_URL = process.env.BASE_URL || 'https://localhost:3000';
const PORT = process.env.PORT || 3000;
const MAX_FILE_SIZE_BYTES = parseSize(process.env.MAX_FILE_SIZE_BYTES) || 104857600; // 100MB default
const BODY_SIZE_LIMIT = process.env.BODY_SIZE_LIMIT || '1gb';
const SESSION_TIMEOUT_MS = parseInt(process.env.SESSION_TIMEOUT_MS || '900000'); // 15 minutes default
const CLEANUP_INTERVAL_MS = parseInt(process.env.CLEANUP_INTERVAL_MS || '300000'); // 5 minutes default
const FILE_RETENTION_TIME = parseInt(process.env.FILE_RETENTION_TIME || '30') * 60 * 1000; // Convert minutes to milliseconds
const UPLOAD_DIR = path.join(__dirname, '../public/uploads');

// Rate limiting configuration
const GLOBAL_RATE_LIMIT_WINDOW_MS = parseInt(process.env.GLOBAL_RATE_LIMIT_WINDOW_MS || '60000');
const GLOBAL_RATE_LIMIT_MAX = parseInt(process.env.GLOBAL_RATE_LIMIT_MAX || '10000');
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000');
const RATE_LIMIT_MAX_REQUESTS = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100');
const SESSION_RATE_LIMIT_WINDOW_MS = parseInt(process.env.SESSION_RATE_LIMIT_WINDOW_MS || '60000');
const SESSION_RATE_LIMIT_MAX = parseInt(process.env.SESSION_RATE_LIMIT_MAX || '10');
const UPLOAD_RATE_LIMIT_WINDOW_MS = parseInt(process.env.UPLOAD_RATE_LIMIT_WINDOW_MS || '60000');
const UPLOAD_RATE_LIMIT_MAX = parseInt(process.env.UPLOAD_RATE_LIMIT_MAX || '5');

// Ensure upload directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Map to track uploaded files and their creation timestamps
const uploadedFiles = new Map();

// Map to track active file downloads to prevent race conditions during cleanup
// Key: filename, Value: number of active downloads
const activeDownloads = new Map();

// Logging utility
function logEvent(ip, action, details = '') {
  const timestamp = new Date().toLocaleTimeString('en-US', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  });
  console.log(`[${timestamp}] ${ip.padEnd(15)} | ${action.padEnd(20)} ${details}`);
}

// Middleware
app.use(express.json({ limit: BODY_SIZE_LIMIT }));
app.use(express.urlencoded({ limit: BODY_SIZE_LIMIT, extended: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Rate limiting middleware
// Global rate limiter (DDoS protection - all requests combined)
const globalDdosLimiter = rateLimit({
  windowMs: GLOBAL_RATE_LIMIT_WINDOW_MS,
  max: GLOBAL_RATE_LIMIT_MAX,
  message: { error: 'Server is under heavy load, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => 'global',  // All requests share same key
  skip: (req) => {
    // Always allow error image endpoints so they can be displayed during rate limiting
    return req.path === '/api/429-images' || req.path === '/api/404-images' || 
           req.path.startsWith('/429/') || req.path.startsWith('/404/');
  },
  handler: (req, res, next, options) => {
    console.log(`[RATE_LIMIT] Global DDoS limit exceeded - Path: ${req.path}, IP: ${req.ip}`);
    res.status(429).json(options.message);
  }
});

// General rate limiter for all API endpoints
const generalLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX_REQUESTS,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for static files and error image endpoints
    if (!req.path.startsWith('/api/')) return true;
    if (req.path === '/api/429-images' || req.path === '/api/404-images') return true;
    return false;
  },
  handler: (req, res, next, options) => {
    console.log(`[RATE_LIMIT] General API limit exceeded - Path: ${req.path}, IP: ${req.ip}`);
    res.status(429).json(options.message);
  }
});

// Stricter rate limiter for session creation (prevent session exhaustion)
const sessionLimiter = rateLimit({
  windowMs: SESSION_RATE_LIMIT_WINDOW_MS,
  max: SESSION_RATE_LIMIT_MAX,
  message: { error: 'Too many sessions created, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.log(`[RATE_LIMIT] Session creation limit exceeded - IP: ${req.ip}`);
    res.status(429).json(options.message);
  }
});

// Strictest rate limiter for file uploads
const uploadLimiter = rateLimit({
  windowMs: UPLOAD_RATE_LIMIT_WINDOW_MS,
  max: UPLOAD_RATE_LIMIT_MAX,
  message: { error: 'Too many uploads, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res, next, options) => {
    console.log(`[RATE_LIMIT] Upload limit exceeded - IP: ${req.ip}`);
    res.status(429).json(options.message);
  }
});

// Apply global DDoS protection first (before per-IP limits)
app.use(globalDdosLimiter);

// Apply general rate limiting to all API routes
app.use('/api/', generalLimiter);

// Multer for file uploads - use disk storage to support large files
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    // Use random filename without original name for privacy
    const randomName = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}_${crypto.randomBytes(8).toString('hex')}`;
    cb(null, randomName);
  }
});

const upload = multer({ 
  storage,
  limits: { 
    fileSize: MAX_FILE_SIZE_BYTES
  }
});

// Connection manager
const connManager = new ConnectionManager({
  sessionTimeoutMs: SESSION_TIMEOUT_MS,
  cleanupIntervalMs: CLEANUP_INTERVAL_MS
});

// Store DH instances temporarily (keyed by connection code)
const dhInstances = new Map();

// Store WebSocket connections (keyed by connection code)
// Each session can have multiple websocket clients (receiver + sender)
const wsConnections = new Map();

// Helper to broadcast to all clients in a session
function broadcastToSession(code, message) {
  const clients = wsConnections.get(code);
  if (clients) {
    const messageStr = JSON.stringify(message);
    clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(messageStr);
      }
    });
  }
}

// Helper to notify specific role in a session
function notifySessionRole(code, role, message) {
  const clients = wsConnections.get(code);
  if (clients) {
    const messageStr = JSON.stringify(message);
    clients.forEach((ws) => {
      if (ws.readyState === WebSocket.OPEN && ws.role === role) {
        ws.send(messageStr);
      }
    });
  }
}


// * Clean up expired uploaded files

function cleanupExpiredFiles() {
  const now = Date.now();
  let deletedCount = 0;

  try {
    // Read all files in the upload directory
    const files = fs.readdirSync(UPLOAD_DIR);
    
    files.forEach((filename) => {
      const filepath = path.join(UPLOAD_DIR, filename);
      
      try {
        // Get file stats to check creation time
        const stats = fs.statSync(filepath);
        const fileAge = now - stats.mtimeMs; // Use modification time
        
        // If file is older than retention time, delete it
        if (fileAge > FILE_RETENTION_TIME) {
          // Check if file has active downloads - skip if so
          const downloadCount = activeDownloads.get(filename) || 0;
          if (downloadCount > 0) {
            console.log(`Skipping deletion of ${filename} - ${downloadCount} active download(s)`);
          } else {
            fs.unlinkSync(filepath);
            uploadedFiles.delete(filename); // Also remove from map if present
            console.log(`Deleted expired file: ${filename} (age: ${Math.round(fileAge / 1000 / 60)} min)`);
            deletedCount++;
          }
        }
      } catch (err) {
        if (err.code !== 'ENOENT') {
          console.error(`Error processing file ${filename}:`, err.message);
        }
      }
    });
    
    if (deletedCount > 0) {
      console.log(`Cleanup complete: deleted ${deletedCount} expired file(s)`);
    }
  } catch (err) {
    console.error('Error during cleanup:', err.message);
  }
}

// Run cleanup on startup to clean up files from previous sessions
console.log('Running initial cleanup of expired files...');
cleanupExpiredFiles();

// Start cleanup timer for recurring cleanup
const cleanupInterval = setInterval(cleanupExpiredFiles, CLEANUP_INTERVAL_MS);

/**
 * Get available disk space for the upload directory
 * Returns available bytes or null if unable to determine
 */
function getAvailableStorage() {
  try {
    // Use df command to get available space (works on Linux/Mac)
    const output = execSync(`df -B1 "${UPLOAD_DIR}" | tail -1 | awk '{print $4}'`, { encoding: 'utf8' });
    const availableBytes = parseInt(output.trim());
    return isNaN(availableBytes) ? null : availableBytes;
  } catch (error) {
    console.error('Error checking disk space:', error.message);
    return null;
  }
}

/**
 * Middleware to check storage before accepting uploads
 * Compares available disk space against the incoming file size
 * If storage is low, attempts cleanup first, then rejects if still insufficient
 */
function checkStorageMiddleware(req, res, next) {
  const contentLength = parseInt(req.headers['content-length'] || '0');
  
  if (contentLength === 0) {
    // No content-length header or zero size, proceed
    return next();
  }
  
  let availableSpace = getAvailableStorage();
  
  if (availableSpace === null) {
    // Can't determine space - try cleanup first as a precaution, then proceed
    // Flag the request so we can provide a better error if upload fails
    console.log('Warning: Unable to determine available storage space, attempting precautionary cleanup');
    cleanupExpiredFiles();
    req.storageCheckFailed = true;
    return next();
  }
  
  if (availableSpace < contentLength) {
    console.log(`Insufficient storage: ${formatBytes(availableSpace)} available, file size: ${formatBytes(contentLength)}`);
    console.log('Triggering cleanup of expired files...');
    
    // Try to free up space by cleaning expired files
    cleanupExpiredFiles();
    
    // Check again after cleanup
    availableSpace = getAvailableStorage();
    
    if (availableSpace !== null && availableSpace < contentLength) {
      console.log(`Still insufficient storage after cleanup: ${formatBytes(availableSpace)} available`);
      return res.status(507).json({ 
        error: 'Server storage is full. Please try again later.',
        availableSpace: formatBytes(availableSpace),
        fileSize: formatBytes(contentLength)
      });
    }
  }
  
  next();
}

// ============ ROUTES ============

/**
 * Receiver page - displays QR code with connection code
 */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

/**
 * Sender page - scans QR code or inputs connection code
 */
app.get('/sender', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/sender.html'));
});


/**
 * API: Create a new receiver session (receiver initiates)
 * Now accepts the receiver's DH public key from the browser
 */
app.post('/api/session/create', sessionLimiter, async (req, res) => {
  try {
    const { initiatorDhPublicKey } = req.body;
    const clientIp = req.ip;
    
    const code = connManager.createConnection({
      mode: 'receiver',
      initiatorDhPublicKey: initiatorDhPublicKey || null
    });

    // Get the receiver token for WebSocket authentication
    const conn = connManager.getConnection(code);
    const wsToken = conn.receiverToken;

    // Log the event
    logEvent(clientIp, 'created session', `(${code})`);

    // Generate QR code URL
    const qrUrl = `${BASE_URL}/join?code=${code}`;
    const qrCode = await QRCode.toDataURL(qrUrl, { width: 300 });

    // Encode connection code as PGP words (from hex string to bytes)
    const codeBuffer = Buffer.from(code, 'hex');
    const pgpCode = encodeToPgp(codeBuffer);

    res.json({
      code,
      pgpCode,
      qrCode,
      baseUrl: BASE_URL,
      wsToken  // Token for WebSocket authentication
    });
  } catch (error) {
    console.error('Error creating session:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API: Join an existing session as sender
 * Now accepts the sender's DH public key from the browser
 * Only one sender allowed per session
 */
app.post('/api/session/join', (req, res) => {
  try {
    let { code, responderDhPublicKey } = req.body;
    const clientIp = req.ip;

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    // Normalize code to uppercase for consistency
    code = code.toUpperCase();

    const conn = connManager.getConnection(code);
    if (!conn) {
      return res.status(404).json({ error: 'Connection not found' });
    }

    // Check if a sender is already connected
    if (conn.senderConnected) {
      return res.status(409).json({ error: 'A sender is already connected to this session. Only one sender allowed.' });
    }

    // Mark that a sender is now connected
    conn.senderConnected = true;

    // Generate sender token for WebSocket authentication
    const wsToken = connManager.generateSenderToken(code);

    // Log the event
    logEvent(clientIp, 'joined session', `(${code})`);

    // Store sender's DH public key if provided
    if (responderDhPublicKey) {
      connManager.setResponderPublicKey(code, responderDhPublicKey);
      
      // Notify receiver via WebSocket that sender's key is available
      notifySessionRole(code, 'receiver', {
        type: 'sender-key-available',
        responderPublicKey: responderDhPublicKey
      });
    }

    res.json({
      success: true,
      initiatorPublicKey: conn.initiatorDhPublicKey,
      responderPublicKey: conn.responderDhPublicKey,
      code,
      wsToken  // Token for WebSocket authentication
    });
  } catch (error) {
    console.error('Error joining session:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API: Get session status and DH public keys (for receiver to poll for sender's key)
 */
app.get('/api/session/status/:code', (req, res) => {
  try {
    let code = req.params.code;
    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }
    
    code = code.toUpperCase();
    const conn = connManager.getConnection(code);
    
    if (!conn) {
      return res.status(404).json({ error: 'Connection not found' });
    }

    res.json({
      status: conn.status,
      initiatorPublicKey: conn.initiatorDhPublicKey,
      responderPublicKey: conn.responderDhPublicKey
    });
  } catch (error) {
    console.error('Error getting session status:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/message/send', uploadLimiter, checkStorageMiddleware, upload.array('files'), (req, res) => {
  try {
    let { code, messageType, ciphertext, iv, authTag, hash, text } = req.body;
    const clientIp = req.ip;
    
    // Handle file IVs and hashes from FormData
    // Note: form-data parser converts 'fileIvs[]' to 'fileIvs' when parsing multipart
    let fileIvs = [];
    let fileHashes = [];
    let fileNames = [];
    let fileNameIvs = [];
    
    // Try both forms: 'fileIvs[]' and 'fileIvs' (form-data strips the brackets)
    const ivKey = req.body['fileIvs[]'] !== undefined ? 'fileIvs[]' : 'fileIvs';
    const hashKey = req.body['fileHashes[]'] !== undefined ? 'fileHashes[]' : 'fileHashes';
    const nameKey = req.body['fileNames[]'] !== undefined ? 'fileNames[]' : 'fileNames';
    const nameIvKey = req.body['fileNameIvs[]'] !== undefined ? 'fileNameIvs[]' : 'fileNameIvs';
    
    if (req.body[ivKey]) {
      fileIvs = Array.isArray(req.body[ivKey]) 
        ? req.body[ivKey] 
        : [req.body[ivKey]];
    }
    
    if (req.body[hashKey]) {
      fileHashes = Array.isArray(req.body[hashKey]) 
        ? req.body[hashKey] 
        : [req.body[hashKey]];
    }
    
    if (req.body[nameKey]) {
      fileNames = Array.isArray(req.body[nameKey]) 
        ? req.body[nameKey] 
        : [req.body[nameKey]];
    }
    
    if (req.body[nameIvKey]) {
      fileNameIvs = Array.isArray(req.body[nameIvKey]) 
        ? req.body[nameIvKey] 
        : [req.body[nameIvKey]];
    }

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    // Normalize code to uppercase
    code = code.toUpperCase();

    const conn = connManager.getConnection(code);
    if (!conn) {
      return res.status(404).json({ error: 'Connection not found' });
    }

    let messageData = {
      type: messageType || 'text',
      timestamp: Date.now()
    };

    if (messageType === 'text') {
      // Store encrypted text message
      messageData = {
        ...messageData,
        ciphertext,
        iv,
        authTag,
        hash,
        text: text || ''
      };
    } else if (messageType === 'files') {
      // Handle encrypted file uploads
      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'No files provided' });
      }

      const encryptedFiles = [];

      for (let i = 0; i < req.files.length; i++) {
        const file = req.files[i];
        // With disk storage, files are already saved - just reference them
        const filename = file.filename; // filename from disk storage
        const iv = fileIvs[i] || '';
        const hash = fileHashes[i] || '';
        const encryptedName = fileNames[i] || '';
        const nameIv = fileNameIvs[i] || '';

        // Track the file for cleanup
        uploadedFiles.set(filename, Date.now());

        encryptedFiles.push({
          filename,
          size: file.size,
          iv: iv,
          hash: hash,
          encryptedName: encryptedName,
          nameIv: nameIv
        });
      }

      messageData = {
        ...messageData,
        files: encryptedFiles
      };
    }

    // Store the message
    connManager.storeMessage(code, messageData);
    
    // Calculate total size for logging
    // For text messages: ciphertext is hex-encoded (each 2 chars = 1 byte)
    // For files: req.files contains actual file sizes
    let totalSize = 0;
    if (messageType === 'text' && ciphertext) {
      // Hex string: 2 chars per byte
      totalSize += Math.ceil(ciphertext.length / 2);
    }
    if (messageType === 'files' && req.files) {
      req.files.forEach(file => {
        totalSize += file.size;
      });
    }
    
    // Log the event with formatted file size
    const action = messageType === 'files' ? 'sent file(s)' : 'sent message';
    const details = messageType === 'files' ? `(${req.files.length} files) size: ${formatBytes(totalSize)}` : `size: ${formatBytes(totalSize)}`;
    logEvent(clientIp, action, details);
    
    // Notify receiver via WebSocket that a new message is available
    notifySessionRole(code, 'receiver', {
      type: 'message-available',
      messageId: messageData.timestamp,
      messageType: messageData.type
    });

    res.json({
      success: true,
      messageId: messageData.timestamp
    });
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API: Retrieve encrypted messages for a connection
 */
app.get('/api/message/retrieve/:code', (req, res) => {
  try {
    let { code } = req.params;

    // Normalize code to uppercase
    code = code.toUpperCase();

    const conn = connManager.getConnection(code);
    if (!conn) {
      return res.status(404).json({ error: 'Connection not found' });
    }

    const messages = connManager.getMessages(code);
    res.json({
      messages
    });
  } catch (error) {
    console.error('Error retrieving messages:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * API: Download encrypted file
 */
app.get('/api/file/download/:filename', (req, res) => {
  try {
    // Sanitize filename to prevent directory traversal
    const filename = path.basename(req.params.filename);
    const filepath = path.resolve(UPLOAD_DIR, filename);
    const uploadDirResolved = path.resolve(UPLOAD_DIR);
    const clientIp = req.ip;

    // Security: prevent directory traversal with proper path comparison
    if (!filepath.startsWith(uploadDirResolved + path.sep)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    if (!fs.existsSync(filepath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Log the event
    logEvent(clientIp, 'downloaded file', filename);

    // Track active download to prevent cleanup race condition
    const currentCount = activeDownloads.get(filename) || 0;
    activeDownloads.set(filename, currentCount + 1);

    // Helper to decrement download count
    const decrementDownload = () => {
      const count = activeDownloads.get(filename) || 1;
      if (count <= 1) {
        activeDownloads.delete(filename);
      } else {
        activeDownloads.set(filename, count - 1);
      }
    };

    // Stream file as binary instead of loading entire file into memory
    res.setHeader('Content-Type', 'application/octet-stream');
    const stream = fs.createReadStream(filepath);
    
    stream.on('error', (error) => {
      console.error('Stream error:', error);
      decrementDownload();
      if (!res.headersSent) {
        res.status(500).json({ error: 'Failed to download file' });
      }
    });
    
    stream.on('end', () => {
      decrementDownload();
    });
    
    // Also handle client disconnect
    res.on('close', () => {
      if (!res.writableEnded) {
        decrementDownload();
        stream.destroy();
      }
    });
    
    stream.pipe(res);
  } catch (error) {
    console.error('Error downloading file:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Redirect from QR code
 */
app.get('/join', (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.redirect('/sender');
  }
  res.redirect(`/sender?code=${code}`);
});

/**
 * Health check
 */
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

/**
 * API: Get server configuration
 */
app.get('/api/config', (req, res) => {
  const bodyLimitBytes = parseSize(BODY_SIZE_LIMIT);
  res.json({
    maxFileSize: MAX_FILE_SIZE_BYTES,
    maxFileSizeFormatted: formatBytes(MAX_FILE_SIZE_BYTES),
    bodyLimit: BODY_SIZE_LIMIT,
    bodyLimitFormatted: formatBytes(bodyLimitBytes),
    sessionTimeout: SESSION_TIMEOUT_MS,
    fileRetention: FILE_RETENTION_TIME
  });
});

/**
 * API: Get list of 429 rate limit images
 */
app.get('/api/429-images', (req, res) => {
  const imagesDir = path.join(__dirname, '../public/429');
  try {
    const files = fs.readdirSync(imagesDir);
    const imageExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg'];
    const images = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return imageExtensions.includes(ext);
    });
    res.json({ images });
  } catch (error) {
    res.json({ images: [] });
  }
});

/**
 * API: Get list of 404 images
 */
app.get('/api/404-images', (req, res) => {
  const imagesDir = path.join(__dirname, '../public/404');
  try {
    const files = fs.readdirSync(imagesDir);
    const imageExtensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg'];
    const images = files.filter(file => {
      const ext = path.extname(file).toLowerCase();
      return imageExtensions.includes(ext);
    });
    res.json({ images });
  } catch (error) {
    res.json({ images: [] });
  }
});

// ============ 404 HANDLER ============

// Catch-all route for 404 - must be after all other routes
app.use((req, res, next) => {
  // Only serve 404 page for non-API routes
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Endpoint not found' });
  }
  res.status(404).sendFile(path.join(__dirname, '../public/404.html'));
});

// ============ ERROR HANDLING ============

// Handle multer errors (file too large, etc.)
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ 
        error: `File too large. Maximum size is ${formatBytes(MAX_FILE_SIZE_BYTES)}`
      });
    }
    if (error.code === 'LIMIT_PART_COUNT') {
      return res.status(400).json({ error: 'Too many parts in form data' });
    }
    if (error.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({ error: 'Too many files' });
    }
  } else if (error.code === 'ENOSPC') {
    // Disk full - no space left on device
    console.error('Disk full error:', error);
    
    // Try cleanup and report the error
    console.log('Triggering emergency cleanup of expired files...');
    cleanupExpiredFiles();
    
    const storageInfo = req.storageCheckFailed 
      ? ' (storage check was unable to determine available space beforehand)'
      : '';
    
    return res.status(507).json({ 
      error: `Server storage is full. Please try again later.${storageInfo}`
    });
  } else if (error.status === 413) {
    return res.status(413).json({ error: 'Payload too large' });
  }
  
  // Pass other errors to default handler
  next(error);
});

// Default error handler
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ 
    error: error.message || 'Internal server error'
  });
});

// Helper function to format bytes
function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

// ============ START SERVER ============

const server = app.listen(PORT, () => {
  console.log(`ReverseQR server running at ${BASE_URL}`);
  console.log(`Sender: ${BASE_URL}/sender`);
  console.log(`\nConfiguration:`);
  console.log(`   • Max file size: ${formatBytes(MAX_FILE_SIZE_BYTES)}`);
  console.log(`   • Body size limit: ${formatBytes(parseSize(BODY_SIZE_LIMIT))}`);
  console.log(`   • Session timeout: ${SESSION_TIMEOUT_MS / 1000 / 60} minutes`);
  console.log(`   • File retention: ${FILE_RETENTION_TIME / 1000 / 60} minutes`);
  console.log(`   • Cleanup interval: ${CLEANUP_INTERVAL_MS / 1000 / 60} minutes`);
});

// ============ WEBSOCKET SERVER ============

const wss = new WebSocket.Server({ server });

// Helper function to get client IP from WebSocket connection
function getWebSocketClientIp(ws, req) {
  // Try to get IP from request (if available)
  if (req && req.ip) return req.ip;
  // Fallback to socket remote address
  if (ws._socket && ws._socket.remoteAddress) {
    return ws._socket.remoteAddress.replace(/::ffff:/, '');
  }
  return 'unknown';
}

wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      // Handle subscription to a session
      if (data.type === 'subscribe') {
        const { code, role, token } = data;
        if (!code) {
          ws.send(JSON.stringify({ type: 'error', message: 'No session code provided' }));
          return;
        }

        // Validate the authentication token
        if (!token || !connManager.validateToken(code, role, token)) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid or missing authentication token' }));
          console.log(`WebSocket: Rejected unauthorized ${role || 'unknown'} subscription to session ${code}`);
          return;
        }
        
        // Store the session code and role on the websocket
        ws.sessionCode = code;
        ws.role = role || 'unknown';
        const clientIp = getWebSocketClientIp(ws, req);
        ws.clientIp = clientIp;
        
        // Add this websocket to the session's client list
        if (!wsConnections.has(code)) {
          wsConnections.set(code, new Set());
        }
        wsConnections.get(code).add(ws);
        
        ws.send(JSON.stringify({ type: 'subscribed', code, role: ws.role }));
        
        // Check if there's already data to send
        const session = connManager.getConnection(code);
        
        // Log receiver reconnections with different IP
        if (ws.role === 'receiver' && session && session.receiverIp && session.receiverIp !== clientIp) {
          logEvent(clientIp, 'receiver reconnected', `session ${code} (previous IP: ${session.receiverIp})`);
        }
        
        // Track receiver IP for reconnection detection
        if (ws.role === 'receiver' && session) {
          session.receiverIp = clientIp;
        }
        if (session) {
          // If receiver subscribes and sender's key is available, notify immediately
          if (ws.role === 'receiver' && session.responderDhPublicKey) {
            ws.send(JSON.stringify({
              type: 'sender-key-available',
              responderPublicKey: session.responderDhPublicKey
            }));
          }
          // If sender subscribes and receiver's key is available, notify immediately
          if (ws.role === 'sender' && session.initiatorDhPublicKey) {
            ws.send(JSON.stringify({
              type: 'receiver-key-available',
              initiatorPublicKey: session.initiatorDhPublicKey
            }));
          }
        }

        // If receiver subscribes, check for any queued messages
        if (ws.role === 'receiver') {
          const messages = connManager.getMessages(code);
          if (messages && messages.length > 0) {
            // Notify receiver that messages are available
            ws.send(JSON.stringify({
              type: 'message-available',
              messageCount: messages.length
            }));
          }
        }
      }


      // Handle ping/keepalive
      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong' }));
      }
      
    } catch (error) {
      console.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    // Remove from session's client list
    if (ws.sessionCode) {
      const clients = wsConnections.get(ws.sessionCode);
      if (clients) {
        clients.delete(ws);
        if (clients.size === 0) {
          wsConnections.delete(ws.sessionCode);
        }
      }
      
      // If a sender disconnects, clear the senderConnected flag
      if (ws.role === 'sender') {
        const conn = connManager.getConnection(ws.sessionCode);
        if (conn) {
          conn.senderConnected = false;
        }
      } else {
        // Client disconnected
      }
    }
  });
  
  ws.on('error', (error) => {
    console.error('WebSocket error:', error);
  });
});

// Ping all clients every 30 seconds to keep connections alive
const wsHeartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      console.log('WebSocket: Terminating inactive client');
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// Graceful shutdown handler
function gracefulShutdown(signal) {
  console.log(`${signal} received, shutting down gracefully...`);
  
  // Clear all intervals
  clearInterval(cleanupInterval);
  clearInterval(wsHeartbeat);
  connManager.stopCleanupTimer();
  
  // Force exit after 5 seconds if graceful shutdown fails
  const forceExitTimeout = setTimeout(() => {
    console.log('Forcing exit after timeout...');
    process.exit(1);
  }, 5000);
  
  // Close all WebSocket connections
  wss.clients.forEach((client) => {
    try {
      client.terminate();
    } catch (e) {
      // Ignore errors during cleanup
    }
  });
  
  // Close WebSocket server
  wss.close(() => {
    console.log('WebSocket server closed');
    
    // Close HTTP server
    server.close(() => {
      console.log('Server closed');
      clearTimeout(forceExitTimeout);
      process.exit(0);
    });
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

module.exports = app;
