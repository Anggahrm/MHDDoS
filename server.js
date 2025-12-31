const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const { body, validationResult } = require('express-validator');

const app = express();
const port = process.env.PORT || 3000;

// Socket path for tmate
const TMATE_SOCKET = '/tmp/tmate.sock';

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Helper function to execute shell commands securely
const executeCommand = (command) => {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(new Error(`Command failed: ${command}\nError: ${stderr}`));
            } else {
                resolve(stdout.trim());
            }
        });
    });
};

// Route for serving the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route for creating tmate sessions
app.post('/create-tmate',
    // Input validation
    body('sessionName').optional().isString().trim().escape(),
    async (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const sessionName = req.body.sessionName || `session-${Date.now()}`;
        
        // Sanitize sessionName to prevent command injection
        const sanitizedSessionName = sessionName.replace(/[^a-zA-Z0-9-_]/g, '');

        // Create tmate session without API key (uses public tmate.io server)
        const createSessionCmd = `tmate -S ${TMATE_SOCKET} -n ${sanitizedSessionName} new-session -d`;

        console.log('Executing command:', createSessionCmd);

        try {
            await executeCommand(createSessionCmd);

            // Wait for tmate session to be ready
            await executeCommand(`tmate -S ${TMATE_SOCKET} wait tmate-ready`);

            // Get connection information
            const sshConn = await executeCommand(`tmate -S ${TMATE_SOCKET} display -p "#{tmate_ssh}"`);
            const webConn = await executeCommand(`tmate -S ${TMATE_SOCKET} display -p "#{tmate_web}"`);

            res.json({
                sessionName: sanitizedSessionName,
                sshLink: sshConn,
                webLink: webConn
            });
        } catch (error) {
            console.error('Error creating tmate session:', error.message);
            next(new Error(`Failed to create tmate session: ${error.message}`));
        }
    }
);

// Global error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Terjadi kesalahan pada server!',
        details: err.message
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server berjalan di http://localhost:${port}`);
});
