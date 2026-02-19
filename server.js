// server.js
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import pkg from "pg";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import unirest from 'unirest';
import nodemailer from 'nodemailer';
import multer from 'multer'; // Add this import
import fs from 'fs'; // Add this import
import path from 'path'; // Add this import
import { fileURLToPath } from 'url'; // Add this import
import { exec } from 'child_process';
import util from 'util';
import axios from 'axios';
import FormData from 'form-data';


dotenv.config();

const { Pool } = pkg;

// Import the employee report routes
import employeeReportRoutes from './employeeReportApi.js';

const app = express();
const PORT = process.env.PORT || 5050;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Middleware
app.use(cors({
  origin: ["http://localhost:5173", "http://10.41.11.103:5173", "http://localhost:80", "http://localhost", "http://10.41.11.87:5173",],
  credentials: true
}));
app.use(express.json());





// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  // database: process.env.DB_NAME || "statusbot_poc",
  // database: process.env.DB_NAME || "msp_db_poc1",
  // database: process.env.DB_NAME || "statusbot_poc_06_01",
  // database: process.env.DB_NAME || "statusbot_poc_28_01",
  database: process.env.DB_NAME || "statusbot_poc_02_02",
  // database: process.env.DB_NAME || "poc_bot",
  // password: process.env.DB_PASSWORD || "root",
  password: process.env.DB_PASSWORD || "nitin258",
  // port: process.env.DB_PORT || 5433,
  port: process.env.DB_PORT || 5432,
});

// Store database pool in app.locals so routes can access it
app.locals.db = pool;

// Email configuration for initiated POC notifications
const emailConfig = {
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT) || 587,
  secure: false, // false for port 587
  requireTLS: true, // Important for port 587
  auth: {
    user: process.env.SMTP_USER || 'alerts@automationedgerpa.com',
    pass: process.env.SMTP_PASS || 'zzarrvgjnvowydkf'
  },
  connectionTimeout: 15000,
  greetingTimeout: 15000,
  socketTimeout: 15000,
  tls: {
    rejectUnauthorized: false
  },
  debug: true,
  logger: true
};

// This recipients list is for Initiated POC notifications
// Recipients from environment variable (comma-separated)
const POC_RECIPIENTS = process.env.POC_NOTIFICATION_RECIPIENTS ||
  'devopsbyzielotech@gmail.com,nitin.bhujbal@automationedge.com';

// This recipients list is for Usecase code creation notifications
// Recipients from environment variable (comma-separated)
const USECASE_RECIPIENTS = process.env.USECASE_NOTIFICATION_RECIPIENTS ||
  'nitin.bhujbal@automationedge.com,suhas.kajawe@automationedge.com';


// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// After your authenticateToken middleware definition, use it for employee report routes
app.use('/poc/employee-report', authenticateToken, employeeReportRoutes);


// Add this to your server.js
app.get("/poc/api/auth/validate", authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: req.user
  });
});




// --- KNOWLEDGE BASE FILE UPLOAD CONFIGURATION ---

// Git repo working directory (clone of your repo)
// ===== KNOWLEDGE BASE CONFIG (EXTERNAL REPO) =====


const execPromise = (cmd, options = {}) =>
  new Promise((resolve, reject) => {
    exec(cmd, options, (err, stdout, stderr) => {
      if (err) {
        return reject((stderr || err.message || '').toString());
      }
      resolve((stdout || '').toString());
    });
  });


const KB_ROOT = path.resolve(
  'C:/Users/nitin.bhujbal/Documents/FullStack-POC/KnowledgeBase'
);

const KNOWLEDGE_BASE_ROOT = path.join(KB_ROOT, 'uploads');
const GIT_REPO_PATH = KB_ROOT;
const ENABLE_GIT_SYNC = true; // 🔴 OFF for laptop


if (!fs.existsSync(KNOWLEDGE_BASE_ROOT)) {
  fs.mkdirSync(KNOWLEDGE_BASE_ROOT, { recursive: true });
}

if (!GIT_REPO_PATH.includes('KnowledgeBase')) {
  throw new Error('❌ Git repo path is NOT KnowledgeBase. Aborting.');
}



// Simple git command runner
const runGitCommand = (command) => {
  return new Promise((resolve, reject) => {
    exec(command, { cwd: GIT_REPO_PATH }, (error, stdout, stderr) => {
      if (error) {
        console.error('❌ Git error:', stderr);
        return reject(stderr);
      }
      resolve(stdout);
    });
  });
};

let gitLock = false;

const acquireGitLock = async () => {
  while (gitLock) {
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  gitLock = true;
};

const releaseGitLock = () => {
  gitLock = false;
};

async function ensureLatestKnowledgeBase(usecaseId) {
  const sparsePath = `uploads/${usecaseId}`;

  await acquireGitLock();
  try {
    if (!fs.existsSync(path.join(KB_REPO_PATH, '.git'))) {
      await execPromise(
        `git clone --no-checkout ${KB_REPO_URL} "${KB_REPO_PATH}"`
      );
    }

    // Pull latest first
    await execPromise(`git pull origin main`, {
      cwd: KB_REPO_PATH
    });

    // Enable sparse checkout for this usecase
    await execPromise(`git sparse-checkout init --cone`, {
      cwd: KB_REPO_PATH
    });

    await execPromise(
      `git sparse-checkout set "${sparsePath}"`,
      { cwd: KB_REPO_PATH }
    );

    console.log(`✅ Sparse synced: ${sparsePath}`);
  } finally {
    releaseGitLock();
  }
}

// Remove acquireGitLock from inside these helpers
async function disableSparseCheckout() {
  try {
    const sparseCheckoutFile = path.join(KB_REPO_PATH, '.git', 'info', 'sparse-checkout');
    if (fs.existsSync(sparseCheckoutFile)) {
      await execPromise(`git sparse-checkout disable`, { cwd: KB_REPO_PATH });
      console.log('🔓 Sparse checkout disabled');
    }
  } catch (err) {
    console.log('Note: Could not disable sparse-checkout', err.message);
  }
}




// ===== Knowledge Base Repo Paths =====
const KB_REPO_PATH = path.resolve(
  'C:/Users/nitin.bhujbal/Documents/FullStack-POC/KnowledgeBase'
);

// ADD THIS LINE - define your Git repository URL
const KB_REPO_URL = 'http://10.41.5.6/pocteamgroup/poc_knowledge_base_nitin.git'; // e.g., 'https://github.com/yourusername/KnowledgeBase.git'

const KB_UPLOADS_PATH = path.join(KB_REPO_PATH, 'uploads');



// Configure multer for file upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const usecaseId = req.body.usecaseId;

    if (!usecaseId) {
      return cb(new Error('usecaseId is required'), null);
    }

    const folderPath = path.join(KB_UPLOADS_PATH, usecaseId);
    console.log('📁 Multer destination:', folderPath);

    if (!fs.existsSync(folderPath)) {
      fs.mkdirSync(folderPath, { recursive: true });
    }

    cb(null, folderPath);
  },

  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const baseName = path.basename(file.originalname, ext);

    const safeName = baseName.replace(/[^\w.-]/g, '_');
    const uniqueName = `${safeName}_${Date.now()}${ext}`;

    console.log('📄 Multer filename:', uniqueName);
    cb(null, uniqueName);
  }
});


const upload = multer({
  storage: storage,
  limits: {
    fileSize: 1000 * 1024 * 1024 // 100MB limit per file
  },
  fileFilter: (req, file, cb) => {
    // Accept all file types
    cb(null, true);
  }
});

// --- KNOWLEDGE BASE ROUTES ---


// Upload multiple files endpoint
app.post('/poc/uploadKnowledgeMaterials',  authenticateToken,  upload.array('files', 10),  async (req, res) => {

    const { usecaseId, uploadedBy, uploadedById } = req.body;
    const loggedInUser = req.user?.emp_name || req.user?.name || 'Unknown User';
    const db = req.app.locals.db;

    if (!usecaseId || !req.files?.length) {
      return res.status(400).json({
        success: false,
        message: 'Missing usecaseId or files'
      });
    }

    try {
      const results = [];

      // ===============================
      // ✅ STEP 1: Save to DB
      // ===============================
      for (const file of req.files) {
        const dbRes = await db.query(
          `INSERT INTO knowledge_materials
           (usecase_id, file_name, file_path, file_size, file_type, uploaded_by, uploaded_by_id, status)
           VALUES ($1,$2,$3,$4,$5,$6,$7,'active') RETURNING id`,
          [
            usecaseId,
            file.filename,
            file.path,
            file.size,
            file.mimetype,
            uploadedBy || loggedInUser,
            uploadedById || req.user?.emp_id
          ]
        );

        results.push({
          success: true,
          fileId: dbRes.rows[0].id,
          fileName: file.originalname
        });
      }

      // ===============================
      // ✅ STEP 2: Send to Git Machine
      // ===============================
      let gitSuccess = false;

      try {
        const formData = new FormData();
        formData.append('usecaseId', usecaseId);
        formData.append('uploadedBy', uploadedBy || loggedInUser);

        req.files.forEach(file => {
          formData.append('files', fs.createReadStream(file.path));
        });

        await axios.post(
          'https://financebot.automationedge.com/poc/gitUploadKnowledgeMaterials',
          formData,
          {
            headers: formData.getHeaders()
          }
        );

        console.log('✅ Git Machine Sync Successful');
        gitSuccess = true;

      } catch (gitErr) {
        console.error('⚠️ Git Machine Sync Failed:', gitErr.message);
      }

      // ===============================
      // ✅ STEP 3: DELETE LOCAL FILES
      // ===============================
      try {
        req.files.forEach(file => {
          if (fs.existsSync(file.path)) {
            fs.unlinkSync(file.path);
            console.log(`🗑️ Deleted file: ${file.path}`);
          }
        });

        // Delete entire usecase folder
        const usecaseFolder = path.dirname(req.files[0].path);

        if (fs.existsSync(usecaseFolder)) {
          fs.rmSync(usecaseFolder, { recursive: true, force: true });
          console.log(`🗑️ Deleted usecase folder: ${usecaseFolder}`);
        }

      } catch (deleteErr) {
        console.error('❌ Cleanup Error:', deleteErr.message);
      }

      return res.json({
        success: true,
        message: gitSuccess
          ? 'Files saved, synced to Git, and cleaned locally.'
          : 'Files saved to DB. Git sync failed but local files cleaned.',
        results
      });

    } catch (err) {

      console.error('❌ Upload Error:', err);

      // ===============================
      // 🔥 Cleanup On Complete Failure
      // ===============================
      if (req.files) {
        try {
          req.files.forEach(file => {
            if (fs.existsSync(file.path)) {
              fs.unlinkSync(file.path);
            }
          });

          const usecaseFolder = path.dirname(req.files[0].path);
          if (fs.existsSync(usecaseFolder)) {
            fs.rmSync(usecaseFolder, { recursive: true, force: true });
          }

        } catch (cleanupErr) {
          console.error('❌ Failure Cleanup Error:', cleanupErr.message);
        }
      }

      return res.status(500).json({
        success: false,
        message: 'Upload failed',
        error: err.message
      });
    }
  }
);



// Download file endpoint
app.get('/poc/downloadKnowledgeMaterial/:fileId',  authenticateToken,  async (req, res) => {

    try {
      const fileId = Number(req.params.fileId);
      const db = req.app.locals.db;

      const result = await db.query(
        `SELECT usecase_id, file_name 
         FROM knowledge_materials 
         WHERE id = $1`,
        [fileId]
      );

      if (!result.rows.length) {
        return res.status(404).json({
          success: false,
          message: 'File record not found in DB'
        });
      }

      const { usecase_id, file_name } = result.rows[0];

      console.log(`⬇️ Requesting file from Git machine: ${file_name}`);

      // Call Git Machine API
      const response = await axios.get(
        `https://financebot.automationedge.com/poc/gitDownloadKnowledgeMaterial`,
        {
          params: {
            usecaseId: usecase_id,
            fileName: file_name
          },
          responseType: 'stream'
        }
      );

      // Set headers
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${file_name}"`
      );

      // Pipe stream directly to client
      response.data.pipe(res);

    } catch (err) {
      console.error('❌ Download Error (DB Machine):', err.message);
      return res.status(500).json({
        success: false,
        message: 'Download failed',
        error: err.message
      });
    }
  }
);



// Get files for usecase endpoint
app.get('/poc/knowledgeBaseFiles/:usecaseId', authenticateToken, async (req, res) => {
  try {
    const { usecaseId } = req.params;
    const db = req.app.locals.db;

    const result = await db.query(
      `SELECT 
         id,                      -- ✅ REQUIRED
         usecase_id,
         file_name,
         file_size,
         uploaded_by,
         uploaded_by_id,
         upload_date
       FROM knowledge_materials
       WHERE usecase_id = $1
         AND status = 'active'
       ORDER BY upload_date DESC`,
      [usecaseId]
    );

    const files = result.rows.map(file => ({
      id: file.id,                           // ✅ EXPLICIT
      usecase_id: file.usecase_id,
      file_name: file.file_name,
      file_size: file.file_size,
      file_size_mb: (file.file_size / (1024 * 1024)).toFixed(2),
      uploaded_by: file.uploaded_by,
      uploaded_by_id: file.uploaded_by_id,
      upload_date: file.upload_date
    }));

    res.json({ success: true, files });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});


// Get Usecase details for Knowledge Base
// app.get('/poc/knowledgeBaseUsecases', authenticateToken, async (req, res) => {
//   try {
//     const db = req.app.locals.db;
//     if (!db) {
//       return res.status(500).json({
//         success: false,
//         message: 'Database connection error'
//       });
//     }

//     const { search } = req.query;

//     // 🔐 User info from token
//     const userId = req.user.emp_id || req.user.id;
//     const userName = req.user.emp_name || req.user.name;

//     // 🔐 Fetch permissions
//     const permissionQuery = `
//       SELECT 
//         status_access,
//         all_status_access,
//         admin_access
//       FROM public.user_permissions
//       WHERE emp_id = $1
//     `;
//     const permissionResult = await db.query(permissionQuery, [userId]);

//     let hasStatusAccess = false;
//     let hasAllStatusAccess = false;
//     let hasAdminAccess = false;

//     if (permissionResult.rows.length > 0) {
//       hasStatusAccess = permissionResult.rows[0].status_access;
//       hasAllStatusAccess = permissionResult.rows[0].all_status_access;
//       hasAdminAccess = permissionResult.rows[0].admin_access;
//     }

//     // 🧠 Base query
//     let query = `
//       SELECT 
//         pd.poc_prj_id AS "Usecase Id",
//         pd.client_name AS "Client Name",
//         COALESCE(NULLIF(TRIM(pe.partner_name), ''), '-') AS "Partner Name",
//         pd.poc_prj_name AS "Usecase Name",
//         pd.status,
//         pd.start_date,
//         pd.excepted_end_date,
//         pd.region,
//         pd.poc_type,
//         pd.department_name,
//         pd.description,
//         pd.tag,
//         pe.actual_start_date
//       FROM poc_prj_details pd
//       LEFT JOIN poc_prj_efforts pe 
//         ON pd.poc_prj_id = pe.poc_prj_id
//       WHERE 1=1
//     `;

//     const queryParams = [];
//     let paramCounter = 1;

//     // 🔎 Search filter
//     if (search) {
//       query += `
//         AND (
//           pd.poc_prj_id ILIKE $${paramCounter}
//           OR pd.client_name ILIKE $${paramCounter}
//           OR pd.poc_prj_name ILIKE $${paramCounter}
//           OR pe.partner_name ILIKE $${paramCounter}
//         )
//       `;
//       queryParams.push(`%${search}%`);
//       paramCounter++;
//     }

//     // 🔐 Permission-based filtering
//     if (!(hasAllStatusAccess || hasAdminAccess)) {

//       if (!hasStatusAccess) {
//         // 🚫 No access at all
//         return res.json({
//           success: true,
//           data: [],
//           total: 0
//         });
//       }

//       // ✅ Only assigned + In Progress
//       query += `
//         AND pd.status = 'In Progress'
//         AND (
//           pd.assigned_to ILIKE $${paramCounter}
//           OR pd.assigned_to ILIKE $${paramCounter + 1}
//           OR pd.assigned_to ILIKE $${paramCounter + 2}
//           OR pd.assigned_to ILIKE $${paramCounter + 3}
//           OR pd.assigned_to = $${paramCounter + 4}
//         )
//       `;

//       queryParams.push(
//         `%${userName}%`,
//         `${userName},%`,
//         `%, ${userName},%`,
//         `%, ${userName}`,
//         userName
//       );

//       paramCounter += 5;
//     }

//     // 🧮 GROUP BY
//     query += `
//       GROUP BY 
//         pd.poc_prj_id,
//         pd.client_name,
//         pd.poc_prj_name,
//         pd.status,
//         pd.start_date,
//         pd.excepted_end_date,
//         pd.region,
//         pd.poc_type,
//         pd.department_name,
//         pd.description,
//         pd.tag,
//         pe.partner_name,
//         pe.actual_start_date
//     `;

//     // ⬇️ ORDER BY
//     query += `
//       ORDER BY
//         CASE WHEN pe.actual_start_date IS NULL THEN 1 ELSE 0 END,
//         pe.actual_start_date DESC,
//         pd.poc_prj_id ASC
//     `;

//     // ▶️ Execute query
//     const { rows: usecases } = await db.query(query, queryParams);

//     // 📎 Check file availability
//     for (const usecase of usecases) {
//       const fileResult = await db.query(
//         `
//           SELECT COUNT(*) AS file_count
//           FROM knowledge_materials
//           WHERE usecase_id = $1
//             AND status = 'active'
//         `,
//         [usecase['Usecase Id']]
//       );

//       usecase.hasFiles = parseInt(fileResult.rows[0].file_count, 10) > 0;
//     }

//     // ✅ Response
//     res.json({
//       success: true,
//       data: usecases,
//       total: usecases.length
//     });

//   } catch (error) {
//     console.error('❌ Error in /poc/knowledgeBaseUsecases:', error);
//     res.status(500).json({
//       success: false,
//       message: 'Error fetching usecases',
//       error: error.message
//     });
//   }
// });

// Get Usecase details for Knowledge Base
app.get('/poc/knowledgeBaseUsecases', authenticateToken, async (req, res) => {
  try {
    const db = req.app.locals.db;
    if (!db) {
      return res.status(500).json({
        success: false,
        message: 'Database connection error'
      });
    }

    const { search } = req.query;

    // 🔐 User info from token
    const userId = req.user.emp_id || req.user.id;
    const userName = req.user.emp_name || req.user.name;

    // 🔐 Fetch permissions
    const permissionQuery = `
      SELECT 
        status_access,
        admin_access
      FROM public.user_permissions
      WHERE emp_id = $1
    `;
    const permissionResult = await db.query(permissionQuery, [userId]);

    let hasStatusAccess = false;
    let hasAdminAccess = false;

    if (permissionResult.rows.length > 0) {
      hasStatusAccess = permissionResult.rows[0].status_access;
      hasAdminAccess = permissionResult.rows[0].admin_access;
    }

    // 🚫 No access at all — return empty
    if (!hasStatusAccess && !hasAdminAccess) {
      return res.json({
        success: true,
        data: [],
        total: 0
      });
    }

    // 🧠 Base query — no permission filtering needed, all users with access see all usecases
    let query = `
      SELECT 
        pd.poc_prj_id AS "Usecase Id",
        pd.client_name AS "Client Name",
        COALESCE(NULLIF(TRIM(pe.partner_name), ''), '-') AS "Partner Name",
        pd.poc_prj_name AS "Usecase Name",
        pd.status,
        pd.start_date,
        pd.excepted_end_date,
        pd.region,
        pd.poc_type,
        pd.department_name,
        pd.description,
        pd.tag,
        pe.actual_start_date
      FROM poc_prj_details pd
      LEFT JOIN poc_prj_efforts pe 
        ON pd.poc_prj_id = pe.poc_prj_id
      WHERE 1=1
    `;

    const queryParams = [];
    let paramCounter = 1;

    // 🔎 Search filter
    if (search) {
      query += `
        AND (
          pd.poc_prj_id ILIKE $${paramCounter}
          OR pd.client_name ILIKE $${paramCounter}
          OR pd.poc_prj_name ILIKE $${paramCounter}
          OR pe.partner_name ILIKE $${paramCounter}
        )
      `;
      queryParams.push(`%${search}%`);
      paramCounter++;
    }

    // 🧮 GROUP BY
    query += `
      GROUP BY 
        pd.poc_prj_id,
        pd.client_name,
        pd.poc_prj_name,
        pd.status,
        pd.start_date,
        pd.excepted_end_date,
        pd.region,
        pd.poc_type,
        pd.department_name,
        pd.description,
        pd.tag,
        pe.partner_name,
        pe.actual_start_date
    `;

    // ⬇️ ORDER BY
    query += `
      ORDER BY
        CASE WHEN pe.actual_start_date IS NULL THEN 1 ELSE 0 END,
        pe.actual_start_date DESC,
        pd.poc_prj_id ASC
    `;

    // ▶️ Execute query
    const { rows: usecases } = await db.query(query, queryParams);

    // 📎 Check file availability
    for (const usecase of usecases) {
      const fileResult = await db.query(
        `
          SELECT COUNT(*) AS file_count
          FROM knowledge_materials
          WHERE usecase_id = $1
            AND status = 'active'
        `,
        [usecase['Usecase Id']]
      );

      usecase.hasFiles = parseInt(fileResult.rows[0].file_count, 10) > 0;
    }

    // ✅ Response
    res.json({
      success: true,
      data: usecases,
      total: usecases.length
    });

  } catch (error) {
    console.error('❌ Error in /poc/knowledgeBaseUsecases:', error);
    res.status(500).json({
      success: false,
      message: 'Error fetching usecases',
      error: error.message
    });
  }
});








app.get('/poc/getSummaryReport', authenticateToken, async (req, res) => {
  console.log('Received request for summary report with query:', req.query);
  try {
    const { date } = req.query;
    let targetDate = date;

    // If no date provided, calculate last working day
    if (!targetDate) {
      const today = new Date();
      let lastWorkingDay = new Date(today);

      // Go back until we find a weekday (Monday=1 to Friday=5)
      do {
        lastWorkingDay.setDate(lastWorkingDay.getDate() - 1);
      } while (lastWorkingDay.getDay() === 0 || lastWorkingDay.getDay() === 6);

      targetDate = lastWorkingDay.toISOString().split('T')[0];
    }

    console.log('Fetching summary report for date:', targetDate);

    // First, debug the date format in leave table
    const debugQuery = `
      SELECT emp_id, from_date, to_date, leave_status
      FROM employee_leave_details 
      WHERE emp_id IN ('AE0605', 'AE0901')
      ORDER BY emp_id;
    `;

    try {
      const debugResult = await pool.query(debugQuery);
      console.log('Debug - Leave records for AE0605 and AE0901:');
      debugResult.rows.forEach(row => {
        console.log(`${row.emp_id}: ${row.from_date} to ${row.to_date} (${row.leave_status})`);
      });
    } catch (debugErr) {
      console.log('Debug query failed:', debugErr.message);
    }

    // Get all active employees
    const employeesQuery = `
      SELECT 
        emp_id,
        emp_name,
        email_id
      FROM emp_details 
      WHERE status='Active' and department_name = 'PCS ROW'
      AND emp_id NOT IN ('AE0204','AE0751','AE0468','AE0802','VD0035','FB0154','AE0248','AE0510','AE0201','AE0007','AE0838')
      ORDER BY emp_id;
    `;

    const employeesResult = await pool.query(employeesQuery);
    const employees = employeesResult.rows;

    if (employees.length === 0) {
      return res.json([]);
    }

    // Get status data for the target date
    const statusQuery = `
      SELECT
        emp_id,
        ROUND(SUM(
          EXTRACT(HOUR FROM hrs::time) +
          EXTRACT(MINUTE FROM hrs::time) / 60.0 +
          EXTRACT(SECOND FROM hrs::time) / 3600.0
        ), 2) AS total_hrs
      FROM daily_poc_prj_status
      WHERE poc_date = $1::date
      GROUP BY emp_id;
    `;

    const statusResult = await pool.query(statusQuery, [targetDate]);
    const statusMap = new Map();
    statusResult.rows.forEach(row => {
      statusMap.set(row.emp_id, parseFloat(row.total_hrs));
    });

    // CORRECTED: Get employees on leave using proper date comparison
    // We need to know the exact date format in the database
    // Let's assume dates are stored as DD-MM-YYYY (as per your original query)

    // Parse targetDate (YYYY-MM-DD) to DD-MM-YYYY
    const [year, month, day] = targetDate.split('-');
    const targetDateDDMMYYYY = `${day}-${month}-${year}`;

    console.log('Checking leaves for date:', {
      targetDate: targetDate,
      targetDateDDMMYYYY: targetDateDDMMYYYY
    });

    // Use a safer approach: convert dates properly in SQL
    const leaveQuery = `
      SELECT DISTINCT emp_id
      FROM employee_leave_details
      WHERE 
        -- First try to parse as DD-MM-YYYY (most likely format based on your query)
        (
          from_date ~ '^\\d{2}-\\d{2}-\\d{4}$' 
          AND to_date ~ '^\\d{2}-\\d{2}-\\d{4}$'
          AND TO_DATE($1, 'DD-MM-YYYY') BETWEEN 
            TO_DATE(from_date, 'DD-MM-YYYY') 
            AND TO_DATE(to_date, 'DD-MM-YYYY')
        )
        OR
        -- Fallback: try YYYY-MM-DD format
        (
          from_date ~ '^\\d{4}-\\d{2}-\\d{2}$' 
          AND to_date ~ '^\\d{4}-\\d{2}-\\d{2}$'
          AND $2::date BETWEEN 
            from_date::date 
            AND to_date::date
        )
      AND (leave_status IS NULL OR LOWER(leave_status) IN ('approved', 'pending'));
    `;

    let leaveEmployees = new Set();

    try {
      const leaveResult = await pool.query(leaveQuery, [targetDateDDMMYYYY, targetDate]);
      leaveResult.rows.forEach(row => {
        leaveEmployees.add(row.emp_id);
      });
      console.log(`Found ${leaveEmployees.size} employees on leave`);

      // Debug specific employees
      if (leaveEmployees.has('AE0605') || leaveEmployees.has('AE0901')) {
        console.log('DEBUG - Checking why these employees show as on leave:');
        ['AE0605', 'AE0901'].forEach(empId => {
          if (leaveEmployees.has(empId)) {
            console.log(`${empId} is marked as on leave`);
          }
        });
      }
    } catch (leaveErr) {
      console.log('Leave query failed, skipping leave check:', leaveErr.message);
    }

    // Format the response
    const formattedData = employees.map(emp => {
      const totalHrs = statusMap.get(emp.emp_id) || 0;
      const isOnLeave = leaveEmployees.has(emp.emp_id);

      // Correct logic: ON LEAVE only if no hours AND actually on leave
      let statusUpdate;
      if (totalHrs > 0) {
        statusUpdate = 'YES'; // Submitted hours
      } else if (isOnLeave) {
        statusUpdate = 'ON LEAVE'; // No hours and on leave
      } else {
        statusUpdate = 'NO'; // No hours and not on leave
      }

      return {
        emp_id: emp.emp_id,
        emp_name: emp.emp_name,
        email_id: emp.email_id,
        status_update: statusUpdate,
        total_hrs: parseFloat(totalHrs.toFixed(2))
      };
    });

    // Add total row
    if (formattedData.length > 0) {
      const employeesOnly = formattedData.filter(emp => emp.emp_id !== 'Total');
      const totalHours = employeesOnly.reduce((sum, emp) => sum + emp.total_hrs, 0);
      const totalYes = employeesOnly.filter(emp => emp.status_update === 'YES').length;
      const totalOnLeave = employeesOnly.filter(emp => emp.status_update === 'ON LEAVE').length;
      const totalEmployees = employeesOnly.length;

      let totalStatus = 'PARTIAL';
      if (totalOnLeave === totalEmployees) {
        totalStatus = 'ON LEAVE';
      } else if (totalYes === totalEmployees) {
        totalStatus = 'YES';
      } else if (totalYes === 0 && totalOnLeave === 0) {
        totalStatus = 'NO';
      }

      formattedData.push({
        emp_id: 'Total',
        emp_name: 'Team Total',
        email_id: '',
        status_update: totalStatus,
        total_hrs: parseFloat(totalHours.toFixed(2))
      });
    }

    // Sort: YES first, then NO, then ON LEAVE
    const sortedData = formattedData
      .filter(emp => emp.emp_id !== 'Total')
      .sort((a, b) => {
        const order = { 'YES': 1, 'NO': 2, 'ON LEAVE': 3 };
        return (order[a.status_update] || 4) - (order[b.status_update] || 4) ||
          a.emp_id.localeCompare(b.emp_id);
      });

    // Add total row back
    const totalRow = formattedData.find(emp => emp.emp_id === 'Total');
    if (totalRow) {
      sortedData.push(totalRow);
    }

    // Debug output
    console.log('\nFinal Report Summary:');
    console.log(`Total employees: ${sortedData.filter(emp => emp.emp_id !== 'Total').length}`);
    console.log(`YES: ${sortedData.filter(emp => emp.status_update === 'YES' && emp.emp_id !== 'Total').length}`);
    console.log(`NO: ${sortedData.filter(emp => emp.status_update === 'NO' && emp.emp_id !== 'Total').length}`);
    console.log(`ON LEAVE: ${sortedData.filter(emp => emp.status_update === 'ON LEAVE' && emp.emp_id !== 'Total').length}`);

    // Show first few results
    console.log('\nFirst 10 employees:');
    sortedData.slice(0, 10).forEach(emp => {
      if (emp.emp_id !== 'Total') {
        console.log(`${emp.emp_id}: ${emp.status_update} (${emp.total_hrs} hrs)`);
      }
    });

    res.json(sortedData);

  } catch (error) {
    console.error('Error in getSummaryReport:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
});
// Get all POCs - FIXED with type casting
app.get("/poc/getAllPocs", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    console.log('Fetching POC records for user:', req.user);

    // Get salesperson name from query parameter
    const requestedSalesPerson = req.query.salesperson_name;
    const userEmail = req.user.salesperson_email;
    const userName = req.user.salesperson_name;

    let query;
    let queryParams = [];

    if (requestedSalesPerson) {
      // If salesperson_name is provided, filter by that salesperson
      console.log('Filtering POC records for salesperson:', requestedSalesPerson);
      query = `
        SELECT 
          id, 
          brief, 
          company_name, 
          designation, 
          end_customer_type, 
          sp_name as sales_person,
          spoc, 
          spoc_email, 
          usecase, 
          partner_company_name, 
          partner_spoc, 
          partner_spoc_email, 
          partner_designation, 
          partner_mobile_number, 
          mobile_number, 
          process_type, 
          region,
          generated_usecase,
          remark,
          status
        FROM public.poc_details 
        WHERE sp_name = $1
        ORDER BY id DESC
      `;
      queryParams = [requestedSalesPerson];
    } else {
      // If no salesperson_name provided, fetch all records (for admin)
      console.log('Fetching all POC records (admin access)');
      query = `
        SELECT 
          id, 
          brief, 
          company_name, 
          designation, 
          end_customer_type, 
          sp_name as sales_person,
          spoc, 
          spoc_email, 
          usecase, 
          partner_company_name, 
          partner_spoc, 
          partner_spoc_email, 
          partner_designation, 
          partner_mobile_number, 
          mobile_number, 
          process_type, 
          region,
          generated_usecase,
          remark,
          status
        FROM public.poc_details 
        ORDER BY id DESC
      `;
    }

    const result = await client.query(query, queryParams);
    console.log('POC records found:', result.rows.length);

    // Transform the data to match frontend expectations
    const pocData = result.rows.map(row => ({
      id: row.id,
      brief: row.brief,
      companyName: row.company_name,
      designation: row.designation,
      endCustomerType: row.end_customer_type,
      salesPerson: row.sales_person,
      spoc: row.spoc,
      spocEmail: row.spoc_email,
      usecase: row.usecase,
      partnerCompanyName: row.partner_company_name,
      partnerSpoc: row.partner_spoc,
      partnerSpocEmail: row.partner_spoc_email,
      partnerDesignation: row.partner_designation,
      partnerMobileNumber: row.partner_mobile_number,
      mobileNumber: row.mobile_number,
      processType: row.process_type,
      region: row.region,
      generatedUsecase: row.generated_usecase,
      remark: row.remark,
      status: row.status
    }));

    res.json(pocData);
  } catch (err) {
    console.error("Error fetching POC records:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  } finally {
    client.release();
  }
});

app.put("/poc/updateInitiatedStatus/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { status } = req.body;

    // Validate status
    const validStatuses = ['Draft', 'Initiated', 'Pending', 'In Progress', 'Completed'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        message: "Invalid status value"
      });
    }

    const query = `
      UPDATE public.poc_details 
      SET status = $1
      WHERE id = $2
      RETURNING id, status
    `;

    const result = await client.query(query, [status, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: "POC record not found"
      });
    }

    res.json({
      message: "Status updated successfully",
      poc: result.rows[0]
    });
  } catch (err) {
    console.error("Error updating status:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  } finally {
    client.release();
  }
});

// app.put("/poc/updateGeneratedUsecase/:id", authenticateToken, async (req, res) => {
//   const client = await pool.connect();
//   try {
//     const { id } = req.params;
//     const { generatedUsecase } = req.body;

//     const query = `
//       UPDATE public.poc_details 
//       SET generated_usecase = $1 
//       WHERE id = $2 
//       RETURNING *;
//     `;

//     const result = await client.query(query, [generatedUsecase, id]);

//     if (result.rows.length === 0) {
//       return res.status(404).json({ message: "POC record not found" });
//     }

//     res.json({
//       message: "Generated usecase updated successfully",
//       poc: result.rows[0]
//     });
//   } catch (err) {
//     console.error("Error updating generated usecase:", err);
//     res.status(500).json({
//       message: "Internal server error",
//       error: err.message
//     });
//   } finally {
//     client.release();
//   }
// });

// API to delete POC record



app.delete("/poc/deleteInitiatedPoc/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    console.log('Deleting POC record with ID:', id);

    await client.query("BEGIN");

    // Use user_permissions table instead of users
    const checkQuery = `
      SELECT pd.*, up.sales_admin 
      FROM public.poc_details pd 
      LEFT JOIN public.user_permissions up ON up.emp_id = $2
      WHERE pd.id = $1
    `;
    const checkResult = await client.query(checkQuery, [id, req.user.emp_id]);

    if (checkResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "POC record not found" });
    }

    const currentPoc = checkResult.rows[0];
    const isSalesAdmin = checkResult.rows[0].sales_admin === true;

    console.log(`User is sales_admin: ${isSalesAdmin}, Current status: ${currentPoc.status}`);

    // Status validation: Only allow deletion if status is "Draft" OR user is sales_admin
    if (!isSalesAdmin && currentPoc.status !== 'Draft') {
      await client.query("ROLLBACK");
      return res.status(403).json({
        message: `Cannot delete record with "${currentPoc.status}" status. Only "Draft" records can be deleted.`,
        currentStatus: currentPoc.status,
        redirect: true
      });
    }

    const deleteQuery = `
      DELETE FROM public.poc_details 
      WHERE id = $1 
      RETURNING *;
    `;

    const result = await client.query(deleteQuery, [id]);

    await client.query("COMMIT");

    res.json({
      message: "POC record deleted successfully",
      deletedPoc: result.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error deleting POC record:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  } finally {
    client.release();
  }
});

app.put("/poc/updateInitiatedPoc", authenticateToken, async (req, res) => {
  console.log("✅ PUT /poc/updateInitiatedPoc endpoint hit");
  console.log("Request body:", req.body);
  const {
    id,
    salesPerson,
    region,
    endCustomerType,
    processType,
    companyName,
    spoc,
    spocEmail,
    designation,
    mobileNumber,
    usecase,
    brief,
    partnerCompanyName,
    partnerSpoc,
    partnerSpocEmail,
    partnerDesignation,
    partnerMobileNumber,
    remark
  } = req.body;

  // Validate required fields
  if (!id) {
    return res.status(400).json({ message: "POC ID is required for update" });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Use user_permissions table to check sales_admin permission
    const checkQuery = `
      SELECT pd.*, up.sales_admin 
      FROM public.poc_details pd 
      LEFT JOIN public.user_permissions up ON up.emp_id = $2
      WHERE pd.id = $1
    `;
    const checkResult = await client.query(checkQuery, [id, req.user.emp_id]);

    if (checkResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "POC record not found" });
    }

    const currentPoc = checkResult.rows[0];
    const isSalesAdmin = checkResult.rows[0].sales_admin === true;

    console.log(`User is sales_admin: ${isSalesAdmin}, Current status: ${currentPoc.status}`);

    // Status validation: Only allow updates if status is "Draft" OR user is sales_admin
    if (!isSalesAdmin && currentPoc.status !== 'Draft') {
      await client.query("ROLLBACK");
      return res.status(403).json({
        message: `Cannot update record. Status has been changed to "${currentPoc.status}". Only "Draft" records can be updated.`,
        currentStatus: currentPoc.status,
        redirect: true
      });
    }

    const query = `
      UPDATE public.poc_details 
      SET 
        sp_name = $1,
        region = $2,
        end_customer_type = $3,
        process_type = $4,
        company_name = $5,
        spoc = $6,
        spoc_email = $7,
        designation = $8,
        mobile_number = $9,
        usecase = $10,
        brief = $11,
        partner_company_name = $12,
        partner_spoc = $13,
        partner_spoc_email = $14,
        partner_designation = $15,
        partner_mobile_number = $16,
        remark = $17
      WHERE id = $18
      RETURNING *
    `;

    const values = [
      salesPerson,
      region,
      endCustomerType,
      processType,
      companyName,
      spoc,
      spocEmail,
      designation,
      mobileNumber,
      usecase,
      brief,
      partnerCompanyName,
      partnerSpoc,
      partnerSpocEmail,
      partnerDesignation,
      partnerMobileNumber,
      remark,
      id
    ];

    const result = await client.query(query, values);
    const updatedPoc = result.rows[0];

    await client.query("COMMIT");

    res.status(200).json({
      message: "POC updated successfully",
      success: true,
      id: updatedPoc.id,
      ...updatedPoc
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error updating POC:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  } finally {
    client.release();
  }
});

// GET endpoint to verify current status of a POC
app.get("/poc/verifyStatus/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const query = `
      SELECT id, status 
      FROM public.poc_details 
      WHERE id = $1
    `;

    const result = await pool.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "POC record not found" });
    }

    res.json({
      id: result.rows[0].id,
      status: result.rows[0].status
    });

  } catch (err) {
    console.error("Error verifying status:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  }
});




app.get("/poc/getLeads", authenticateToken, async (req, res) => {
  try {
    console.log('Fetching leads...');
    const result = await pool.query(`
      SELECT lead_name, department_name, employee_name 
      FROM public.lead_details 
      where lead_status = 'Active' and department_name = 'PCS ROW'
      ORDER BY lead_name
    `);
    console.log('Leads found:', result.rows.length);
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching leads:", err);
    res.status(500).json({ message: "Internal server error", error: err.message });
  }
});


app.get("/poc/permissions/:emp_id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { emp_id } = req.params;

    const query = `
      SELECT 
        dashboard_access,
        report_access,
        usecase_creation_access,
        status_access,
        sales_access,
        all_status_access,
        leave_access,
        sales_admin ,
        sales_dashboard_access,
        status_status_access,
        all_sales_access,
        admin_access,
        knowledge_base_access
      FROM public.user_permissions
      WHERE emp_id = $1;
    `;

    const result = await client.query(query, [emp_id]);

    if (result.rows.length === 0) {
      return res.json({
        dashboard_access: false,
        report_access: false,
        usecase_creation_access: false,
        status_access: false,
        sales_access: false,
        all_status_access: false,
        leave_access: false,
        sales_admin: false  // Default to false if no record found
      });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching user permissions:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});


app.get("/poc/getTodayStatus", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    // Get today's date in YYYY-MM-DD
    const today = new Date().toISOString().split("T")[0];
    const employeeId = req.user.emp_id;

    // First, check user permissions
    const permissionQuery = `
      SELECT all_status_access 
      FROM public.user_permissions 
      WHERE emp_id = $1;
    `;

    const permissionResult = await client.query(permissionQuery, [employeeId]);
    const hasAllStatusAccess = permissionResult.rows.length > 0 && permissionResult.rows[0].all_status_access === true;

    let query;
    let queryParams;

    if (hasAllStatusAccess) {
      // User has access to all statuses - show everyone's status
      query = `
        SELECT 
          id,
          emp_name AS "employeeName",
          emp_id AS "employeeId",
          poc_prj_id AS "usecaseId",
          poc_date AS "date",
          status AS "description",
          status,
          hrs,
          leads_email AS "leadIds",
          department_name AS "departmentName"
        FROM public.daily_poc_prj_status
        WHERE poc_date = $1
        ORDER BY id DESC;
      `;
      queryParams = [today];
    } else {
      // User can only see their own status
      query = `
        SELECT 
          id,
          emp_name AS "employeeName",
          emp_id AS "employeeId",
          poc_prj_id AS "usecaseId",
          poc_date AS "date",
          status AS "description",
          status,
          hrs,
          leads_email AS "leadIds",
          department_name AS "departmentName"
        FROM public.daily_poc_prj_status
        WHERE poc_date = $1 AND emp_id = $2
        ORDER BY id DESC;
      `;
      queryParams = [today, employeeId];
    }

    const result = await client.query(query, queryParams);

    // ✅ Transform hrs ("HH:MM") → workingHours + workingMinutes
    const formattedRows = result.rows.map((row) => {
      let workingHours = 0;
      let workingMinutes = 0;

      if (row.hrs) {
        const [h, m] = row.hrs.split(":");
        workingHours = parseInt(h, 10);
        workingMinutes = parseInt(m, 10);
      }

      // Get usecase name from usecases table or use the ID
      const usecaseName = row.usecaseId; // You might want to join with usecases table to get the actual name

      return {
        id: row.id,
        date: row.date,
        usecaseName: usecaseName, // This should match what frontend expects
        usecaseId: row.usecaseId,
        leadName: row.leadNames || '',
        leadIds: row.leadIds ? row.leadIds.split(",") : [],
        status: row.status,
        workingHours: workingHours,
        workingMinutes: workingMinutes,
        description: row.description || "",
        employeeName: row.employeeName,
        employeeId: row.employeeId,
        departmentName: row.departmentName,
        // Include permission info
        hasAllStatusAccess: hasAllStatusAccess
      };
    });

    res.json(formattedRows);
  } catch (err) {
    console.error("Error fetching today's status:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});

app.get("/poc/getStatusByDate", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { date } = req.query;
    const employeeId = req.user.emp_id;

    // ✅ CHANGE: Fetch BOTH permissions, not just all_status_access
    const permissionQuery = `
      SELECT all_status_access, status_access 
      FROM public.user_permissions 
      WHERE emp_id = $1;
    `;

    const permissionResult = await client.query(permissionQuery, [employeeId]);

    // ✅ CHANGE: Check for both permissions
    let hasAllAccess = false;
    let hasStatusAccess = false;

    if (permissionResult.rows.length > 0) {
      hasAllAccess = permissionResult.rows[0].all_status_access === true;
      hasStatusAccess = permissionResult.rows[0].status_access === true;
    }

    let query;
    let queryParams;

    // ✅ CHANGE: Show all statuses if user has EITHER permission
    if (hasAllAccess || hasStatusAccess) {
      query = `
        SELECT 
          id,
          emp_name AS "employeeName",
          emp_id AS "employeeId",
          poc_prj_id AS "usecaseId",
          poc_date AS "date",
          status AS "description",
          status,
          hrs,
          leads_email AS "leadIds",
          department_name AS "departmentName"
        FROM public.daily_poc_prj_status
        WHERE poc_date = $1
        ORDER BY id DESC;
      `;
      queryParams = [date];
    } else {
      // User has neither permission - show only their own status
      query = `
        SELECT 
          id,
          emp_name AS "employeeName",
          emp_id AS "employeeId",
          poc_prj_id AS "usecaseId",
          poc_date AS "date",
          status AS "description",
          status,
          hrs,
          leads_email AS "leadIds",
          department_name AS "departmentName"
        FROM public.daily_poc_prj_status
        WHERE poc_date = $1 AND emp_id = $2
        ORDER BY id DESC;
      `;
      queryParams = [date, employeeId];
    }

    const result = await client.query(query, queryParams);

    // ✅ Transform hrs ("HH:MM") → workingHours + workingMinutes
    const formattedRows = result.rows.map((row) => {
      let workingHours = 0;
      let workingMinutes = 0;

      if (row.hrs) {
        const [h, m] = row.hrs.split(":");
        workingHours = parseInt(h, 10);
        workingMinutes = parseInt(m, 10);
      }

      // Get usecase name from usecases table or use the ID
      const usecaseName = row.usecaseId; // You might want to join with usecases table to get the actual name

      return {
        id: row.id,
        date: row.date,
        usecaseName: usecaseName,
        usecaseId: row.usecaseId,
        leadName: row.leadNames || '',
        leadIds: row.leadIds ? row.leadIds.split(",") : [],
        status: row.status,
        workingHours: workingHours,
        workingMinutes: workingMinutes,
        description: row.description || "",
        employeeName: row.employeeName,
        employeeId: row.employeeId,
        departmentName: row.departmentName,
        // ✅ CHANGE: Include both permission flags
        hasAllStatusAccess: hasAllAccess,
        hasStatusAccess: hasStatusAccess
      };
    });

    res.json(formattedRows);
  } catch (err) {
    console.error("Error fetching status by date:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});


app.post("/poc/saveDailyStatus", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      date,
      usecaseId,
      leadIds,
      status,
      workingHours,
      workingMinutes,
      description,
      employeeId,
      employeeName,
      usecaseName,
      leadNames
    } = req.body;

    // 🔹 Build "HH:MM" string for hrs
    const formattedHrs = `${String(workingHours || 0).padStart(2, "0")}:${String(workingMinutes || 0).padStart(2, "0")}`;

    console.log("Formatted hrs:", formattedHrs);

    await client.query("BEGIN");

    const insertStatusQuery = `
      INSERT INTO public.daily_poc_prj_status (
        emp_name, emp_id, poc_prj_id, poc_date,
        status, hrs, leads_email, department_name
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,'PCS ROW')
      RETURNING *;
    `;

    const result = await client.query(insertStatusQuery, [
      employeeName,   // emp_name
      employeeId,     // emp_id
      usecaseId,      // poc_prj_id
      date,           // poc_date
      description,         // status
      formattedHrs,   // hrs in HH:MM
      leadIds         // leads_email (comma separated)
    ]);

    await client.query("COMMIT");

    res.status(201).json({
      message: "Daily POC status saved successfully",
      data: result.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error saving daily POC status:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});





// Update daily status
app.put("/poc/empupdateStatus/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const {
      employeeName,
      empName,
      employeeId,
      empId,
      usecaseId,
      pocPrjId,
      date,
      pocDate,
      status,
      workingHours,
      workingMinutes,
      leadIds,
      description,
      leadsEmail,
      departmentName
    } = req.body;

    console.log("Update Daily Status Payload:", req.body);

    // hrs -> HH:MM
    const hrs = `${workingHours || "0"}:${workingMinutes || "00"}`;

    await client.query("BEGIN");

    const updateQuery = `
      UPDATE public.daily_poc_prj_status
      SET poc_prj_id     = COALESCE($1, poc_prj_id),
          poc_date       = COALESCE($2::date, poc_date),
          status         = COALESCE($3, status),
          hrs            = COALESCE($4, hrs),
          leads_email    = COALESCE($5, leads_email),
          department_name= COALESCE($6, department_name)
      WHERE id = $7
      RETURNING *;
    `;

    const result = await client.query(updateQuery, [
      usecaseId ?? pocPrjId ?? null,
      date ?? pocDate ?? null,
      description ?? status ?? null,  // Use description from frontend, fallback to status
      hrs ?? null,
      leadIds ?? leadsEmail ?? null,
      departmentName ?? null,
      id
    ]);

    await client.query("COMMIT");

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Status not found" });
    }

    res.status(200).json({
      message: "Daily POC status updated successfully",
      data: result.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error updating daily POC status:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});


// DELETE /poc/deleteStatus/:id
app.delete("/poc/deleteStatus/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    console.log(id);
    await client.query("BEGIN");

    // Optional: check if the status exists
    const checkResult = await client.query(
      "SELECT * FROM public.daily_poc_prj_status WHERE id = $1",
      [id]
    );

    if (checkResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Status not found" });
    }

    // Delete the status
    const deleteResult = await client.query(
      "DELETE FROM public.daily_poc_prj_status WHERE id = $1 RETURNING *",
      [id]
    );

    await client.query("COMMIT");

    res.status(200).json({
      message: "Daily POC status deleted successfully",
      data: deleteResult.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error deleting daily POC status:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});





app.get("/poc/getUsecases", authenticateToken, async (req, res) => {
  try {
    // Get user info from token
    const userId = req.user.emp_id || req.user.id;
    const userName = req.user.emp_name || req.user.name;

    // Fetch user permissions first
    const permissionQuery = `
      SELECT 
        status_access,
        all_status_access,
        admin_access
      FROM public.user_permissions
      WHERE emp_id = $1;
    `;

    const permissionResult = await pool.query(permissionQuery, [userId]);

    let hasStatusAccess = false;
    let hasAllStatusAccess = false;
    let hasAdminAccess = false;

    if (permissionResult.rows.length > 0) {
      hasStatusAccess = permissionResult.rows[0].status_access;
      hasAllStatusAccess = permissionResult.rows[0].all_status_access;
      hasAdminAccess = permissionResult.rows[0].admin_access;
    }

    let query = '';
    let params = [];

    // Logic based on permissions
    if (hasAllStatusAccess || hasAdminAccess) {
      // Show all in-progress usecases
      query = `
        SELECT 
          poc_prj_id, poc_prj_name, client_name, partner_client_own, sales_person, 
          description, assigned_to, start_date, excepted_end_date, status, remarks, 
          created_by, region, sales_account_manager_name, complexity, last_status, 
          last_status_date, status_change_date, is_billable, poc_type, tag, 
          spoc_email_address, spoc_designation, department_name
        FROM public.poc_prj_details 
        WHERE status = 'In Progress' 
        ORDER BY poc_prj_name
      `;
    } else if (hasStatusAccess) {
      // Show only assigned usecases
      query = `
        SELECT 
          poc_prj_id, poc_prj_name, client_name, partner_client_own, sales_person, 
          description, assigned_to, start_date, excepted_end_date, status, remarks, 
          created_by, region, sales_account_manager_name, complexity, last_status, 
          last_status_date, status_change_date, is_billable, poc_type, tag, 
          spoc_email_address, spoc_designation, department_name
        FROM public.poc_prj_details 
        WHERE status = 'In Progress' 
          AND (
            assigned_to ILIKE $1 
            OR assigned_to ILIKE $2
            OR assigned_to ILIKE $3
            OR assigned_to ILIKE $4
            OR assigned_to = $5
          )
        ORDER BY poc_prj_name
      `;

      // Prepare search patterns for comma-separated assigned_to field
      const userNamePattern = `%${userName}%`;
      const userNameStartPattern = `${userName},%`;
      const userNameMiddlePattern = `%, ${userName},%`;
      const userNameEndPattern = `%, ${userName}`;

      params = [
        userNamePattern,
        userNameStartPattern,
        userNameMiddlePattern,
        userNameEndPattern,
        userName
      ];
    } else {
      // No access - return empty array
      return res.json([]);
    }

    const result = await pool.query(query, params);
    res.json(result.rows);

  } catch (err) {
    console.error("Error fetching usecases:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});






// Get distinct status types
app.get('/poc/getStatusTypes', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT status
      FROM public.poc_prj_details
      WHERE status IS NOT NULL
      ORDER BY status
    `);
    const statusTypes = result.rows.map(row => row.status);
    res.json(statusTypes);
  } catch (error) {
    console.error('Error fetching status types:', error);
    res.status(500).json({ error: 'Failed to fetch status types' });
  }
});




// SELECT DISTINCT regexp_replace(poc_prj_id, '[-_].*$', '') AS type
app.get("/poc/getPocTypes", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT poc_type as type
      FROM public.poc_prj_details
      WHERE poc_prj_id IS NOT NULL
    `);

    const types = result.rows.map(row => row.type).filter(type => type);
    res.json(types);
  } catch (err) {
    console.error("Error fetching POC types:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});




// Get reports data
app.get("/poc/getReports", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
    SELECT
    poc_prj_id AS id,
    poc_prj_name,
    assigned_to,
    sales_person AS "salesPerson",
    region,
    poc_type,
    start_date,
    excepted_end_date,
    client_name AS "companyName",
    description AS usecase,
    status,
    partner_client_own
FROM public.poc_prj_details
WHERE poc_prj_id IS NOT NULL
ORDER BY start_date DESC;
 
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching reports:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});




app.post("/poc/api/auth/login", async (req, res) => {
  console.log("Login attempt with body:", req.body);
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }

    let user = null;
    let userType = '';

    // ✅ ADD department_name here
    const empResult = await pool.query(
      `SELECT sr_no, emp_id, emp_name, email_id, role, password, department_name
       FROM emp_details
       WHERE (emp_id = $1 OR email_id = $1)
       AND status = 'Active'`,
      [username]
    );

    if (empResult.rows.length > 0) {
      user = empResult.rows[0];
      userType = 'employee';
    } else {
      const salespersonResult = await pool.query(
        `SELECT "Sr No" AS sr_no, salesperson_name, salesperson_email, password
         FROM salesperson_details
         WHERE salesperson_email = $1`,
        [username]
      );

      if (salespersonResult.rows.length > 0) {
        user = salespersonResult.rows[0];
        userType = 'salesperson';

        user.emp_id = "AE00";
        user.emp_name = user.salesperson_name;
        user.role = 0;
        user.department_name = "SALES"; // 🔹 optional but recommended
      }
    }

    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    if (password !== user.password) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // ✅ ADD department_name to token
    const tokenPayload = {
      sr_no: user.sr_no,
      user_type: userType,
      emp_id: user.emp_id,
      emp_name: user.emp_name,
      role: user.role,
      department_name: user.department_name
    };

    // const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "1h" });
    const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: "1m" });

    // ✅ ADD department_name to response
    const userResponse = {
      sr_no: user.sr_no,
      emp_id: user.emp_id,
      emp_name: user.emp_name,
      role: user.role,
      user_type: userType,
      department_name: user.department_name,
      email_id: user.email_id
    };

    res.json({ token, user: userResponse });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


app.post("/poc/api/auth/change-password", async (req, res) => {
  try {
    const { username, oldPassword, newPassword } = req.body;

    // Validation
    if (!username || !oldPassword || !newPassword) {
      return res.status(400).json({
        message: "Username, old password, and new password are required"
      });
    }

    if (oldPassword === newPassword) {
      return res.status(400).json({
        message: "New password cannot be the same as old password"
      });
    }

    let user = null;
    let userType = '';
    let tableName = '';

    // Check in emp_details table first
    const empResult = await pool.query(
      `SELECT sr_no, emp_id, emp_name, email_id, role, password, department_name
       FROM emp_details
       WHERE (emp_id = $1 OR email_id = $1)
       AND status = 'Active'`,
      [username]
    );

    if (empResult.rows.length > 0) {
      user = empResult.rows[0];
      userType = 'employee';
      tableName = 'emp_details';
    } else {
      // Check in salesperson_details table
      const salespersonResult = await pool.query(
        `SELECT "Sr No" AS sr_no, salesperson_name, salesperson_email, password
         FROM salesperson_details
         WHERE salesperson_email = $1`,
        [username]
      );

      if (salespersonResult.rows.length > 0) {
        user = salespersonResult.rows[0];
        userType = 'salesperson';
        tableName = 'salesperson_details';
      }
    }

    if (!user) {
      return res.status(404).json({
        message: "User not found or account is inactive"
      });
    }

    // Verify old password matches
    if (oldPassword !== user.password) {
      return res.status(401).json({
        message: "Current password is incorrect"
      });
    }

    // Update password based on user type
    let updateQuery = '';
    let updateParams = [];

    if (userType === 'employee') {
      updateQuery = `
        UPDATE emp_details 
        SET password = $1 
        WHERE (emp_id = $2 OR email_id = $2) 
        AND status = 'Active'
      `;
      updateParams = [newPassword, username];
    } else if (userType === 'salesperson') {
      updateQuery = `
        UPDATE salesperson_details 
        SET password = $1 
        WHERE salesperson_email = $2
      `;
      updateParams = [newPassword, username];
    }

    await pool.query(updateQuery, updateParams);

    res.status(200).json({
      message: "Password updated successfully",
      success: true
    });

  } catch (err) {
    console.error("Change password error:", err);

    if (err.code === '23505') {
      return res.status(400).json({
        message: "Password update failed due to constraint violation"
      });
    }

    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  }
});



app.get("/poc/getAllApprovedBy", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
            SELECT approved_by_id, emp_id, email, full_name
            FROM approved_by
            ORDER BY full_name
        `);

    const approvers = result.rows.map(row => ({
      id: row.approved_by_id,
      empId: row.emp_id,
      email: row.email,
      name: row.full_name
    }));

    res.json(approvers);
  } catch (err) {
    console.error("Error fetching approved by list:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get all POCs - FIXED with type casting
app.get("/poc/all", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        p.poc_prj_id as "pocId",
        p.poc_prj_name as "pocName",
        p.client_name as "entityName",
        p.partner_client_own as "entityType",
        p.sales_person as "salesPerson",
        p.region,
        p.is_billable as "isBillable",
        p.status,
        p.start_date as "startDate",
        p.excepted_end_date as "endDate",
        p.poc_type as "pocType",
        p.description,
        p.spoc_email_address as "spocEmail",
        p.spoc_designation as "spocDesignation",
        p.tag as "tags",
        p.assigned_to as "assignedTo",
        p.created_by as "createdBy",
        p.remarks as "remark",
        e.actual_start_date as "actualStartDate",
        e.actual_end_date as "actualEndDate",
        e.estimated_efforts as "estimatedEfforts",
        e.approved_by as "approvedBy",
        e.total_efforts as "totalEfforts",
        e.variance_days as "varianceDays",
        e.partner_name as "partnerName",
        COALESCE((
          SELECT SUM(
            CASE 
              WHEN hrs ~ '^[0-9]+:[0-9]+$' 
                THEN split_part(hrs, ':', 1)::int + split_part(hrs, ':', 2)::int / 60.0
              WHEN hrs ~ '^[0-9]+$'
                THEN hrs::int
              ELSE 0
            END
          ) AS total_hours
          FROM public.daily_poc_prj_status
          WHERE poc_prj_id = p.poc_prj_id::text
        ), 0) as "totalWorkedHours"
      FROM poc_prj_details p
      LEFT JOIN poc_prj_efforts e ON p.poc_prj_id::text = e.poc_prj_id::text
      ORDER BY p.poc_prj_id
    `);

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching Usecases:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});



// Create new POC
app.post("/poc/create", authenticateToken, async (req, res) => {
  try {
    const {
      pocId, pocName, entityName, entityType, salesPerson, region, isBillable,
      status, startDate, endDate, pocType, description, spocEmail, spocDesignation,
      tags, assignedTo, createdBy, remark, actualStartDate, actualEndDate,
      estimatedEfforts, approvedBy, totalEfforts, varianceDays
    } = req.body;
    console.log(req.body)
    // Start transaction
    await pool.query('BEGIN');

    // Insert into poc_prj_details
    const pocDetailsQuery = `
      INSERT INTO poc_prj_details (
        poc_prj_id, poc_prj_name, client_name, partner_client_own, sales_person,
        region, is_billable, status, start_date, excepted_end_date, poc_type,
        description, spoc_email_address, spoc_designation, tag, assigned_to,
        created_by, remarks
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      RETURNING *
    `;

    const pocDetailsValues = [
      pocId, pocName, entityName, entityType, salesPerson, region, isBillable,
      status, startDate, endDate, pocType, description, spocEmail, spocDesignation,
      tags, assignedTo, createdBy, remark
    ];

    const pocDetailsResult = await pool.query(pocDetailsQuery, pocDetailsValues);

    // Insert into poc_prj_efforts if effort data provided
    if (actualStartDate || actualEndDate || estimatedEfforts || approvedBy || totalEfforts || varianceDays) {
      const effortsQuery = `
        INSERT INTO poc_prj_efforts (
          poc_prj_id, actual_start_date, actual_end_date, estimated_efforts,
          approved_by, total_efforts, variance_days
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `;

      const effortsValues = [
        pocId, actualStartDate, actualEndDate, estimatedEfforts,
        approvedBy, totalEfforts, varianceDays
      ];

      await pool.query(effortsQuery, effortsValues);
    }

    // Commit transaction
    await pool.query('COMMIT');

    res.status(201).json({
      message: "POC created successfully",
      poc: pocDetailsResult.rows[0]
    });
  } catch (err) {
    // Rollback transaction on error
    await pool.query('ROLLBACK');

    console.error("Error creating POC:", err);

    if (err.code === '23505') { // Unique violation
      return res.status(409).json({ message: "POC ID already exists" });
    }

    res.status(500).json({ message: "Internal server error" });
  }
});



// Update POC - FIXED with type casting and Yes/No conversion for isBillable only
app.put("/poc/update/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    let {
      pocName, entityName, entityType, salesPerson, region, isBillable,
      status, startDate, endDate, pocType, description, spocEmail, spocDesignation,
      tags, assignedTo, remark, actualStartDate, actualEndDate,
      estimatedEfforts, approvedBy, totalEfforts, varianceDays, partnerName
    } = req.body;
    console.log(req.body);

    // 🔹 Convert boolean → Yes/No for isBillable
    const billableValue = isBillable === true ? "Yes" : "No";

    // Start transaction
    await pool.query("BEGIN");

    // 🔹 Update main details
    const pocDetailsQuery = `
      UPDATE poc_prj_details SET
        poc_prj_name = $1,
        client_name = $2,
        partner_client_own = $3,
        sales_person = $4,
        region = $5,
        is_billable = $6,
        status = $7,
        start_date = $8,
        excepted_end_date = $9,
        poc_type = $10,
        description = $11,
        spoc_email_address = $12,
        spoc_designation = $13,
        tag = $14,
        assigned_to = $15,
        remarks = $16
      WHERE poc_prj_id::text = $17
      RETURNING *
    `;

    const pocDetailsValues = [
      pocName, entityName, entityType, salesPerson, region, billableValue, // ✅ Yes/No saved
      status, startDate, endDate, pocType, description, spocEmail, spocDesignation,
      tags, assignedTo, remark, id
    ];

    const pocDetailsResult = await pool.query(pocDetailsQuery, pocDetailsValues);

    if (pocDetailsResult.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ message: "POC not found" });
    }

    // 🔹 Update efforts table (always update, if no row → insert)
    const effortsUpdateQuery = `
      UPDATE poc_prj_efforts SET
        actual_start_date = $1,
        actual_end_date = $2,
        estimated_efforts = $3,
        approved_by = $4,
        total_efforts = $5,
        variance_days = $6,
        partner_name = $7
      WHERE poc_prj_id::text = $8
      RETURNING *
    `;

    const effortsValues = [
      actualStartDate, actualEndDate, estimatedEfforts,
      approvedBy, totalEfforts, varianceDays, partnerName, id
    ];

    const effortsResult = await pool.query(effortsUpdateQuery, effortsValues);

    // If no row exists → insert instead
    if (effortsResult.rows.length === 0) {
      const effortsInsertQuery = `
        INSERT INTO poc_prj_efforts (
          poc_prj_id, actual_start_date, actual_end_date, estimated_efforts,
          approved_by, total_efforts, variance_days
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
      `;

      await pool.query(effortsInsertQuery, [
        id, actualStartDate, actualEndDate,
        estimatedEfforts, approvedBy, totalEfforts, varianceDays
      ]);
    }

    // Commit transaction
    await pool.query("COMMIT");

    res.json({
      message: "POC updated successfully",
      poc: pocDetailsResult.rows[0]
    });
  } catch (err) {
    await pool.query("ROLLBACK");
    console.error("Error updating POC:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});



// Get all assignTo (employees) - FIXED
app.get("/poc/getAllAssignTo", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
        SELECT sr_no, emp_id, emp_name, email_id
        FROM emp_details
        WHERE status = 'Active'
        AND emp_id NOT IN ('AE0007', 'AE0201', 'AE0751')
        ORDER BY emp_name;
      `);

    const employees = result.rows.map(row => ({
      id: row.sr_no,
      empId: row.emp_id,
      name: row.emp_name,
      email: row.email_id
    }));

    res.json(employees);
  } catch (err) {
    console.error("Error fetching assignTo list:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/poc/getAllSalesPerson", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
        SELECT salesperson_name, salesperson_email         
        FROM public.salesperson_details
        where salesperson_email not in ('sachin.deshpande@automationedge.com', 'snehadeep.paul@automationedge.com');
      `);

    const salesPersons = result.rows.map(row => ({
      id: row.salesperson_email,   // use email as unique key
      name: row.salesperson_name,
      email: row.salesperson_email
    }));

    res.json(salesPersons);
  } catch (err) {
    console.error("Error fetching sales persons:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


// Delete POC - FIXED with type casting
app.delete("/poc/delete/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Start transaction
    await pool.query('BEGIN');

    // Delete from poc_prj_efforts first (due to foreign key constraint)
    await pool.query(
      'DELETE FROM poc_prj_efforts WHERE poc_prj_id::text = $1',
      [id]
    );

    // Delete from poc_prj_details
    const result = await pool.query(
      'DELETE FROM poc_prj_details WHERE poc_prj_id::text = $1 RETURNING *',
      [id]
    );

    if (result.rows.length === 0) {
      await pool.query('ROLLBACK');
      return res.status(404).json({ message: "POC not found" });
    }

    // Commit transaction
    await pool.query('COMMIT');

    res.json({ message: "POC deleted successfully" });
  } catch (err) {
    // Rollback transaction on error
    await pool.query('ROLLBACK');

    console.error("Error deleting POC:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get unique values for filters
app.get("/poc/filters/unique-values", authenticateToken, async (req, res) => {
  try {
    const { column } = req.query;

    if (!column) {
      return res.status(400).json({ message: "Column parameter is required" });
    }

    // Validate column name to prevent SQL injection
    const validColumns = [
      'poc_prj_id', 'poc_prj_name', 'client_name', 'partner_client_own',
      'sales_person', 'region', 'is_billable', 'status', 'poc_type',
      'assigned_to', 'created_by'
    ];

    if (!validColumns.includes(column)) {
      return res.status(400).json({ message: "Invalid column name" });
    }

    const query = `SELECT DISTINCT ${column} FROM poc_prj_details WHERE ${column} IS NOT NULL ORDER BY ${column}`;
    const result = await pool.query(query);

    const values = result.rows.map(row => row[column]);
    res.json(values);
  } catch (err) {
    console.error("Error fetching unique values:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Get dashboard statistics
app.get("/poc/dashboard/stats", authenticateToken, async (req, res) => {
  try {
    const totalQuery = 'SELECT COUNT(*) FROM poc_prj_details';
    const completedQuery = 'SELECT COUNT(*) FROM poc_prj_details WHERE status = $1';
    const inProgressQuery = 'SELECT COUNT(*) FROM poc_prj_details WHERE status = $1';
    const billableQuery = 'SELECT COUNT(*) FROM poc_prj_details WHERE is_billable = true';

    const [totalResult, completedResult, inProgressResult, billableResult] = await Promise.all([
      pool.query(totalQuery),
      pool.query(completedQuery, ['Completed']),
      pool.query(inProgressQuery, ['In Progress']),
      pool.query(billableQuery)
    ]);

    const stats = {
      total: parseInt(totalResult.rows[0].count),
      completed: parseInt(completedResult.rows[0].count),
      inProgress: parseInt(inProgressResult.rows[0].count),
      billable: parseInt(billableResult.rows[0].count)
    };

    res.json(stats);
  } catch (err) {
    console.error("Error fetching dashboard stats:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.status(200).json({ message: "Server is running" });
});




// Fixed Function to generate next poc_prj_id
async function generateNextPocId(prefix) {
  try {
    // Convert prefix to lowercase for case-insensitive comparison
    const prefixLower = prefix.toLowerCase();

    const result = await pool.query(
      `SELECT poc_prj_id 
       FROM public.poc_prj_details 
       WHERE LOWER(poc_prj_id) LIKE $1`,
      [prefixLower + "-%"]
    );

    console.log('🔍 DEBUG generateNextPocId:');
    console.log('Original Prefix:', prefix);
    console.log('Lowercase Prefix:', prefixLower);
    console.log('Found existing IDs:', result.rows);

    if (result.rows.length === 0) {
      return `${prefix}-01`;
    }

    let highestNumber = 0;

    // Find the highest number among ALL matching IDs
    for (const row of result.rows) {
      const id = row.poc_prj_id;
      const match = id.match(/-(\d+)$/i);

      if (match) {
        const num = parseInt(match[1], 10);
        if (!isNaN(num) && num > highestNumber) {
          highestNumber = num;
        }
      }
    }

    const nextNumber = highestNumber + 1;

    // Use appropriate padding based on the number size
    const nextId = highestNumber >= 100 ?
      `${prefix}-${nextNumber}` :
      `${prefix}-${nextNumber.toString().padStart(2, '0')}`;

    console.log('Highest number found:', highestNumber);
    console.log('Next number:', nextNumber);
    console.log('Generated next ID:', nextId);

    return nextId;

  } catch (error) {
    console.error('Error generating next POC ID:', error);
    return `${prefix}-01`;
  }
}






// Method to send POC creation notification email
const sendPOCNotificationEmail = async (pocData) => {

  const clientPartnerDisplay =
    `Client - ${pocData.entityName}` +
    (pocData.partnerName && pocData.partnerName.trim()
      ? `, Partner - ${pocData.partnerName}`
      : '');

  try {
    const transporter = nodemailer.createTransport(emailConfig);

    const emailSubject = `New POC ID Created: ${pocData.pocPrjId}`;

    const emailHtml = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body {
            font-family: 'Calibri', Arial, sans-serif;
            line-height: 1.6;
            color: #000000;
            margin: 0;
            padding: 20px;
            background-color: #ffffff;
        }
        .container {
            max-width: 700px;
            margin: 0 auto;
            background: #ffffff;
        }
        .content {
            padding: 20px;
        }
        .greeting {
            font-size: 14px;
            color: #000000;
            margin-bottom: 15px;
            font-weight: normal;
        }
        .info-text {
            font-size: 14px;
            color: #000000;
            margin-bottom: 20px;
            line-height: 1.5;
        }
        .poc-table {
            width: 100%;
            border: 1px solid #000000;
            border-collapse: collapse;
            font-size: 14px;
            font-family: Calibri, Arial, sans-serif;
        }
        .poc-table th {
            background-color: rgba(57, 25, 201, 0.822);
            color: #ffffff;
            padding: 8px 12px;
            text-align: left;
            font-weight: bold;
            border: 1px solid #000000;
            font-size: 14px;
        }
        .poc-table td {
            padding: 8px 12px;
            border: 1px solid #000000;
            background-color: #ffffff;
            font-size: 14px;
        }
        .poc-table tr:nth-child(even) td {
            background-color: #ffffff;
        }
        .field-column {
            font-weight: bold;
            color: #000000;
            width: 35%;
        }
        .value-column {
            color: #000000;
            width: 65%;
        }
        .poc-id-value {
            color: #000000;
            font-weight: bold;
        }
        .footer {
            margin-top: 20px;
            padding: 15px 0;
            border-top: 1px solid #cccccc;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="content">
            <div class="greeting">Hi Team,</div>
            
            <div class="info-text">
                Given POC ID already exists, so BOT has created new POC ID as below:
            </div>
            
            <table class="poc-table" cellspacing="0" cellpadding="5">
                <tr>
                    <th>Field</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td class="field-column">POC ID</td>
                    <td class="value-column poc-id-value">${pocData.pocPrjId}</td>
                </tr>
                <tr>
                    <td class="field-column">POC Name</td>
                    <td class="value-column">${pocData.pocName}</td>
                </tr>
                <tr>
                    <td class="field-column">Name of Partner/Client/Internal</td>
                    <td class="value-column">${clientPartnerDisplay}</td>
                </tr>
                <tr>
                    <td class="field-column">Assigned To</td>
                    <td class="value-column">${pocData.assignedTo}</td>
                </tr>
                <tr>
                    <td class="field-column">Salesperson</td>
                    <td class="value-column">${pocData.salesPerson}</td>
                </tr>
            </table>
        </div>
        
        <div class="footer">
            <font face='Cambria' color='#003b94'>
            <br><p>Thanks & Regards,</font></br>
            <font face='Cambria' color='#ff9100'><b>POC BOT</b></font><br>
            <i><font face="Calibri" size="3" color="#003b94">
            ------------------------------------------------------------------<br>
            This is BOT generated email, please do not reply
            </font></i>
            <br><br>
        </div>
    </div>
</body>
</html>
    `;

    const mailOptions = {
      from: emailConfig.auth.user,
      to: USECASE_RECIPIENTS,
      subject: emailSubject,
      html: emailHtml,
      text: `Hi Team,\n\nGiven POC ID already exists, so BOT has created new POC ID as below:\n\nPOC ID: ${pocData.pocPrjId}\nPOC Name: ${pocData.pocName}\nName of Partner/Client/Internal: ${clientPartnerDisplay}\nAssigned To: ${pocData.assignedTo}\nSalesperson: ${pocData.salesPerson}\n\nThanks & Regards,\nPOC BOT\n------------------------------------------------------------------\nThis is BOT generated email, please do not reply`
    };

    const result = await transporter.sendMail(mailOptions);
    console.log("POC notification email sent successfully:", result.messageId);
    return result;
  } catch (error) {
    console.error("Error sending POC notification email:", error);
    throw error;
  }
};



// Save POC with AutomationEdge integration
app.post("/poc/savepocprjid", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      pocId,           // prefix only, like "Event"
      pocName,
      entityType,      // client type
      entityName,      // company name
      partnerName,     // goes to efforts table
      pocType,
      region,
      salesPerson,
      spocEmail,
      spocDesignation,
      description,
      assignedTo,
      startDate,
      endDate,
      isBillable,
      tags,
      remark,
      createdBy
    } = req.body;

    console.log(req.body);
    await client.query("BEGIN");
    const billableValue = isBillable === true ? "Yes" : "No";

    // 🔹 Generate poc_prj_id
    const pocPrjId = await generateNextPocId(pocId);

    // 🔹 Insert into poc_prj_details
    const insertDetailsQuery = `
  INSERT INTO public.poc_prj_details (
    poc_prj_id, poc_prj_name, client_name, partner_client_own,
    sales_person, description, assigned_to, start_date,
    excepted_end_date, remarks, created_by, region, poc_type,
    is_billable, tag, spoc_email_address, spoc_designation, department_name,
    status  -- Add status column
  )
  VALUES (
    $1,$2,$3,$4,$5,$6,$7,$8,$9,
    $10,$11,$12,$13,$14,$15,$16,$17,$18,
    'Draft'  -- Set default status as 'Draft'
  )
  RETURNING *;
`;

    const detailsResult = await client.query(insertDetailsQuery, [
      pocPrjId,
      pocName,
      entityName,
      entityType,
      salesPerson,
      description,
      assignedTo,
      startDate,
      endDate,
      remark,
      createdBy,
      region,
      pocType,
      billableValue,
      tags,
      spocEmail,
      spocDesignation,
      "PCS ROW"
    ]);

    // 🔹 Insert into poc_prj_efforts
    const insertEffortsQuery = `
      INSERT INTO public.poc_prj_efforts (poc_prj_id, partner_name)
      VALUES ($1, $2)
      RETURNING *;
    `;
    const effortsResult = await client.query(insertEffortsQuery, [pocPrjId, partnerName]);

    await client.query("COMMIT");

    // ✅ Send email notification
    try {
      await sendPOCNotificationEmail({
        pocPrjId,
        pocName,
        entityType,
        entityName,
        partnerName,
        assignedTo,
        salesPerson
      });
    } catch (emailError) {
      console.error("Error sending notification email:", emailError);
      // Don't throw error - email failure shouldn't fail the main operation
    }


    // Final API response
    res.status(201).json({
      message: "POC saved successfully",
      details: detailsResult.rows[0],
      efforts: effortsResult.rows[0]
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error saving POC:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});



app.get("/poc/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(`
        SELECT 
          p.poc_prj_id as "pocId",
          p.poc_prj_name as "pocName",
          p.client_name as "entityName",
          p.partner_client_own as "entityType",
          p.sales_person as "salesPerson",
          p.region,
          p.is_billable as "isBillable",
          p.status,
          p.start_date as "startDate",
          p.excepted_end_date as "endDate",
          p.poc_type as "pocType",
          p.description,
          p.spoc_email_address as "spocEmail",
          p.spoc_designation as "spocDesignation",
          p.tag as "tags",
          p.assigned_to as "assignedTo",
          p.created_by as "createdBy",
          p.remarks as "remark",
          e.actual_start_date as "actualStartDate",
          e.actual_end_date as "actualEndDate",
          e.estimated_efforts as "estimatedEfforts",
          e.approved_by as "approvedBy",
          e.total_efforts as "totalEfforts",
          e.variance_days as "varianceDays"
        FROM poc_prj_details p
        LEFT JOIN poc_prj_efforts e ON p.poc_prj_id::text = e.poc_prj_id::text
        WHERE p.poc_prj_id::text = $1
      `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "POC not found" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("Error fetching POC:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});


// Update POC Status Only - FIXED (without updated_at column)
app.put("/poc/updateStatus/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    console.log("Update Status Request:", { id, status });

    // Validate required fields
    if (!status) {
      return res.status(400).json({ message: "Status is required" });
    }

    // Validate status value
    const validStatuses = ['Pending', 'In Progress', 'Completed', 'Dropped', 'Draft', 'Awaiting', 'Hold', 'Closed', 'Converted', 'Live'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        message: "Invalid status value",
        validStatuses: validStatuses
      });
    }

    // Simple update without updated_at column
    const updateQuery = `
            UPDATE poc_prj_details 
            SET status = $1
            WHERE poc_prj_id::text = $2
            RETURNING poc_prj_id, poc_prj_name, status
        `;

    const result = await pool.query(updateQuery, [status, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "POC not found with ID: " + id });
    }

    res.json({
      success: true,
      message: "Status updated successfully",
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Error updating POC status:", err);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message
    });
  }
});



// Update remark endpoint
app.put('/poc/updateRemark/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { remark } = req.body;

    // Simple update without updated_at column
    const updateQuery = `
            UPDATE poc_prj_details 
            SET remarks = $1
            WHERE poc_prj_id::text = $2
            RETURNING poc_prj_id, poc_prj_name, remarks
        `;

    const result = await pool.query(updateQuery, [remark, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "POC not found with ID: " + id });
    }

    res.json({
      success: true,
      message: "Remark updated successfully",
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Error updating POC remark:", err);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message
    });
  }
});





// Create transporter - FIXED: Added proper variable declaration
let transporter;

try {
  transporter = nodemailer.createTransport(emailConfig);

  // Verify transporter configuration
  transporter.verify(function (error, success) {
    if (error) {
      console.error('❌ Email transporter configuration error:', error);
    } else {
      console.log('✅ Email transporter is ready to send messages');
    }
  });
} catch (error) {
  console.error('❌ Failed to create email transporter:', error);
}

// Email service function
async function sendPocEmail(pocDetails) {
  // Check if transporter is defined
  if (!transporter) {
    console.error('❌ Email transporter is not configured');
    return;
  }

  try {
    const subject = `New POC Created - ID: ${pocDetails.id}`;

    // HTML body with professional CSS
    const body = `
      <html>
        <head>
          <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; padding: 20px; }
            h2 { color: #333; }
            table { width: 80%; margin: 20px auto; border-collapse: collapse;
                    background: #fff; border-radius: 10px; overflow: hidden;
                    box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
            th, td { padding: 12px 18px; text-align: left; border-bottom: 1px solid #eee; }
            th { width: 30%; background: #f1f5ff; color: #333; text-transform: uppercase;
                 letter-spacing: 0.05em; font-weight: 600; }
            td { width: 70%; color: #444; }
            tr:nth-child(even) { background: #fafafa; }
            tr:hover { background: #f1f5ff; }
            .success { margin: 20px auto; width: 80%; font-size: 16px; font-weight: 600; color: green; }
          </style>
        </head>
        <body>
         <p>Hi Team,</p> 
         <p>Please find the below table report for the newly initiated usecase by the PCS ROW Team.</p>
         <br /><br />
          <h2>📢 A new POC has been created</h2>
          <table>
            <tr><th>ID</th><td>${pocDetails.id}</td></tr>
            <tr><th>Sales Person</th><td>${safe(pocDetails.sp_name)}</td></tr>
            <tr><th>Region</th><td>${safe(pocDetails.region)}</td></tr>
            <tr><th>End Customer Type</th><td>${safe(pocDetails.end_customer_type)}</td></tr>
            <tr><th>Process Type</th><td>${safe(pocDetails.process_type)}</td></tr>
            <tr><th>Customer Company</th><td>${safe(pocDetails.company_name)}</td></tr>
            <tr><th>Customer SPOC</th><td>${safe(pocDetails.spoc)}</td></tr>
            <tr><th>Customer SPOC Email</th><td>${safe(pocDetails.spoc_email)}</td></tr>
            <tr><th>Customer Designation</th><td>${safe(pocDetails.designation)}</td></tr>
            <tr><th>Customer Mobile</th><td>${safe(pocDetails.mobile_number)}</td></tr>
            <tr><th>Use Case</th><td>${safe(pocDetails.usecase)}</td></tr>
            <tr><th>Brief</th><td>${safe(pocDetails.brief)}</td></tr>
            ${pocDetails.end_customer_type === 'Partner' ? `
            <tr><th>Partner Company</th><td>${safe(pocDetails.partner_company_name)}</td></tr>
            <tr><th>Partner SPOC</th><td>${safe(pocDetails.partner_spoc)}</td></tr>
            <tr><th>Partner SPOC Email</th><td>${safe(pocDetails.partner_spoc_email)}</td></tr>
            <tr><th>Partner Designation</th><td>${safe(pocDetails.partner_designation)}</td></tr>
            <tr><th>Partner Mobile</th><td>${safe(pocDetails.partner_mobile_number)}</td></tr>
            ` : ''}
          </table>
          <p class='success'>✅ Created successfully! 🚀</p>
          <br /><br />
         <font face='Cambria', color='#003b94'></p><br><p>Thanks & Regards,</font>
         </br><font face='Cambria', color='#ff9100'>PCS ROW Team BOT</b></font>
         <br><i>
         <font face=\"Calibri\", size=3, color=\"#003b94\" >
           ------------------------------------------------------------------<br>
         This is BOT generated email, please do not reply.
         </font></i><br><br></font>
          </body>
      </html>
    `;

    const mailOptions = {
      from: emailConfig.auth.user,
      to: POC_RECIPIENTS.split(',').map(email => email.trim()),
      subject: subject,
      html: body
    };

    const result = await transporter.sendMail(mailOptions);
    console.log('📧 Email sent successfully to:', POC_RECIPIENTS);
    return result;

  } catch (error) {
    console.error('❌ Failed to send email:', error);
    throw new Error(`Failed to send email: ${error.message}`);
  }
}

function safe(value) {
  return value != null ? value.toString() : '';
}


// Updated POST endpoint to save POC details with email
app.post("/poc/save", authenticateToken, async (req, res) => {
  const {
    salesPerson,
    region,
    endCustomerType,
    processType,
    companyName,
    spoc,
    spocEmail,
    designation,
    mobileNumber,
    usecase,
    brief,
    partnerCompanyName,
    partnerSpoc,
    partnerSpocEmail,
    partnerDesignation,
    partnerMobileNumber,
    remark
  } = req.body;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const query = `
      INSERT INTO public.poc_details (
        sp_name,
        region,
        end_customer_type,
        process_type,
        company_name,
        spoc,
        spoc_email,
        designation,
        mobile_number,
        usecase,
        brief,
        partner_company_name,
        partner_spoc,
        partner_spoc_email,
        partner_designation,
        partner_mobile_number,
        remark,
        status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
      RETURNING *
    `;

    const values = [
      salesPerson,
      region,
      endCustomerType,
      processType,
      companyName,
      spoc,
      spocEmail,
      designation,
      mobileNumber,
      usecase,
      brief,
      partnerCompanyName,
      partnerSpoc,
      partnerSpocEmail,
      partnerDesignation,
      partnerMobileNumber,
      remark,
      "Draft" // Default status
    ];

    const result = await client.query(query, values);
    const savedPoc = result.rows[0];

    // Send email notification (don't await to avoid blocking response)
    if (transporter) {
      sendPocEmail(savedPoc).catch(emailError => {
        console.error('Email sending failed:', emailError);
        // Don't throw error - email failure shouldn't affect the main operation
      });
    } else {
      console.warn('⚠️ Email transporter not available - skipping email notification');
    }

    await client.query("COMMIT");

    res.status(201).json({
      message: "POC saved successfully",
      id: savedPoc.id,
      ...savedPoc
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error saving POC:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});



// In your backend - API endpoint to get employee list
app.get('/poc/getEmployees', authenticateToken, async (req, res) => {
  try {
    const query = `
            SELECT 
                emp_id,
                emp_name,
                email_id
            FROM emp_details 
            WHERE status='Active' 
            AND emp_id NOT IN ('AE0204','AE0751','AE0468','AE0802','VD0035','FB0154','AE0248','AE0510','AE0201','AE0007','AE0838')
            ORDER BY emp_id
        `;

    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching employees:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});





// Summary Report API endpoint












// In your server.js file, add these routes after your other routes:

// ============================================
// LEAVE MANAGEMENT ROUTES
// ============================================

// Email recipients
const manager_mail_id = process.env.POC_NOTIFICATION_RECIPIENTS ||
  'devopsbyzielotech@gmail.com';
const pcs_row_mail_id = process.env.POC_NOTIFICATION_RECIPIENTS ||
  'nitin.bhujbal@automationedge.com';

// 1. Apply for Leave (POST)
app.post('/poc/leave/apply', authenticateToken, async (req, res) => {
  try {
    console.log('=== LEAVE APPLICATION REQUEST ===');
    console.log('Employee ID:', req.user?.emp_id);

    // Get user info
    const emp_id = req.user.emp_id;
    const emp_name = req.user.emp_name || req.user.email_id;

    if (!emp_id) {
      return res.status(400).json({ error: 'User information not found in token' });
    }

    const {
      leaveType,
      startDate,
      endDate,
      days,
      reason,
      contactDuringLeave,
      halfDay = false,
      halfDayType,
      status = 'Pending for approval of reporting manager'
    } = req.body;

    // Validation
    if (!leaveType || !startDate || !endDate || !days || !reason) {
      return res.status(400).json({
        error: 'Missing required fields',
        received: { leaveType, startDate, endDate, days, reason }
      });
    }

    // Format dates to DD-MM-YYYY
    const formatDateToDDMMYYYY = (dateString) => {
      if (!dateString) return null;
      const date = new Date(dateString);
      const day = String(date.getDate()).padStart(2, '0');
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const year = date.getFullYear();
      return `${day}-${month}-${year}`;
    };

    // Format current date for apply_date
    const today = new Date();
    const formattedApplyDate = `${String(today.getDate()).padStart(2, '0')}-${String(today.getMonth() + 1).padStart(2, '0')}-${today.getFullYear()}`;

    // Format start and end dates
    const formattedStartDate = formatDateToDDMMYYYY(startDate);
    const formattedEndDate = formatDateToDDMMYYYY(endDate);

    console.log('Formatted Dates:', {
      apply_date: formattedApplyDate,
      from_date: formattedStartDate,
      to_date: formattedEndDate,
      halfDay: halfDay,
      halfDayType: halfDayType
    });

    // Fetch employee email from emp_details table
    console.log('Fetching employee email details...');
    const empEmailQuery = `
      SELECT email_id 
      FROM emp_details 
      WHERE emp_id = $1
    `;

    const empEmailResult = await pool.query(empEmailQuery, [emp_id]);

    if (empEmailResult.rows.length === 0) {
      console.error(`Employee with ID ${emp_id} not found in emp_details table`);
      return res.status(404).json({
        error: 'Employee details not found',
        message: `Employee ID ${emp_id} does not exist in employee records`
      });
    }

    const emp_email = empEmailResult.rows[0].email_id;
    console.log(`Found employee email: ${emp_email}`);

    // Set RM email (reporting manager email)
    const rm_emp_email = 'piraji.doiphode@automationedge.com';

    // Insert leave application with correct email and RM email
    const query = `
      INSERT INTO employee_leave_details (
        emp_id, 
        emp_name,
        emp_email,
        rm_emp_email,
        leave_type, 
        apply_date,
        from_date, 
        to_date, 
        reason,
        leave_status,
        half_day,
        half_day_type
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *
    `;

    const values = [
      emp_id,
      emp_name,
      emp_email, // Use actual email from emp_details table
      rm_emp_email, // Set RM email
      leaveType,
      formattedApplyDate, // Use formatted apply date
      formattedStartDate, // Use formatted start date
      formattedEndDate, // Use formatted end date
      reason,
      status,
      halfDay,
      halfDayType
    ];

    console.log('Inserting leave application with values:', values);

    const result = await pool.query(query, values);
    const savedLeave = result.rows[0];

    console.log(`Leave application saved: SR#${savedLeave.sr_no} for ${emp_id}`);
    console.log('Email used:', emp_email);
    console.log('RM Email set:', rm_emp_email);

    // Send email with correct employee email
    sendLeaveApplyEmail({
      emp_id: emp_id,
      emp_name: emp_name,
      emp_email: emp_email, // Pass actual email
      leave_type: leaveType,
      start_date: startDate, // Keep original format for email
      end_date: endDate, // Keep original format for email
      days: parseFloat(days),
      reason: reason,
      contact_during_leave: contactDuringLeave || null,
      half_day: halfDay,
      half_day_type: halfDayType,
      status: status
    }).then(success => {
      if (success) {
        console.log(`Leave application email sent for ${emp_id} to ${emp_email}`);
      }
    });

    res.status(201).json({
      message: 'Leave applied successfully',
      leave: savedLeave
    });

  } catch (error) {
    console.error('Error applying leave:', error.message);
    console.error('Stack trace:', error.stack);

    res.status(500).json({
      error: 'Failed to apply for leave',
      details: error.message
    });
  }
});

// Function to send leave application email
const sendLeaveApplyEmail = async (leaveDetails) => {
  try {
    // Parse recipients (use same as revoke email)
    const toRecipients = POC_RECIPIENTS.split(',').map(email => email.trim());

    // Format dates
    const formatDate = (dateString) => {
      const date = new Date(dateString);
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    };

    // Format leave type
    const formatLeaveType = (type) => {
      const typeMap = {
        sick: 'Sick Leave',
        privileged: 'Privileged Leave',
        casual: 'Casual Leave',
        comp_off: 'Comp Off',
        leave_without_pay: 'Leave Without Pay',
        maternity: 'Maternity Leave',
        paternity: 'Paternity Leave'
      };
      return typeMap[type] || type;
    };

    // Create email body
    const emailBody = `
Hi Team,

I would like to apply for leave as per the details below:

Employee ID: ${leaveDetails.emp_id}
Employee Name: ${leaveDetails.emp_name}
Employee Email: ${leaveDetails.emp_email}
Leave Type: ${formatLeaveType(leaveDetails.leave_type)}
Leave Period: ${formatDate(leaveDetails.start_date)} to ${formatDate(leaveDetails.end_date)}
Number of Days: ${leaveDetails.days} ${leaveDetails.half_day ? '(Half Day' + (leaveDetails.half_day_type === 'first' ? ' - First Half)' : ' - Second Half)') : ''}
Reason: ${leaveDetails.reason}
Contact During Leave: ${leaveDetails.contact_during_leave || 'Not provided'}

Kindly review and approve my leave request.

Please let me know if any additional information is required.

Thank you for your support.

Thanks & Regards,
POC Bot
    `;

    // Email options
    const mailOptions = {
      from: `"POC Bot" <${emailConfig.auth.user}>`,
      to: manager_mail_id,
      cc: pcs_row_mail_id, // CC the actual employee email
      subject: 'Leave Application',
      text: emailBody,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
          <p>Hi Team,</p>
          
          <p>I would like to apply for leave as per the details below:</p>
          
          <table style="border-collapse: collapse; margin: 20px 0; width: 100%;">
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd; width: 30%;"><strong>Employee ID:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd; width: 70%;">${leaveDetails.emp_id}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Employee Name:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${leaveDetails.emp_name}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Employee Email:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${leaveDetails.emp_email}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Leave Type:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatLeaveType(leaveDetails.leave_type)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Leave Period:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatDate(leaveDetails.start_date)} to ${formatDate(leaveDetails.end_date)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Number of Days:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${leaveDetails.days} ${leaveDetails.half_day ? '(Half Day - ' + (leaveDetails.half_day_type === 'first' ? 'First Half)' : 'Second Half)') : ''}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Reason:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${leaveDetails.reason}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Contact During Leave:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${leaveDetails.contact_during_leave || 'Not provided'}</td>
            </tr>
          </table>
          
          <p>Kindly review and approve my leave request.</p>
          
          <p>Please let me know if any additional information is required.</p>
          
          <p>Thank you for your support.</p>
          
           <br>
            <font face='Cambria' color='#003b94'>
              <p>Thanks & Regards,</p>
            </font>
            <font face='Cambria' color='#ff9100'>
              <p>POC BOT</p>
            </font>
          <i>
            <font face="Calibri" size="3" color="#003b94">
              ------------------------------------------------------------------<br>
              This is BOT generated email, please do not reply
            </font>
          </i>
        </div>
      `
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log(`Email sent successfully. Message ID: ${info.messageId}`);
    return true;

  } catch (error) {
    console.error('Error sending leave application email:', error.message);
    return false;
  }
};


// 2. Get leave requests (GET)
app.get('/poc/leave/requests', authenticateToken, async (req, res) => {
  try {
    const emp_id = req.user.emp_id;

    // Check if user has all_status_access or status_access permission
    const permissionQuery = `
      SELECT all_status_access, status_access FROM user_permissions WHERE emp_id = $1
    `;
    const permissionResult = await pool.query(permissionQuery, [emp_id]);

    let hasAllAccess = false;
    let hasStatusAccess = false;

    if (permissionResult.rows.length > 0) {
      hasAllAccess = permissionResult.rows[0].all_status_access || false;
      hasStatusAccess = permissionResult.rows[0].status_access || false;
    }

    let query;
    let params = [];

    // If user has all_status_access OR status_access, show all leaves
    if (hasAllAccess || hasStatusAccess) {
      query = `
        SELECT 
          sr_no as id,
          emp_id,
          emp_name,
          leave_type,
          from_date,
          to_date,
          apply_date,
          reason,
          leave_status as status,
          emp_email,
          rm_emp_email,
          half_day,
          half_day_type
        FROM employee_leave_details 
        ORDER BY sr_no DESC
      `;
    } else {
      // Otherwise, show only their own leaves
      query = `
        SELECT 
          sr_no as id,
          emp_id,
          emp_name,
          leave_type,
          from_date,
          to_date,
          apply_date,
          reason,
          leave_status as status,
          emp_email,
          rm_emp_email,
          half_day,
          half_day_type
        FROM employee_leave_details 
        WHERE emp_id = $1 
        ORDER BY sr_no DESC
      `;
      params = [emp_id];
    }

    const result = await pool.query(query, params);

    // Helper function to parse dates in multiple formats
    const parseDate = (dateStr) => {
      if (!dateStr || typeof dateStr !== 'string') return null;

      dateStr = dateStr.trim();

      // Try YYYY-MM-DD format
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const [year, month, day] = dateStr.split('-').map(Number);
        return new Date(year, month - 1, day);
      }

      // Try DD-MM-YYYY format
      if (/^\d{2}-\d{2}-\d{4}$/.test(dateStr)) {
        const [day, month, year] = dateStr.split('-').map(Number);
        return new Date(year, month - 1, day);
      }

      // Try parsing as-is
      const date = new Date(dateStr);
      return !isNaN(date.getTime()) ? date : null;
    };

    // Helper function to format date to YYYY-MM-DD
    const formatDateToYYYYMMDD = (dateStr) => {
      if (!dateStr) return '';

      const date = parseDate(dateStr);
      if (!date) return dateStr;

      const year = date.getFullYear();
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const day = String(date.getDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    };

    // Calculate days between two dates - UPDATED for half-day
    const calculateDays = (startDateStr, endDateStr, halfDay = false) => {
      if (halfDay) return 0.5;

      const startDate = parseDate(startDateStr);
      const endDate = parseDate(endDateStr);

      if (!startDate || !endDate) return 1;

      const start = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate());
      const end = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDate());

      const diffTime = Math.abs(end - start);
      const diffDays = Math.floor(diffTime / (1024 * 60 * 60 * 24));

      return diffDays + 1;
    };

    // Transform the data
    const transformedResult = result.rows.map(row => {
      const days = calculateDays(row.from_date, row.to_date, row.half_day);
      const formattedStartDate = formatDateToYYYYMMDD(row.from_date);
      const formattedEndDate = formatDateToYYYYMMDD(row.to_date);

      return {
        id: row.id,
        emp_id: row.emp_id,
        emp_name: row.emp_name,
        leave_type: row.leave_type,
        start_date: formattedStartDate,
        end_date: formattedEndDate,
        days: days,
        reason: row.reason,
        // contact_during_leave: row.contact_during_leave || null,
        half_day: row.half_day || false,
        half_day_type: row.half_day_type || 'first',
        status: row.status,
        applied_date: row.apply_date,
        updated_at: row.apply_date,
        emp_email: row.emp_email,
        rm_emp_email: row.rm_emp_email
      };
    });

    res.status(200).json(transformedResult);
  } catch (error) {
    console.error('Error fetching leave requests:', error);
    res.status(500).json({ error: 'Failed to fetch leave requests' });
  }
});


// LEAVE EDIT API - Updated with half-day support
app.put('/poc/leave/edit/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const emp_id = req.user.emp_id;
    const {
      leaveType,
      startDate,
      endDate,
      reason,
      contactDuringLeave,
      halfDay = false,
      halfDayType
    } = req.body;

    // 1. Check if leave exists - Get original details for email
    const leaveQuery = `
      SELECT sr_no, emp_id, emp_name, leave_type, from_date, to_date, reason, leave_status,
             half_day, half_day_type
      FROM employee_leave_details WHERE sr_no = $1
    `;
    const leaveResult = await pool.query(leaveQuery, [id]);

    if (leaveResult.rowCount === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }

    const originalLeave = leaveResult.rows[0];

    // 2. Check if user can edit this leave
    if (originalLeave.emp_id === emp_id) {
      // User owns the leave - allow edit
    } else {
      // User doesn't own the leave - check if they have all_status_access
      const permissionsQuery = `
        SELECT all_status_access 
        FROM user_permissions 
        WHERE emp_id = $1
      `;
      const permissionsResult = await pool.query(permissionsQuery, [emp_id]);

      // Check if user has all_status_access (assuming it's a boolean column)
      if (permissionsResult.rowCount === 0 || !permissionsResult.rows[0].all_status_access) {
        return res.status(403).json({
          error: 'Not authorized to edit this leave'
        });
      }
    }

    // Format dates to DD-MM-YYYY (same as apply leave API)
    const formatDateToDDMMYYYY = (dateString) => {
      if (!dateString) return null;

      // If already in DD-MM-YYYY format, return as is
      if (dateString.match(/^\d{2}-\d{2}-\d{4}$/)) {
        return dateString;
      }

      // If in YYYY-MM-DD format, convert to DD-MM-YYYY
      if (dateString.match(/^\d{4}-\d{2}-\d{2}$/)) {
        const parts = dateString.split('-');
        const year = parts[0];
        const month = parts[1];
        const day = parts[2];
        return `${day}-${month}-${year}`;
      }

      // Otherwise, parse as Date object
      const date = new Date(dateString);
      const day = String(date.getDate()).padStart(2, '0');
      const month = String(date.getMonth() + 1).padStart(2, '0');
      const year = date.getFullYear();
      return `${day}-${month}-${year}`;
    };

    // Format start and end dates
    const formattedStartDate = formatDateToDDMMYYYY(startDate);
    const formattedEndDate = formatDateToDDMMYYYY(endDate);

    console.log('Edit - Formatted Dates:', {
      from_date: formattedStartDate,
      to_date: formattedEndDate,
      halfDay: halfDay,
      halfDayType: halfDayType
    });

    // 3. Calculate days for updated leave
    const calculateDays = () => {
      if (halfDay) return 0.5;

      // Parse dates for calculation
      const parseDate = (dateStr) => {
        // Handle DD-MM-YYYY format
        if (dateStr.match(/^\d{2}-\d{2}-\d{4}$/)) {
          const parts = dateStr.split('-');
          return new Date(parts[2], parts[1] - 1, parts[0]);
        }
        // Handle YYYY-MM-DD format
        if (dateStr.match(/^\d{4}-\d{2}-\d{2}$/)) {
          return new Date(dateStr);
        }
        return new Date(dateStr);
      };

      const start = parseDate(formattedStartDate);
      const end = parseDate(formattedEndDate);
      const timeDiff = Math.abs(end.getTime() - start.getTime());
      return Math.ceil(timeDiff / (1000 * 3600 * 24)) + 1;
    };

    const updatedDays = calculateDays();

    // 4. Update leave in employee_leave_details table - ADD half_day and half_day_type
    const updateQuery = `
      UPDATE employee_leave_details 
      SET 
        leave_type = $1,
        from_date = $2,
        to_date = $3,
        reason = $4,
        half_day = $5,
        half_day_type = $6
      WHERE sr_no = $7
      RETURNING *
    `;

    const values = [
      leaveType,
      formattedStartDate,  // Use formatted date (DD-MM-YYYY)
      formattedEndDate,    // Use formatted date (DD-MM-YYYY)
      reason,
      halfDay,
      halfDayType,
      id
    ];

    console.log('Update query values:', values);

    const result = await pool.query(updateQuery, values);
    const updatedLeave = result.rows[0];

    // Add days to the updatedLeave object for email
    updatedLeave.days = updatedDays;

    console.log('Updated leave record:', updatedLeave);

    // 5. Format dates for email (use original input format)
    const formatForEmail = (dateStr) => {
      if (!dateStr) return dateStr;

      // If already in YYYY-MM-DD, convert to readable format
      if (dateStr.match(/^\d{4}-\d{2}-\d{2}$/)) {
        const parts = dateStr.split('-');
        return `${parts[2]}-${parts[1]}-${parts[0]}`;
      }

      // If in DD-MM-YYYY, return as is
      if (dateStr.match(/^\d{2}-\d{2}-\d{4}$/)) {
        return dateStr;
      }

      return dateStr;
    };

    // Prepare data for email - Include half_day information in both original and updated
    const originalForEmail = {
      ...originalLeave,
      from_date: formatForEmail(originalLeave.from_date),
      to_date: formatForEmail(originalLeave.to_date),
      // Calculate days for original leave
      days: originalLeave.half_day ? 0.5 :
        (() => {
          const parseDate = (dateStr) => {
            if (dateStr.match(/^\d{2}-\d{2}-\d{4}$/)) {
              const parts = dateStr.split('-');
              return new Date(parts[2], parts[1] - 1, parts[0]);
            }
            return new Date(dateStr);
          };
          const start = parseDate(originalLeave.from_date);
          const end = parseDate(originalLeave.to_date);
          const timeDiff = Math.abs(end.getTime() - start.getTime());
          return Math.ceil(timeDiff / (1000 * 3600 * 24)) + 1;
        })()
    };

    const updatedForEmail = {
      ...updatedLeave,
      from_date: formattedStartDate, // Already in DD-MM-YYYY format
      to_date: formattedEndDate,     // Already in DD-MM-YYYY format
      days: updatedDays,
      half_day: halfDay,
      half_day_type: halfDayType
    };

    // 6. Send email notification in background
    sendLeaveUpdateEmail(originalForEmail, updatedForEmail, req.user.emp_name || req.user.email_id)
      .then(success => {
        if (success) {
          console.log('Leave update email sent successfully');
        } else {
          console.log('Failed to send leave update email');
        }
      })
      .catch(err => {
        console.error('Error in leave update email process:', err);
      });

    res.status(200).json({
      message: 'Leave request updated successfully',
      leave: updatedLeave  // This will have dates in DD-MM-YYYY format
    });
  } catch (error) {
    console.error('Error updating leave:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({ error: 'Failed to update leave request' });
  }
});

// Format days - Updated to include half-day type
const formatDays = (days, halfDay = false, halfDayType = 'first') => {
  const numDays = Number(days); // Convert to number first

  // If it's a half day
  if (halfDay && numDays === 0.5) {
    const halfType = halfDayType === 'first' ? 'First Half' : 'Second Half';
    return `0.5 (Half Day - ${halfType})`;
  }

  // If days is a whole number, show without decimal
  if (Number.isInteger(numDays)) {
    return numDays.toString();
  }

  // For other decimal values, show with 1 decimal place
  return numDays.toFixed(1);
};

// Function to send leave update email - Updated for half-day support
const sendLeaveUpdateEmail = async (originalLeave, updatedLeave, updatedByName) => {
  try {
    // Parse recipients (use same as other emails)
    const toRecipients = manager_mail_id.split(',').map(email => email.trim());
    const ccRecipients = pcs_row_mail_id.split(',').map(email => email.trim());

    // Helper function to parse dates in multiple formats
    const parseDate = (dateStr) => {
      if (!dateStr || typeof dateStr !== 'string') return null;

      dateStr = dateStr.trim();

      // Try YYYY-MM-DD format
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const [year, month, day] = dateStr.split('-').map(Number);
        return new Date(year, month - 1, day);
      }

      // Try DD-MM-YYYY format
      if (/^\d{2}-\d{2}-\d{4}$/.test(dateStr)) {
        const [day, month, year] = dateStr.split('-').map(Number);
        return new Date(year, month - 1, day);
      }

      // Try parsing as-is
      const date = new Date(dateStr);
      return !isNaN(date.getTime()) ? date : null;
    };

    // Format dates for display
    const formatDate = (dateString) => {
      const date = parseDate(dateString);
      if (!date) return 'Invalid Date';
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    };

    // Format leave type
    const formatLeaveType = (type) => {
      const typeMap = {
        sick: 'Sick Leave',
        privileged: 'Privileged Leave',
        casual: 'Casual Leave',
        comp_off: 'Comp Off',
        leave_without_pay: 'Leave Without Pay',
        maternity: 'Maternity Leave',
        paternity: 'Paternity Leave'
      };
      return typeMap[type] || type;
    };

    // Create email body - Updated to show half-day information
    const emailBody = `
Hi Team,

I would like to request an update to my previously applied leave. Please find the revised details below:

Original Leave Details:

Employee ID: ${originalLeave.emp_id}
Employee Name: ${originalLeave.emp_name || 'N/A'}
Leave Type: ${formatLeaveType(originalLeave.leave_type)}
Leave Period: ${formatDate(originalLeave.from_date)} to ${formatDate(originalLeave.to_date)}
Number of Days: ${formatDays(originalLeave.days, originalLeave.half_day, originalLeave.half_day_type)}
Reason: ${originalLeave.reason}
Contact During Leave: ${originalLeave.contact_during_leave || 'Not provided'}

Updated Leave Details:

Leave Type: ${formatLeaveType(updatedLeave.leave_type)}
Leave Period: ${formatDate(updatedLeave.from_date)} to ${formatDate(updatedLeave.to_date)}
Number of Days: ${formatDays(updatedLeave.days, updatedLeave.half_day, updatedLeave.half_day_type)}
Reason: ${updatedLeave.reason}
Contact During Leave: ${updatedLeave.contact_during_leave || 'Not provided'}

Kindly consider the above changes and update the leave request accordingly.

Please let me know if any further information is required from my end.

Thank you for your support.

Thanks & Regards,
POC Bot

---
Note: This leave was updated by ${updatedByName}
    `;

    // Email options
    const mailOptions = {
      from: `"POC Bot" <${emailConfig.auth.user}>`,
      to: manager_mail_id,
      cc: pcs_row_mail_id,
      subject: 'Request to Update Applied Leave',
      text: emailBody,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
          <p>Hi Team,</p>
          
          <p>I would like to request an update to my previously applied leave. Please find the revised details below:</p>
          
          <h4 style="color: #333; margin: 20px 0 10px 0;">Original Leave Details:</h4>
          <table style="border-collapse: collapse; margin: 0 0 20px 0; width: 100%;">
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd; width: 30%;"><strong>Employee ID:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd; width: 70%;">${originalLeave.emp_id}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Employee Name:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${originalLeave.emp_name || 'N/A'}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Leave Type:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatLeaveType(originalLeave.leave_type)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Leave Period:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatDate(originalLeave.from_date)} to ${formatDate(originalLeave.to_date)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Number of Days:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatDays(originalLeave.days, originalLeave.half_day, originalLeave.half_day_type)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Reason:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${originalLeave.reason}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Contact During Leave:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${originalLeave.contact_during_leave || 'Not provided'}</td>
            </tr>
          </table>
          
          <h4 style="color: #333; margin: 20px 0 10px 0;">Updated Leave Details:</h4>
          <table style="border-collapse: collapse; margin: 0 0 20px 0; width: 100%;">
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd; width: 30%;"><strong>Leave Type:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd; width: 70%;">${formatLeaveType(updatedLeave.leave_type)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Leave Period:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatDate(updatedLeave.from_date)} to ${formatDate(updatedLeave.to_date)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Number of Days:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatDays(updatedLeave.days, updatedLeave.half_day, updatedLeave.half_day_type)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Reason:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${updatedLeave.reason}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Contact During Leave:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${updatedLeave.contact_during_leave || 'Not provided'}</td>
            </tr>
          </table>
          
          <p>Kindly consider the above changes and update the leave request accordingly.</p>
          
          <p>Please let me know if any further information is required from my end.</p>
          
          <p>Thank you for your support.</p>
          
          <br>
            <font face='Cambria' color='#003b94'>
              <p>Thanks & Regards,</p>
            </font>
            <font face='Cambria' color='#ff9100'>
              <p>POC BOT</p>
            </font>
          <i>
            <font face="Calibri" size="3" color="#003b94">
              ------------------------------------------------------------------<br>
              This is BOT generated email, please do not reply
            </font>
          </i>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="font-size: 12px; color: #666;">
            Note: This leave was updated by <strong>${updatedByName}</strong>
          </p>
        </div>
      `
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log('Leave update email sent:', info.messageId);
    return true;

  } catch (error) {
    console.error('Error sending leave update email:', error);
    return false;
  }
};



// 4. Delete (Revoke) leave request (DELETE)
app.delete('/poc/leave/delete/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const emp_id = req.user.emp_id;

    // Get data from request body
    const { revokeMessage, employeeName, revokedByName } = req.body || {};

    // 1. Check if leave exists
    const leaveQuery = `
      SELECT sr_no, emp_id, emp_name, leave_type, from_date, to_date, reason,
             half_day, half_day_type
      FROM employee_leave_details WHERE sr_no = $1
    `;
    const leaveResult = await pool.query(leaveQuery, [id]);

    if (leaveResult.rowCount === 0) {
      return res.status(404).json({ error: 'Leave request not found' });
    }

    const leave = leaveResult.rows[0];

    // 2. Check if user can delete this leave
    if (leave.emp_id === emp_id) {
      // User owns the leave - allow delete
    } else {
      // User doesn't own the leave - check if they have all_status_access
      const permissionsQuery = `
        SELECT all_status_access 
        FROM user_permissions 
        WHERE emp_id = $1
      `;
      const permissionsResult = await pool.query(permissionsQuery, [emp_id]);

      if (permissionsResult.rowCount === 0 || !permissionsResult.rows[0].all_status_access) {
        return res.status(403).json({
          error: 'Not authorized to delete this leave'
        });
      }
    }

    // Calculate days based on half_day flag
    const calculateDays = () => {
      if (leave.half_day) return 0.5;

      const parseDate = (dateStr) => {
        if (!dateStr) return new Date();

        // Handle DD-MM-YYYY format
        if (dateStr.match(/^\d{2}-\d{2}-\d{4}$/)) {
          const parts = dateStr.split('-');
          return new Date(parts[2], parts[1] - 1, parts[0]);
        }

        // Handle YYYY-MM-DD format
        if (dateStr.match(/^\d{4}-\d{2}-\d{2}$/)) {
          return new Date(dateStr);
        }

        return new Date(dateStr);
      };

      const start = parseDate(leave.from_date);
      const end = parseDate(leave.to_date);
      const timeDiff = Math.abs(end.getTime() - start.getTime());
      return Math.ceil(timeDiff / (1000 * 3600 * 24)) + 1;
    };

    const days = calculateDays();

    // 3. Log the revoke message before deleting
    console.log('=== LEAVE REVOKE LOG ===');
    console.log('Timestamp:', new Date().toISOString());
    console.log('Revoked By User ID:', emp_id);
    console.log('Revoked By Name:', revokedByName || 'Unknown');
    console.log('Leave Details:', {
      leaveId: id,
      employeeId: leave.emp_id,
      employeeName: employeeName || leave.emp_name || 'Unknown',
      leaveType: leave.leave_type,
      startDate: leave.from_date,
      endDate: leave.to_date,
      reason: leave.reason,
      halfDay: leave.half_day,
      halfDayType: leave.half_day_type,
      days: days
    });

    if (revokeMessage && revokeMessage.trim() !== '') {
      console.log('Revoke Message:', revokeMessage);
    } else {
      console.log('Revoke Message: [No message provided]');
    }

    console.log('=== END REVOKE LOG ===');

    // 4. Send email notification
    sendRevokeEmail({
      sr_no: leave.sr_no,
      emp_id: leave.emp_id,
      emp_name: employeeName || leave.emp_name || 'Unknown',
      leave_type: leave.leave_type,
      from_date: leave.from_date,
      to_date: leave.to_date,
      reason: leave.reason,
      half_day: leave.half_day,
      half_day_type: leave.half_day_type,
      contact_during_leave: leave.contact_during_leave,
      days: days
    }, emp_id, revokeMessage)
      .then(success => {
        if (success) {
          console.log('Revoke email notification sent successfully');
        } else {
          console.log('Failed to send revoke email notification');
        }
      })
      .catch(err => {
        console.error('Error in email sending process:', err);
      });

    // 5. Delete leave
    const deleteQuery = `
      DELETE FROM employee_leave_details 
      WHERE sr_no = $1
      RETURNING sr_no
    `;

    const result = await pool.query(deleteQuery, [id]);

    res.status(200).json({
      message: 'Leave request revoked successfully'
    });
  } catch (error) {
    console.error('Error revoking leave:', error);
    res.status(500).json({ error: 'Failed to revoke leave request' });
  }
});

// Helper function to send email
const sendRevokeEmail = async (leaveDetails, revokerId, revokeMessage) => {
  try {
    // Parse recipients
    const toRecipients = manager_mail_id.split(',').map(email => email.trim());
    const ccRecipients = pcs_row_mail_id.split(',').map(email => email.trim());

    // Helper function to parse dates in multiple formats
    const parseDate = (dateStr) => {
      if (!dateStr || typeof dateStr !== 'string') return null;

      dateStr = dateStr.trim();

      // Try YYYY-MM-DD format
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const [year, month, day] = dateStr.split('-').map(Number);
        return new Date(year, month - 1, day);
      }

      // Try DD-MM-YYYY format
      if (/^\d{2}-\d{2}-\d{4}$/.test(dateStr)) {
        const [day, month, year] = dateStr.split('-').map(Number);
        return new Date(year, month - 1, day);
      }

      // Try parsing as-is
      const date = new Date(dateStr);
      return !isNaN(date.getTime()) ? date : null;
    };

    // Format dates for display
    const formatDate = (dateString) => {
      const date = parseDate(dateString);
      if (!date) return 'Invalid Date';
      return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      });
    };

    // Format leave type
    const formatLeaveType = (type) => {
      const typeMap = {
        sick: 'Sick Leave',
        privileged: 'Privileged Leave',
        casual: 'Casual Leave',
        comp_off: 'Comp Off',
        leave_without_pay: 'Leave Without Pay',
        maternity: 'Maternity Leave',
        paternity: 'Paternity Leave'
      };
      return typeMap[type] || type;
    };

    // Format days with half-day information
    const formatDays = (days, halfDay = false, halfDayType = 'first') => {
      const numDays = Number(days);

      if (halfDay && numDays === 0.5) {
        const halfType = halfDayType === 'first' ? 'First Half' : 'Second Half';
        return `0.5 (Half Day - ${halfType})`;
      }

      if (Number.isInteger(numDays)) {
        return numDays.toString();
      }

      return numDays.toFixed(1);
    };

    // Create email body
    const emailBody = `
Hi Team,

I would like to request the revocation of the previously applied leave as per the details below:

Employee ID: ${leaveDetails.emp_id}
Employee Name: ${leaveDetails.emp_name || 'N/A'}
Leave Type: ${formatLeaveType(leaveDetails.leave_type)}
Leave Period: ${formatDate(leaveDetails.from_date)} to ${formatDate(leaveDetails.to_date)}
Number of Days: ${formatDays(leaveDetails.days, leaveDetails.half_day, leaveDetails.half_day_type)}
Contact During Leave: ${leaveDetails.contact_during_leave || 'Not provided'}
Reason for Revocation: ${revokeMessage || 'No reason provided'}

Kindly revoke the above-mentioned leave request at your convenience.

Please let me know if any further information is required from my end.

Thank you for your support.

 
    Thanks & Regards,
    POC Bot

---
Note: This leave was revoked by User ID: ${revokerId}
    `;

    // Email options
    const mailOptions = {
      from: `"POC Bot" <${emailConfig.auth.user}>`,
      to: manager_mail_id,
      cc: pcs_row_mail_id,
      subject: 'Request to Revoke Leave Application',
      text: emailBody,
      html: `
        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
          <p>Hi Team,</p>
          
          <p>I would like to request the revocation of the previously applied leave as per the details below:</p>
          
          <table style="border-collapse: collapse; margin: 20px 0;">
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd; width: 30%;"><strong>Employee ID:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd; width: 70%;">${leaveDetails.emp_id}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Employee Name:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${leaveDetails.emp_name || 'N/A'}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Leave Type:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatLeaveType(leaveDetails.leave_type)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Leave Period:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatDate(leaveDetails.from_date)} to ${formatDate(leaveDetails.to_date)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Number of Days:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${formatDays(leaveDetails.days, leaveDetails.half_day, leaveDetails.half_day_type)}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Contact During Leave:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${leaveDetails.contact_during_leave || 'Not provided'}</td>
            </tr>
            <tr>
              <td style="padding: 8px; border: 1px solid #ddd;"><strong>Reason for Revocation:</strong></td>
              <td style="padding: 8px; border: 1px solid #ddd;">${revokeMessage || 'No reason provided'}</td>
            </tr>
          </table>
          
          <p>Kindly revoke the above-mentioned leave request at your convenience.</p>
          
          <p>Please let me know if any further information is required from my end.</p>
          
          <p>Thank you for your support.</p>
          
           <br>
            <font face='Cambria' color='#003b94'>
              <p>Thanks & Regards,</p>
            </font>
            <font face='Cambria' color='#ff9100'>
              <p>POC BOT</p>
            </font>
          <i>
            <font face="Calibri" size="3" color="#003b94">
              ------------------------------------------------------------------<br>
              This is BOT generated email, please do not reply
            </font>
          </i>
          
          <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
          <p style="font-size: 12px; color: #666;">
            Note: This leave was revoked by User ID: ${revokerId}
          </p>
        </div>
      `
    };

    // Send email
    const info = await transporter.sendMail(mailOptions);
    console.log('Revoke email sent:', info.messageId);
    return true;

  } catch (error) {
    console.error('Error sending revoke email:', error);
    return false;
  }
};




////-----------------------salesss

app.get("/poc/sales/all", authenticateToken, async (req, res) => {
  try {
    const empName = req.user.emp_name;
    const role = req.user.role;
    const empId = req.user.emp_id;

    console.log("EMP:", empName, "ROLE:", role, "EMP_ID:", empId);

    // First, get the user's permissions to check all_sales_access
    let allSalesAccess = false;
    try {
      const permQuery = `
        SELECT all_sales_access 
        FROM public.user_permissions 
        WHERE emp_id = $1
      `;
      const permResult = await pool.query(permQuery, [empId]);
      if (permResult.rows.length > 0) {
        allSalesAccess = permResult.rows[0].all_sales_access || false;
      }
    } catch (permErr) {
      console.error("Error fetching permissions:", permErr);
      // Continue without permissions - defaults to false
    }

    console.log("All Sales Access:", allSalesAccess);

    const result = await pool.query(`
      SELECT 
        p.poc_prj_id            AS "pocId",
        p.poc_prj_name          AS "pocName",
        p.client_name           AS "entityName",
        p.partner_client_own    AS "entityType",
        p.sales_person          AS "salesPerson",
        p.region,
        p.status,
        p.start_date            AS "startDate",
        p.excepted_end_date     AS "endDate",
        p.actual_start_date     AS "actualStartDate",
        p.actual_end_date       AS "actualEndDate",
        p.poc_type              AS "pocType",
        p.description,
        p.spoc_email_address    AS "spocEmail",
        p.spoc_designation      AS "spocDesignation",
        p.tag                   AS "tags",
        p.assigned_to           AS "assignedTo",
        p.created_by            AS "createdBy",
        p.remarks               AS "remark",
        p.estimated_efforts     AS "estimatedEfforts",
        p.approved_by           AS "approvedBy",
        p.total_efforts         AS "totalEfforts",
        p.partner_name          AS "partnerName",

        COALESCE((
          SELECT SUM(
            CASE 
              WHEN hrs ~ '^[0-9]+:[0-9]+$' 
                THEN split_part(hrs, ':', 1)::int
                   + split_part(hrs, ':', 2)::int / 60.0
              WHEN hrs ~ '^[0-9]+$'
                THEN hrs::int
              ELSE 0
            END
          )
          FROM public.daily_poc_prj_status d 
          WHERE d.poc_prj_id = p.poc_prj_id::text
        ), 0) AS "totalWorkedHours"

      FROM public.poc_prj_sales_details p
      WHERE (
        $2 IN ('ADMIN', 'Department Admin')
        OR $3 = true  -- all_sales_access permission
        OR p.created_by = $1
        OR $1 = ANY (
          SELECT trim(x)
          FROM unnest(string_to_array(p.assigned_to, ',')) AS x
        )
      )
      ORDER BY p.poc_prj_id DESC
    `, [empName, role, allSalesAccess]);

    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching Sales Usecases:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});




async function generateNextsales(prefix) {
  try {
    // Convert prefix to lowercase for case-insensitive comparison
    const prefixLower = prefix.toLowerCase();

    const result = await pool.query(
      `SELECT poc_prj_id 
       FROM public.poc_prj_sales_details
       WHERE LOWER(poc_prj_id) LIKE $1`,
      [prefixLower + "-%"]
    );

    console.log('🔍 DEBUG generateNextPocId:');
    console.log('Original Prefix:', prefix);
    console.log('Lowercase Prefix:', prefixLower);
    console.log('Found existing IDs:', result.rows);

    if (result.rows.length === 0) {
      return `${prefix}-01`;
    }

    let highestNumber = 0;

    // Find the highest number among ALL matching IDs
    for (const row of result.rows) {
      const id = row.poc_prj_id;
      const match = id.match(/-(\d+)$/i);

      if (match) {
        const num = parseInt(match[1], 10);
        if (!isNaN(num) && num > highestNumber) {
          highestNumber = num;
        }
      }
    }

    const nextNumber = highestNumber + 1;

    // Use appropriate padding based on the number size
    const nextId = highestNumber >= 100 ?
      `${prefix}-${nextNumber}` :
      `${prefix}-${nextNumber.toString().padStart(2, '0')}`;

    console.log('Highest number found:', highestNumber);
    console.log('Next number:', nextNumber);
    console.log('Generated next ID:', nextId);

    return nextId;

  } catch (error) {
    console.error('Error generating next POC ID:', error);
    return `${prefix}-01`;
  }
}
app.post("/poc/sales/savepocprjid", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    /* =========================
       🔹 FRONTEND PAYLOAD
       ========================= */
    const {
      pocId,
      pocName,
      entityName,
      entityType,
      salesPerson,
      region,
      startDate,
      endDate,
      actualStartDate,
      actualEndDate,
      pocType,
      description,
      spocEmail,
      spocDesignation,
      tags,
      assignedTo,
      createdBy,
      remark,
      estimatedEfforts,
      approvedBy,
      totalEfforts,
      partnerName
    } = req.body;

    console.log("Incoming payload:", req.body);

    /* =========================
       🔁 MAP → DB FIELDS
       ========================= */
    const poc_prj_name = pocName;
    const client_name = entityName;
    const partner_client_own = entityType;
    const sales_person = salesPerson;
    const start_date = startDate;
    const excepted_end_date = endDate;
    const actual_start_date = actualStartDate || null;
    const actual_end_date = actualEndDate || null;
    const poc_type = pocId;
    const spoc_email_address = spocEmail;
    const spoc_designation = spocDesignation;
    const tag = tags;
    const assigned_to = assignedTo;
    const created_by = createdBy;
    const remarks = remark;
    const partner_name = partnerName;

    await client.query("BEGIN");

    /* =========================
       🔹 INSERT QUERY
       ========================= */
    const insertQuery = `
      INSERT INTO public.poc_prj_sales_details (
        poc_prj_name,
        client_name,
        partner_client_own,
        sales_person,
        region,
        status,
        start_date,
        excepted_end_date,
        actual_start_date,
        actual_end_date,
        poc_type,
        description,
        spoc_email_address,
        spoc_designation,
        tag,
        assigned_to,
        created_by,
        remarks,
        estimated_efforts,
        approved_by,
        total_efforts,
        partner_name,
        created_at,
        updated_at
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,
        $7,$8,$9,$10,
        $11,$12,$13,$14,
        $15,$16,$17,$18,
        $19,$20,$21,$22,
        NOW(), NOW()
      )
      RETURNING *;
    `;

    const values = [
      poc_prj_name,          // $1
      client_name,           // $2
      partner_client_own,    // $3
      sales_person,          // $4
      region,                // $5
      "Draft",               // $6
      start_date,            // $7
      excepted_end_date,     // $8
      actual_start_date,     // $9
      actual_end_date,       // $10
      poc_type,              // $11
      description,           // $12
      spoc_email_address,    // $13
      spoc_designation,      // $14
      tag,                   // $15
      assigned_to,           // $16
      created_by,            // $17
      remarks,               // $18
      estimatedEfforts || null, // $19
      approvedBy || null,       // $20
      totalEfforts || null,     // $21
      partner_name            // $22
    ];

    const result = await client.query(insertQuery, values);

    await client.query("COMMIT");

    res.status(201).json({
      message: "POC saved successfully",
      data: result.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error saving POC:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});



app.get("/poc/sales/getAllAssignTo", authenticateToken, async (req, res) => {
  const { department_name } = req.query;
  const role = req.user.role;

  try {

    let query = `
      SELECT sr_no, emp_id, emp_name, email_id
      FROM emp_details
      WHERE status = 'Active'
        AND emp_id NOT IN ('AE0007', 'AE0201', 'AE0751')
    `;

    const params = [];

    // 🔐 Apply department filter ONLY for non-admin roles
    if (!['ADMIN', 'Department Admin'].includes(role)) {
      if (!department_name) {
        return res.status(400).json({ message: "department_name is required" });
      }
      query += ` AND department_name = $1`;
      params.push(department_name);
    }

    query += ` ORDER BY emp_name`;

    const result = await pool.query(query, params);

    const employees = result.rows.map(row => ({
      id: row.sr_no,
      empId: row.emp_id,
      emp_name: row.emp_name,
      email: row.email_id
    }));

    res.json(employees);

  } catch (err) {
    console.error("Error fetching assignTo list:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.put("/poc/sales/updateStatus/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    console.log("Update Status Request:", { id, status });

    // 🔹 Validate required fields
    if (!status) {
      return res.status(400).json({ message: "Status is required" });
    }

    // 🔹 Validate allowed status values
    const validStatuses = [
      'Pending',
      'In Progress',
      'Completed',
      'Dropped',
      'Draft',
      'Awaiting',
      'Hold',
      'Closed',
      'Converted',
      'Live'
    ];

    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        message: "Invalid status value",
        validStatuses
      });
    }

    // 🔹 UPDATE correct table + updated_at
    const updateQuery = `
      UPDATE public.poc_prj_sales_details
      SET
        status = $1,
        updated_at = NOW()
      WHERE poc_prj_id::text = $2
      RETURNING
        poc_prj_id,
        poc_prj_name,
        status,
        updated_at
    `;

    const result = await pool.query(updateQuery, [status, id]);

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "POC not found with ID: " + id
      });
    }

    res.json({
      success: true,
      message: "Status updated successfully",
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Error updating POC status:", err);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message
    });
  }
});

app.put('/poc/sales/updateRemark/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { remark } = req.body;

    // Simple update without updated_at column
    const updateQuery = `
            UPDATE poc_prj_sales_details 
            SET remarks = $1
            WHERE poc_prj_id::text = $2
            RETURNING poc_prj_id, poc_prj_name, remarks
        `;

    const result = await pool.query(updateQuery, [remark, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "POC not found with ID: " + id });
    }

    res.json({
      success: true,
      message: "Remark updated successfully",
      data: result.rows[0]
    });

  } catch (err) {
    console.error("Error updating POC remark:", err);
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: err.message
    });
  }
});
app.delete("/poc/sales/delete/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    // Start transaction
    await client.query("BEGIN");

    // ✅ Delete ONLY from poc_prj_sales_details
    const result = await client.query(
      `DELETE FROM poc_prj_sales_details 
       WHERE poc_prj_id::text = $1 
       RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "POC not found in sales table" });
    }

    // Commit transaction
    await client.query("COMMIT");

    res.json({
      message: "POC sales record deleted successfully",
      deletedRecord: result.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error deleting POC sales record:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});
app.put("/poc/sales/update/:id", authenticateToken, async (req, res) => {
  try {
    // 🔹 POC ID must be INTEGER
    const id = parseInt(req.params.id, 10);

    if (isNaN(id)) {
      return res.status(400).json({ message: "Invalid POC ID" });
    }

    const {
      pocName,
      entityName,
      entityType,
      salesPerson,
      region,

      status,
      startDate,
      endDate,
      pocType,
      description,
      spocEmail,
      spocDesignation,
      tags,
      assignedTo,
      remark,
      actualStartDate,
      actualEndDate,
      estimatedEfforts,
      approvedBy,
      totalEfforts,
      partnerName
    } = req.body;

    // 🔹 Normalize billable (boolean or string)


    const updateQuery = `
      UPDATE public.poc_prj_sales_details
      SET
        poc_prj_name        = $1,
        client_name         = $2,
        partner_client_own  = $3,
        sales_person        = $4,
        region              = $5,
        status              = $6,
        start_date          = $7,
        excepted_end_date   = $8,
        poc_type            = $9,
        description         = $10,
        spoc_email_address  = $11,
        spoc_designation    = $12,
        tag                 = $13,
        assigned_to         = $14,
        remarks             = $15,
        actual_start_date   = $16,
        actual_end_date     = $17,
        estimated_efforts   = $18,
        approved_by         = $19,
        total_efforts       = $20,
        partner_name        = $21,
        updated_at          = NOW()
      WHERE poc_prj_id = $22
      RETURNING *
    `;

    const values = [
      pocName || null,
      entityName || null,
      entityType || null,
      salesPerson || null,
      region || null,
      status || null,
      startDate || null,
      endDate || null,
      pocType || null,
      description || null,
      spocEmail || null,
      spocDesignation || null,
      tags || null,
      assignedTo || null,
      remark || null,
      actualStartDate || null,
      actualEndDate || null,
      estimatedEfforts || null,
      approvedBy || null,
      totalEfforts || null,
      partnerName || null,
      id
    ];

    const result = await pool.query(updateQuery, values);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: "POC not found" });
    }

    res.json({
      success: true,
      message: "POC updated successfully",
      poc: result.rows[0]
    });

  } catch (err) {
    console.error("Error updating POC:", err);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

app.get("/poc/sales/getUsecases", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        poc_prj_id            AS "pocId",
        poc_prj_name          AS "pocName",
        client_name           AS "clientName",
        partner_client_own    AS "entityType",
        sales_person          AS "salesPerson",
        region,
        status,
        start_date            AS "startDate",
        excepted_end_date     AS "endDate",
        poc_type              AS "pocType",
        description,
        spoc_email_address    AS "spocEmail",
        spoc_designation      AS "spocDesignation",
        tag                   AS "tags",
        assigned_to           AS "assignedTo",
        created_by            AS "createdBy",
        remarks               AS "remark",
        estimated_efforts     AS "estimatedEfforts",
        approved_by           AS "approvedBy",
        total_efforts         AS "totalEfforts",
        partner_name          AS "partnerName",
        created_at            AS "createdAt",
        updated_at            AS "updatedAt"
      FROM public.poc_prj_sales_details
     
    `);
    //   WHERE status = 'In Progress'
    // ORDER BY poc_prj_name
    // console.log(result.rows)
    res.json(result.rows);

  } catch (err) {
    console.error("Error fetching usecases:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
app.get("/poc/sales/getLeads", authenticateToken, async (req, res) => {
  try {
    const departmentName = req.user.department_name;

    if (!departmentName) {
      return res.status(400).json({
        message: "Department not found in token"
      });
    }

    console.log('Fetching leads for department:', departmentName);

    const result = await pool.query(
      `
      SELECT
        lead_name,
        department_name,
        employee_name
      
      FROM public.lead_details
      WHERE
        lead_status = 'Active'
        AND department_name = $1
      ORDER BY lead_name
      `,
      [departmentName]
    );

    console.log('Leads found:', result.rows.length);
    console.log(result.rows)
    res.json(result.rows);

  } catch (err) {
    console.error("Error fetching leads:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  }
});
app.post("/poc/sales/saveDailyStatus", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const {
      date,
      usecaseId,
      leadIds,
      status,
      workingHours,
      workingMinutes,
      description,
      employeeId,
      employeeName,
      usecaseName,
      leadNames
    } = req.body;

    // 🔹 Build "HH:MM" string for hrs
    const formattedHrs = `${String(workingHours || 0).padStart(2, "0")}:${String(workingMinutes || 0).padStart(2, "0")}`;

    console.log("Formatted hrs:", formattedHrs);

    await client.query("BEGIN");

    const insertStatusQuery = `
      INSERT INTO public.sales_daily_status (
        emp_name, emp_id, poc_prj_id, poc_date,
        status, hrs, leads_email, department_name
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,'PCS ROW')
      RETURNING *;
    `;

    const result = await client.query(insertStatusQuery, [
      employeeName,   // emp_name
      employeeId,     // emp_id
      usecaseId,      // poc_prj_id
      date,           // poc_date
      description,         // status
      formattedHrs,   // hrs in HH:MM
      leadIds         // leads_email (comma separated)
    ]);

    await client.query("COMMIT");

    res.status(201).json({
      message: "Daily POC status saved successfully",
      data: result.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error saving daily POC status:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});
app.put("/poc/sales/empupdateStatus/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const {
      employeeName,
      empName,
      employeeId,
      empId,
      usecaseId,
      pocPrjId,
      date,
      pocDate,
      status,
      workingHours,
      workingMinutes,
      leadIds,
      description,
      leadsEmail,
      departmentName
    } = req.body;

    console.log("Update Daily Status Payload:", req.body);

    // hrs -> HH:MM
    const hrs = `${workingHours || "0"}:${workingMinutes || "00"}`;

    await client.query("BEGIN");

    const updateQuery = `
      UPDATE public.sales_daily_status
      SET poc_prj_id     = COALESCE($1, poc_prj_id),
          poc_date       = COALESCE($2::date, poc_date),
          status         = COALESCE($3, status),
          hrs            = COALESCE($4, hrs),
          leads_email    = COALESCE($5, leads_email),
          department_name= COALESCE($6, department_name)
      WHERE id = $7
      RETURNING *;
    `;

    const result = await client.query(updateQuery, [
      usecaseId ?? pocPrjId ?? null,
      date ?? pocDate ?? null,
      description ?? status ?? null,  // Use description from frontend, fallback to status
      hrs ?? null,
      leadIds ?? leadsEmail ?? null,
      departmentName ?? null,
      id
    ]);

    await client.query("COMMIT");

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Status not found" });
    }

    res.status(200).json({
      message: "Daily POC status updated successfully",
      data: result.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error updating daily POC status:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});

app.delete("/poc/sales/deleteStatus/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    console.log(id);
    await client.query("BEGIN");

    // Optional: check if the status exists
    const checkResult = await client.query(
      "SELECT * FROM public.sales_daily_status WHERE id = $1",
      [id]
    );

    if (checkResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "Status not found" });
    }

    // Delete the status
    const deleteResult = await client.query(
      "DELETE FROM public.sales_daily_status WHERE id = $1 RETURNING *",
      [id]
    );

    await client.query("COMMIT");

    res.status(200).json({
      message: "Daily POC status deleted successfully",
      data: deleteResult.rows[0]
    });

  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Error deleting daily POC status:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});
app.get("/poc/sales/getStatusByDate", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { date } = req.query;
    const employeeId = req.user.emp_id;

    const permissionQuery = `
      SELECT all_status_access 
      FROM public.user_permissions 
      WHERE emp_id = $1;
    `;

    const permissionResult = await client.query(permissionQuery, [employeeId]);
    const hasAllStatusAccess = permissionResult.rows.length > 0 && permissionResult.rows[0].all_status_access === true;

    let query;
    let queryParams;

    if (hasAllStatusAccess) {
      query = `
        SELECT 
          id,
          emp_name AS "employeeName",
          emp_id AS "employeeId",
          poc_prj_id AS "usecaseId",
          poc_date AS "date",
          status AS "description",
          status,
          hrs,
          leads_email AS "leadIds",
          department_name AS "departmentName"
        FROM public.sales_daily_status
        WHERE poc_date = $1
        ORDER BY id DESC;
      `;
      queryParams = [date];
    } else {
      query = `
        SELECT 
          id,
          emp_name AS "employeeName",
          emp_id AS "employeeId",
          poc_prj_id AS "usecaseId",
          poc_date AS "date",
          status AS "description",
          status,
          hrs,
          leads_email AS "leadIds",
          department_name AS "departmentName"
        FROM public.sales_daily_status
        WHERE poc_date = $1 AND emp_id = $2
        ORDER BY id DESC;
      `;
      queryParams = [date, employeeId];
    }

    const result = await client.query(query, queryParams);

    // ✅ Transform hrs ("HH:MM") → workingHours + workingMinutes
    const formattedRows = result.rows.map((row) => {
      let workingHours = 0;
      let workingMinutes = 0;

      if (row.hrs) {
        const [h, m] = row.hrs.split(":");
        workingHours = parseInt(h, 10);
        workingMinutes = parseInt(m, 10);
      }

      // Get usecase name from usecases table or use the ID
      const usecaseName = row.usecaseId; // You might want to join with usecases table to get the actual name

      return {
        id: row.id,
        date: row.date,
        usecaseName: usecaseName, // This should match what frontend expects
        usecaseId: row.usecaseId,
        leadName: row.leadNames || '',
        leadIds: row.leadIds ? row.leadIds.split(",") : [],
        status: row.status,
        workingHours: workingHours,
        workingMinutes: workingMinutes,
        description: row.description || "",
        employeeName: row.employeeName,
        employeeId: row.employeeId,
        departmentName: row.departmentName,
        // Include permission info
        hasAllStatusAccess: hasAllStatusAccess
      };
    });

    res.json(formattedRows);
  } catch (err) {
    console.error("Error fetching status by date:", err);
    res.status(500).json({ message: "Internal server error" });
  } finally {
    client.release();
  }
});





// Admin tab apis 


// In your server.js file
app.get('/poc/admin/getAllUsers', authenticateToken, async (req, res) => {
  try {
    // Verify admin access (you can add additional admin check here)
    const user = req.user;

    // Query to get all users from emp_details table
    const query = `
            SELECT 
                sr_no,
                emp_id,
                emp_name,
                email_id,
                status,
                department_name,
                role,
                password
            FROM emp_details
            Where emp_id NOT IN ('AE0204')
            ORDER BY department_name, emp_name
        `;

    const result = await pool.query(query);

    // Return the users data (excluding password for security)
    const users = result.rows.map(user => ({
      sr_no: user.sr_no,
      emp_id: user.emp_id,
      emp_name: user.emp_name,
      email_id: user.email_id,
      status: user.status || 'Active',
      department_name: user.department_name,
      role: user.role || 'User'
      // Note: password is not included in the response
    }));

    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Add new user
app.post('/poc/admin/createUser', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { emp_id, emp_name, email_id, status, department_name, role, password } = req.body;

    // Validate required fields
    if (!emp_id || !emp_name || !email_id || !password) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Employee ID, Name, Email, and Password are required' });
    }

    // Check if user already exists
    const checkQuery = 'SELECT emp_id FROM emp_details WHERE emp_id = $1 OR email_id = $2';
    const checkResult = await client.query(checkQuery, [emp_id, email_id]);

    if (checkResult.rowCount > 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Employee ID or Email already exists' });
    }

    // Insert new user into emp_details
    const insertUserQuery = `
      INSERT INTO emp_details 
      (emp_id, emp_name, email_id, status, department_name, role, password)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING emp_id, emp_name, email_id, status, department_name, role
    `;

    const userValues = [
      emp_id,
      emp_name,
      email_id,
      status || 'Active',
      department_name,
      role || 'Employee',
      password
    ];

    const userResult = await client.query(insertUserQuery, userValues);

    // Insert default permissions into user_permissions (all false)
    const insertPermissionsQuery = `
      INSERT INTO user_permissions 
      (
        emp_id, 
        dashboard_access, 
        report_access, 
        usecase_creation_access, 
        status_access, 
        sales_access,
        all_status_access,
        sales_admin,
        sales_dashboard_access,
        status_status_access,
        leave_access,
        all_sales_access,
        admin_access
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      RETURNING emp_id
    `;

    const permissionValues = [
      emp_id,                    // $1
      false,                     // $2 dashboard_access
      false,                     // $3 report_access
      false,                     // $4 usecase_creation_access
      false,                     // $5 status_access
      false,                     // $6 sales_access
      false,                     // $7 all_status_access
      false,                     // $8 sales_admin
      false,                     // $9 sales_dashboard_access
      false,                     // $10 status_status_access
      false,                     // $11 leave_access
      false,                     // $12 all_sales_access
      false                      // $13 admin_access
    ];

    await client.query(insertPermissionsQuery, permissionValues);

    await client.query('COMMIT');

    res.status(201).json({
      success: true,
      message: 'User created successfully with default permissions',
      user: userResult.rows[0]
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error creating user:', error);

    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Permissions record already exists or duplicate key',
        details: error.detail
      });
    }

    res.status(500).json({ error: 'Failed to create user' });
  } finally {
    client.release();
  }
});

// Update existing user
app.put('/poc/admin/updateUser', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const { emp_id, emp_name, email_id, status, department_name, role, password } = req.body;

    // Validate required fields
    if (!emp_id) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Employee ID is required' });
    }

    // Check if user exists
    const checkQuery = 'SELECT emp_id FROM emp_details WHERE emp_id = $1';
    const checkResult = await client.query(checkQuery, [emp_id]);

    if (checkResult.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }

    // Build dynamic update query
    let updateFields = [];
    let values = [];
    let paramCount = 1;

    if (emp_name) {
      updateFields.push(`emp_name = $${paramCount}`);
      values.push(emp_name);
      paramCount++;
    }

    if (email_id) {
      updateFields.push(`email_id = $${paramCount}`);
      values.push(email_id);
      paramCount++;
    }

    if (status) {
      updateFields.push(`status = $${paramCount}`);
      values.push(status);
      paramCount++;
    }

    if (department_name) {
      updateFields.push(`department_name = $${paramCount}`);
      values.push(department_name);
      paramCount++;
    }

    if (role) {
      updateFields.push(`role = $${paramCount}`);
      values.push(role);
      paramCount++;
    }

    if (password) {
      updateFields.push(`password = $${paramCount}`);
      values.push(password);
      paramCount++;
    }

    if (updateFields.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'No fields to update' });
    }

    // Add emp_id as last parameter
    values.push(emp_id);

    const updateQuery = `
      UPDATE emp_details 
      SET ${updateFields.join(', ')}
      WHERE emp_id = $${paramCount}
      RETURNING emp_id, emp_name, email_id, status, department_name, role
    `;

    const result = await client.query(updateQuery, values);

    // Check and create permissions using ON CONFLICT DO NOTHING
    const insertPermissionsQuery = `
      INSERT INTO user_permissions 
      (
        emp_id, 
        dashboard_access, 
        report_access, 
        usecase_creation_access, 
        status_access, 
        sales_access,
        all_status_access,
        sales_admin,
        sales_dashboard_access,
        status_status_access,
        leave_access,
        all_sales_access,
        admin_access
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
      ON CONFLICT (emp_id) DO NOTHING
      RETURNING emp_id
    `;

    const permissionValues = [
      emp_id,
      false, false, false, false, false,
      false, false, false, false, false, false, false
    ];

    await client.query(insertPermissionsQuery, permissionValues);

    await client.query('COMMIT');

    res.json({
      success: true,
      message: 'User updated successfully',
      user: result.rows[0]
    });

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error updating user:', error);

    // More specific error handling
    if (error.code === '23505') {
      return res.status(409).json({
        error: 'Permissions record already exists for this user'
      });
    }

    res.status(500).json({ error: 'Failed to update user' });
  } finally {
    client.release();
  }
});

// Add this API endpoint in your server.js
app.post('/poc/admin/updateUserStatus', authenticateToken, async (req, res) => {
  try {
    const { emp_id, status } = req.body;

    if (!emp_id || !status) {
      return res.status(400).json({ error: 'Employee ID and status are required' });
    }

    const validStatuses = ['Active', 'Inactive'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status value' });
    }

    const query = `
            UPDATE emp_details 
            SET status = $1 
            WHERE emp_id = $2 
            RETURNING emp_id, emp_name, status
        `;

    const result = await pool.query(query, [status, emp_id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      success: true,
      message: `User status updated to ${status}`,
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// In your backend (Node.js/Express example)
app.get('/poc/admin/getUserPermissions/:empId', authenticateToken, async (req, res) => {
  try {
    const { empId } = req.params;

    // Query the user_permissions table
    const result = await pool.query(
      'SELECT * FROM user_permissions WHERE emp_id = $1',
      [empId]
    );

    if (result.rows.length === 0) {
      // Return default permissions if no record exists
      return res.json({
        status_access: false,
        report_access: false,
        usecase_creation_access: false,
        all_status_access: false,
        sales_access: false,
        sales_admin: false,
        status_status_access: false,
        sales_dashboard_access: false,
        all_sales_access: false,
        knowledge_base_access: false,
      });
    }

    // Return the existing permissions
    const permissions = result.rows[0];
    res.json({
      status_access: permissions.status_access || false,
      report_access: permissions.report_access || false,
      usecase_creation_access: permissions.usecase_creation_access || false,
      all_status_access: permissions.all_status_access || false,
      sales_access: permissions.sales_access || false,
      sales_admin: permissions.sales_admin || false,
      status_status_access: permissions.status_status_access || false,
      sales_dashboard_access: permissions.sales_dashboard_access || false,
      all_sales_access: permissions.all_sales_access || false,
      knowledge_base_access: permissions.knowledge_base_access || false,
    });

  } catch (error) {
    console.error('Error fetching user permissions:', error);
    res.status(500).json({ error: 'Failed to fetch user permissions' });
  }
});

// In your backend (Node.js/Express example)
app.post('/poc/admin/updateUserPermissions', authenticateToken, async (req, res) => {
  try {
    const {
      emp_id,
      status_access,
      report_access,
      usecase_creation_access,
      all_status_access,
      sales_access,
      sales_admin,
      status_status_access,
      sales_dashboard_access,
      all_sales_access,
      knowledge_base_access,
    } = req.body;

    // Check if permission record exists for this user
    const checkResult = await pool.query(
      'SELECT id FROM user_permissions WHERE emp_id = $1',
      [emp_id]
    );

    if (checkResult.rows.length === 0) {
      // Insert new record
      await pool.query(
        `INSERT INTO user_permissions 
                (emp_id, status_access, report_access, usecase_creation_access, 
                 all_status_access, sales_access, sales_admin, status_status_access, 
                 sales_dashboard_access, all_sales_access, knowledge_base_access,)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          emp_id,
          status_access,
          report_access,
          usecase_creation_access,
          all_status_access,
          sales_access,
          sales_admin,
          status_status_access,
          sales_dashboard_access,
          all_sales_access,
          knowledge_base_access,
        ]
      );
    } else {
      // Update existing record
      await pool.query(
        `UPDATE user_permissions 
                SET status_access = $2,
                    report_access = $3,
                    usecase_creation_access = $4,
                    all_status_access = $5,
                    sales_access = $6,
                    sales_admin = $7,
                    status_status_access = $8,
                    sales_dashboard_access = $9,
                    all_sales_access = $10,
                    knowledge_base_access = $11,
                    updated_at = CURRENT_TIMESTAMP
                WHERE emp_id = $1`,
        [
          emp_id,
          status_access,
          report_access,
          usecase_creation_access,
          all_status_access,
          sales_access,
          sales_admin,
          status_status_access,
          sales_dashboard_access,
          all_sales_access,
          knowledge_base_access,
        ]
      );
    }

    res.json({ success: true, message: 'Permissions updated successfully' });

  } catch (error) {
    console.error('Error updating user permissions:', error);
    res.status(500).json({ error: 'Failed to update user permissions' });
  }
});








// Change this line at the end of server.js
app.listen(PORT, '0.0.0.0', () => {
  console.log(`POC Management server running at http://localhost:${PORT}`);
  console.log(`Also accessible via: http://10.41.11.103:${PORT}`);
});

