// server.js
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import pkg from "pg";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import unirest from 'unirest';

dotenv.config();

const { Pool } = pkg;


const app = express();
const PORT = process.env.PORT || 5050;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Middleware
app.use(cors({
  // origin: "http://mspeventwin1.westus.cloudapp.azure.com" ,// frontend
  origin: ["http://localhost:5173", "http://10.41.11.103:5173","http://localhost:80","http://localhost"],
  credentials: true
}));
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER || "postgres",
  host: process.env.DB_HOST || "localhost",
  // database: process.env.DB_NAME || "statusbot_poc",
  database: process.env.DB_NAME || "msp_db_poc1",
  // password: process.env.DB_PASSWORD || "root",
  password: process.env.DB_PASSWORD || "nitin258",
  // port: process.env.DB_PORT || 5433,
  port: process.env.DB_PORT || 5432,
});

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



// Add this to your server.js
app.get("/poc/api/auth/validate", authenticateToken, (req, res) => {
    res.json({ 
        valid: true, 
        user: req.user 
    });
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



// Get distinct poc types 
app.get("/poc/getPocTypes", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT DISTINCT regexp_replace(poc_prj_id, '[-_].*$', '') AS type
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
        poc_prj_id as id,
        sales_person as "salesPerson",
        region,
        poc_type,
        start_date,
        excepted_end_date,
        client_name as "companyName",
        description as usecase,
        status
      FROM public.poc_prj_details
      ORDER BY start_date DESC
    `);
 
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching reports:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});
 








// ✅ Login API using emp_details table
app.post("/poc/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }

    // Check against emp_details (login by emp_id or email_id)
    const result = await pool.query(
      `SELECT sr_no, emp_id, emp_name, email_id, role, password
       FROM emp_details
       WHERE emp_id = $1 OR email_id = $1`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = result.rows[0];
    const passwordMatch = (password === user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Generate JWT
    const token = jwt.sign(
      { sr_no: user.sr_no, emp_id: user.emp_id, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: {
        sr_no: user.sr_no,
        emp_id: user.emp_id,
        emp_name: user.emp_name,
        email_id: user.email_id,
        role: user.role
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Internal server error" });
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
        e.variance_days as "varianceDays"
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
      estimatedEfforts, approvedBy, totalEfforts, varianceDays
    } = req.body;

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
        variance_days = $6
      WHERE poc_prj_id::text = $7
      RETURNING *
    `;

    const effortsValues = [
      actualStartDate, actualEndDate, estimatedEfforts,
      approvedBy, totalEfforts, varianceDays, id
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
        where status = 'Active'
        ORDER BY emp_name
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
        FROM public.salesperson_details;
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
// Get all sales persons
// Get all sales persons



// Function to generate next poc_prj_id
async function generateNextPocId(prefix) {
  const result = await pool.query(
    `SELECT poc_prj_id 
       FROM public.poc_prj_details 
       WHERE poc_prj_id LIKE $1 
       ORDER BY poc_prj_id DESC 
       LIMIT 1`,
    [prefix + "-%"]
  );

  let nextNumber = 1;
  if (result.rows.length > 0) {
    const lastId = result.rows[0].poc_prj_id; // e.g. Event-03
    const numberPart = lastId.substring(prefix.length + 1); // "03"
    const parsed = parseInt(numberPart, 10);
    if (!isNaN(parsed)) {
      nextNumber = parsed + 1;
    }
  }

  return `${prefix}-${String(nextNumber).padStart(2, "0")}`;
}


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
        is_billable, tag, spoc_email_address, spoc_designation, department_name
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,
        $10,$11,$12,$13,$14,$15,$16,$17,$18
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
      entityType
    ]);

    // 🔹 Insert into poc_prj_efforts
    const insertEffortsQuery = `
      INSERT INTO public.poc_prj_efforts (poc_prj_id, partner_name)
      VALUES ($1, $2)
      RETURNING *;
    `;
    const effortsResult = await client.query(insertEffortsQuery, [pocPrjId, partnerName]);

    await client.query("COMMIT");

    // ✅ Now trigger AutomationEdge workflow
    try {
      // Authenticate
      const sessionToken = await new Promise((resolve, reject) => {
        unirest
          .post("https://T4.automationedge.com/aeengine/rest/authenticate")
          .query({ username: "Msp", password: "Msp@12345" })
          .end((response) => {
            if (response.error) reject("Authentication failed");
            else resolve(response.body.sessionToken);
          });
      });

      // Build request body for workflow
      const requestBody = {
        orgCode: "MSP_EVENT",
        workflowName: "POC_BOT-Add_New_POC_PRJ_ID",
        userId: "MSP Event",
        source: "Rest Test",
        responseMailSubject: 'null',
        params: [
          { name: 'poc_prj_id', type: 'String', value: pocPrjId },
          { name: 'poc_prj_name', type: 'String', value: pocName },
          { name: 'partner_client_own', type: 'String', value: entityType },
          { name: 'client_name', type: 'String', value: entityName },
          { name: 'sales_person', type: 'String', value: salesPerson },
          { name: 'description', type: 'String', value: description },
          { name: 'assigned_to', type: 'String', value: assignedTo },
          { name: 'start_date', type: 'Date', value: startDate },
          { name: 'excepted_end_date', type: 'Date', value: endDate },
          { name: 'remarks', type: 'String', value: remark || '' },
          { name: 'created_by', type: 'String', value: createdBy },
          { name: 'region', type: 'String', value: region },
          { name: 'is_billable', type: 'String', value: billableValue },
          { name: 'poc_type', type: 'String', value: pocType },
          { name: 'tag', type: 'String', value: tags },

          { name: 'chatBotEndPoint', type: 'String', value: null },
          { name: 'additionalInfo', type: 'String', value: null },
          { name: 'spoc_email_address', type: 'String', value: spocEmail },
          { name: 'spoc_designation', type: 'String', value: spocDesignation },
          { name: 'user_email', type: 'String', value: spocEmail }
        ]

      };
      console.log(requestBody);
      console.log(sessionToken);      // Execute workflow
      const automationRequestId = await new Promise((resolve, reject) => {
        unirest
          .post("https://T4.automationedge.com/aeengine/rest/execute")
          .headers({
            "Content-Type": "application/json",
            "X-Session-Token": sessionToken
          })
          .send(requestBody)
          .end((response) => {
            if (response.error) reject("Workflow execution failed");
            else resolve(response.body.automationRequestId);
          });
      });

      console.log("Workflow executed successfully:", automationRequestId);
    } catch (aeError) {
      console.error("Error during AutomationEdge workflow execution:", aeError);
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
    const validStatuses = ['Pending', 'In Progress', 'Completed', 'Cancelled', 'Draft', 'Awaiting', 'Hold', 'Closed', 'Converted'];
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







 


// Change this line at the end of server.js
app.listen(PORT, '0.0.0.0', () => {
  console.log(`POC Management server running at http://localhost:${PORT}`);
  console.log(`Also accessible via: http://10.41.11.103:${PORT}`);
});

