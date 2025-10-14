// server.js
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import pkg from "pg";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import unirest from 'unirest';
import nodemailer from 'nodemailer';

dotenv.config();

const { Pool } = pkg;


const app = express();
const PORT = process.env.PORT || 5050;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// Middleware
app.use(cors({
  // origin: "http://mspeventwin1.westus.cloudapp.azure.com" ,// frontend
  origin: ["http://localhost:5173", "http://10.41.11.103:5173", "http://localhost:80", "http://localhost"],
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



// Email configuration
// const emailConfig = {
//   host: process.env.SMTP_HOST || 'smtp.gmail.com',
//   // port: process.env.SMTP_PORT || 587,
//   port: process.env.SMTP_PORT || 465,
//   secure: true,
//   auth: {
//     user: process.env.SMTP_USER || 'alerts@automationedgerpa.com',
//     pass: process.env.SMTP_PASS || 'zzarrvgjnvowydkf'

//   }
// };

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


// Recipients from environment variable (comma-separated)
const POC_RECIPIENTS = process.env.POC_NOTIFICATION_RECIPIENTS || 'devopsbyzielotech@gmail.com,nitin.bhujbal@automationedge.com,suhas.kajawe@automationedge.com';






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




// app.get("/poc/getAllPocs", authenticateToken, async (req, res) => {
//   const client = await pool.connect();
//   try {
//     console.log('Fetching all POC records...');

//     // Use only the columns that exist based on your SELECT query
//     const query = `
//       SELECT 
//         id, 
//         brief, 
//         company_name, 
//         designation, 
//         end_customer_type, 
//         sp_name as sales_person,
//         spoc, 
//         spoc_email, 
//         usecase, 
//         partner_company_name, 
//         partner_spoc, 
//         partner_spoc_email, 
//         partner_designation, 
//         partner_mobile_number, 
//         mobile_number, 
//         process_type, 
//         region,
//         generated_usecase,
//         remark,
//         status

//       FROM public.poc_details 
//       ORDER BY id DESC
//     `;

//     const result = await client.query(query);
//     console.log('POC records found:', result.rows.length);

//     // Transform the data to match frontend expectations
//     const pocData = result.rows.map(row => ({
//       id: row.id,
//       brief: row.brief,
//       companyName: row.company_name,
//       designation: row.designation,
//       endCustomerType: row.end_customer_type,
//       salesPerson: row.sales_person,
//       spoc: row.spoc,
//       spocEmail: row.spoc_email,
//       usecase: row.usecase,
//       partnerCompanyName: row.partner_company_name,
//       partnerSpoc: row.partner_spoc,
//       partnerSpocEmail: row.partner_spoc_email,
//       partnerDesignation: row.partner_designation,
//       partnerMobileNumber: row.partner_mobile_number,
//       mobileNumber: row.mobile_number,
//       processType: row.process_type,
//       region: row.region,
//       generatedUsecase: row.generated_usecase,
//       remark: row.remark,
//       status: row.status
//     }));

//     res.json(pocData);
//   } catch (err) {
//     console.error("Error fetching POC records:", err);
//     res.status(500).json({
//       message: "Internal server error",
//       error: err.message
//     });
//   } finally {
//     client.release();
//   }
// });




// API to update generated_usecase in poc_details table

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
app.put("/poc/updateGeneratedUsecase/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;
    const { generatedUsecase } = req.body;

    const query = `
      UPDATE public.poc_details 
      SET generated_usecase = $1 
      WHERE id = $2 
      RETURNING *;
    `;

    const result = await client.query(query, [generatedUsecase, id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "POC record not found" });
    }

    res.json({
      message: "Generated usecase updated successfully",
      poc: result.rows[0]
    });
  } catch (err) {
    console.error("Error updating generated usecase:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  } finally {
    client.release();
  }
});

// API to delete POC record
app.delete("/poc/deletePoc/:id", authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    console.log('Deleting POC record with ID:', id);

    const query = `
      DELETE FROM public.poc_details 
      WHERE id = $1 
      RETURNING *;
    `;

    const result = await client.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "POC record not found" });
    }

    res.json({
      message: "POC record deleted successfully",
      deletedPoc: result.rows[0]
    });

  } catch (err) {
    console.error("Error deleting POC record:", err);
    res.status(500).json({
      message: "Internal server error",
      error: err.message
    });
  } finally {
    client.release();
  }
});

// PUT endpoint to update POC details (without updated_at)
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

    // First, check if the POC exists
    const checkQuery = 'SELECT * FROM public.poc_details WHERE id = $1';
    const checkResult = await client.query(checkQuery, [id]);

    if (checkResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ message: "POC record not found" });
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




app.get("/poc/getLeads", authenticateToken, async (req, res) => {
  try {
    console.log('Fetching leads...');
    const result = await pool.query(`
      SELECT lead_name, department_name, employee_name 
      FROM public.lead_details 
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
        sales_admin  -- Make sure this column exists in your table
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
        sales_access: true,
        all_status_access: false,
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
    const result = await pool.query(`
    SELECT poc_prj_id, poc_prj_name, client_name, partner_client_own, sales_person, description, assigned_to, start_date, excepted_end_date, status, remarks, created_by, region, sales_account_manager_name, complexity, last_status, last_status_date, status_change_date, is_billable, poc_type, tag, spoc_email_address, spoc_designation, department_name
  
      FROM public.poc_prj_details 
       where status ='In Progress' ORDER BY poc_prj_name
    `);
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











// // ✅ Login API using emp_details table
// app.post("/poc/api/auth/login", async (req, res) => {
//   try {
//     const { username, password } = req.body;

//     if (!username || !password) {
//       return res.status(400).json({ message: "Username and password required" });
//     }

//     // Check against emp_details (login by emp_id or email_id)
//     const result = await pool.query(
//       `SELECT sr_no, emp_id, emp_name, email_id, role, password
//        FROM emp_details
//        WHERE emp_id = $1 OR email_id = $1`,
//       [username]
//     );

//     if (result.rows.length === 0) {
//       return res.status(401).json({ message: "Invalid username or password" });
//     }

//     const user = result.rows[0];
//     const passwordMatch = (password === user.password);

//     if (!passwordMatch) {
//       return res.status(401).json({ message: "Invalid username or password" });
//     }

//     // Generate JWT
//     const token = jwt.sign(
//       { sr_no: user.sr_no, emp_id: user.emp_id, role: user.role },
//       JWT_SECRET,
//       { expiresIn: "1h" }
//     );

//     res.json({
//       token,
//       user: {
//         sr_no: user.sr_no,
//         emp_id: user.emp_id,
//         emp_name: user.emp_name,
//         email_id: user.email_id,
//         role: user.role
//       }
//     });
//   } catch (err) {
//     console.error("Login error:", err);
//     res.status(500).json({ message: "Internal server error" });
//   }
// });

app.post("/poc/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }

    let user = null;
    let userType = '';

    // First, check against emp_details (login by emp_id or email_id)
    const empResult = await pool.query(
      `SELECT sr_no, emp_id, emp_name, email_id, role, password
       FROM emp_details
       WHERE emp_id = $1 OR email_id = $1`,
      [username]
    );

    if (empResult.rows.length > 0) {
      user = empResult.rows[0];
      userType = 'employee';
    } else {
      // If not found in emp_details, check against salesperson_details
      const salespersonResult = await pool.query(
        `SELECT "Sr No" AS sr_no, salesperson_name, salesperson_email, password
         FROM salesperson_details
         WHERE salesperson_email = $1`,
        [username]
      );

      if (salespersonResult.rows.length > 0) {
        user = salespersonResult.rows[0];
        userType = 'salesperson';

        // For salesperson, set default emp_id and role
        user.emp_id = "AE00";  // Default emp_id for salesperson
        user.role = 0;  // Default role for salesperson (0 or any other placeholder)
      }
    }

    // If user not found in either table
    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Verify password
    const passwordMatch = (password === user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // Generate JWT with user type information
    const tokenPayload = {
      sr_no: user.sr_no,
      user_type: userType,
      emp_id: user.emp_id,  // Include emp_id (AE00 for salesperson)
      role: user.role       // Include role (0 for salesperson)
    };

    if (userType === 'employee') {
      tokenPayload.emp_id = user.emp_id;
      tokenPayload.role = user.role;
    } else {
      tokenPayload.salesperson_email = user.salesperson_email;
    }

    const token = jwt.sign(
      tokenPayload,
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Unified response format for both employee and salesperson
    let userResponse = {
      sr_no: user.sr_no,
      emp_id: user.emp_id,  // emp_id (AE00 for salesperson)
      role: user.role,      // role (0 for salesperson)
      user_type: userType   // user_type: 'employee' or 'salesperson'
    };

    // Additional fields for employees (specific to them)
    if (userType === 'employee') {
      userResponse.emp_name = user.emp_name;
      userResponse.email_id = user.email_id;
    } else {
      // Additional fields for salesperson
      userResponse.salesperson_name = user.salesperson_name;
      userResponse.salesperson_email = user.salesperson_email;
    }

    res.json({
      token,
      user: userResponse
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

    // ✅ Now trigger AutomationEdge workflow
    // try {
    //   // Authenticate
    //   const sessionToken = await new Promise((resolve, reject) => {
    //     unirest
    //       .post("https://T4.automationedge.com/aeengine/rest/authenticate")
    //       .query({ username: "Msp", password: "Msp@12345" })
    //       .end((response) => {
    //         if (response.error) reject("Authentication failed");
    //         else resolve(response.body.sessionToken);
    //       });
    //   });

    //   // Build request body for workflow
    //   const requestBody = {
    //     orgCode: "MSP_EVENT",
    //     workflowName: "POC_BOT-Add_New_POC_PRJ_ID",
    //     userId: "MSP Event",
    //     source: "Rest Test",
    //     responseMailSubject: 'null',
    //     params: [
    //       { name: 'poc_prj_id', type: 'String', value: pocPrjId },
    //       { name: 'poc_prj_name', type: 'String', value: pocName },
    //       { name: 'partner_client_own', type: 'String', value: entityType },
    //       { name: 'client_name', type: 'String', value: entityName },
    //       { name: 'sales_person', type: 'String', value: salesPerson },
    //       { name: 'description', type: 'String', value: description },
    //       { name: 'assigned_to', type: 'String', value: assignedTo },
    //       { name: 'start_date', type: 'Date', value: startDate },
    //       { name: 'excepted_end_date', type: 'Date', value: endDate },
    //       { name: 'remarks', type: 'String', value: remark || '' },
    //       { name: 'created_by', type: 'String', value: createdBy },
    //       { name: 'region', type: 'String', value: region },
    //       { name: 'is_billable', type: 'String', value: billableValue },
    //       { name: 'poc_type', type: 'String', value: pocType },
    //       { name: 'tag', type: 'String', value: tags },
    //       { name: 'status', type: 'String', value: 'Draft' }, // Add status parameter

    //       { name: 'chatBotEndPoint', type: 'String', value: null },
    //       { name: 'additionalInfo', type: 'String', value: null },
    //       { name: 'spoc_email_address', type: 'String', value: spocEmail },
    //       { name: 'spoc_designation', type: 'String', value: spocDesignation },
    //       { name: 'user_email', type: 'String', value: spocEmail }
    //     ]
    //   };

    //   console.log(requestBody);
    //   console.log(sessionToken);      // Execute workflow
    //   const automationRequestId = await new Promise((resolve, reject) => {
    //     unirest
    //       .post("https://T4.automationedge.com/aeengine/rest/execute")
    //       .headers({
    //         "Content-Type": "application/json",
    //         "X-Session-Token": sessionToken
    //       })
    //       .send(requestBody)
    //       .end((response) => {
    //         if (response.error) reject("Workflow execution failed");
    //         else resolve(response.body.automationRequestId);
    //       });
    //   });

    //   console.log("Workflow executed successfully:", automationRequestId);
    // } catch (aeError) {
    //   console.error("Error during AutomationEdge workflow execution:", aeError);
    // }

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
    const validStatuses = ['Pending', 'In Progress', 'Completed', 'Dropped', 'Draft', 'Awaiting', 'Hold', 'Closed', 'Converted'];
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







// Change this line at the end of server.js
app.listen(PORT, '0.0.0.0', () => {
  console.log(`POC Management server running at http://localhost:${PORT}`);
  console.log(`Also accessible via: http://10.41.11.103:${PORT}`);
});

