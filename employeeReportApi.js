// employeeReportApi.js
import express from 'express';

const router = express.Router();

// Helper function to calculate overtime
const calculateOvertime = (hours) => {
    const normalHours = 8;
    return hours > normalHours ? hours - normalHours : 0;
};




// 1. Get all employees with work hours summary
router.get('/getEmployeeWorkSummary', async (req, res) => {
    try {
        const { usecaseId } = req.query;
        const { startDate, endDate, status = 'Active' } = req.query;
        const limit = parseInt(req.query.limit) || 100;
        const offset = parseInt(req.query.offset) || 0;

        // Base query parameters
        const queryParams = [];
        let paramCounter = 1;
        let statusFilter = '';
        let dateFilter = '';
        let usecaseFilter = '';

        // Handle status filter
        if (status.toLowerCase() !== 'all') {  // Check if status is not 'all'
            statusFilter = ` AND ed.status = $${paramCounter}`;
            queryParams.push(status);
            paramCounter++;
        }

        // Add department filter (always PCS ROW)
        const departmentFilter = ` AND ed.department_name = $${paramCounter}`;
        queryParams.push('PCS ROW');
        paramCounter++;

        // Date filter logic
        if (startDate && endDate) {
            dateFilter = ` AND ps.poc_date BETWEEN $${paramCounter} AND $${paramCounter + 1}`;
            queryParams.push(startDate, endDate);
            paramCounter += 2;
        } else if (startDate) {
            dateFilter = ` AND ps.poc_date >= $${paramCounter}`;
            queryParams.push(startDate);
            paramCounter++;
        } else if (endDate) {
            dateFilter = ` AND ps.poc_date <= $${paramCounter}`;
            queryParams.push(endDate);
            paramCounter++;
        }

        // ✅ Usecase filter
        if (usecaseId) {
            usecaseFilter = ` AND ps.poc_prj_id = $${paramCounter}`;
            queryParams.push(usecaseId);
            paramCounter++;
        }

        // Main query to get employees with work hours
        const query = `
      WITH employee_hours AS (
        SELECT 
          ed.emp_id,
          ed.emp_name,
          ed.email_id,
          ed.status,
          ed.department_name,
          ed.role,
          COALESCE(MAX(ps.poc_date), CURRENT_DATE) as last_work_date,
          COALESCE(MIN(ps.poc_date), CURRENT_DATE) as first_work_date,
          COUNT(DISTINCT ps.poc_date) as total_days_worked,
          SUM(
            CASE
                -- Case 1: HH:MM format
                WHEN ps.hrs ~ '^[0-9]+:[0-9]+$' THEN
                CAST(SPLIT_PART(ps.hrs, ':', 1) AS NUMERIC)
                + CAST(SPLIT_PART(ps.hrs, ':', 2) AS NUMERIC) / 60.0

                -- Case 2: Pure numeric hours (4, 5, 7.5)
                WHEN ps.hrs ~ '^[0-9]+(\.[0-9]+)?$' THEN
                CAST(ps.hrs AS NUMERIC)

                ELSE 0
            END
            ) AS total_work_hours,
          COUNT(DISTINCT ps.poc_prj_id) as total_projects,
          COUNT(DISTINCT ps.customer_name) as total_customers
        FROM emp_details ed
        LEFT JOIN daily_poc_prj_status ps ON ed.emp_id = ps.emp_id
          ${dateFilter}
        WHERE ed.emp_id != 'AE0204'
          ${statusFilter}
          ${departmentFilter}
          ${usecaseFilter}
        GROUP BY ed.emp_id, ed.emp_name, ed.email_id, ed.status, 
                 ed.department_name, ed.role
      )
      SELECT *
      FROM employee_hours
      ORDER BY total_work_hours DESC
      LIMIT $${paramCounter} OFFSET $${paramCounter + 1};
    `;

        queryParams.push(limit, offset);

        // Get database connection from app.locals
        const db = req.app.locals.db;

        // Get efforts data from poc_prj_efforts table with date filtering
        let estimatedEffortsHours = 0;
        let totalEffortsHours = 0;

        let effortsQuery = `
            SELECT 
                COALESCE(SUM(estimated_efforts * 8), 0) as total_estimated_efforts_hours,
                COALESCE(SUM(total_efforts * 8), 0) as total_efforts_hours
            FROM poc_prj_efforts
            WHERE 1=1
        `;

        const effortsParams = [];
        let effortParamCounter = 1;

        // Apply usecase filter to efforts
        if (usecaseId) {
            effortsQuery += ` AND poc_prj_id = $${effortParamCounter}`;
            effortsParams.push(usecaseId);
            effortParamCounter++;
        }

        // Apply date filter to efforts (using actual_start_date)
        if (startDate && endDate) {
            effortsQuery += ` AND actual_start_date BETWEEN $${effortParamCounter} AND $${effortParamCounter + 1}`;
            effortsParams.push(startDate, endDate);
            effortParamCounter += 2;
        } else if (startDate) {
            effortsQuery += ` AND actual_start_date >= $${effortParamCounter}`;
            effortsParams.push(startDate);
            effortParamCounter++;
        } else if (endDate) {
            effortsQuery += ` AND actual_start_date <= $${effortParamCounter}`;
            effortsParams.push(endDate);
            effortParamCounter++;
        }

        console.log('Efforts Query:', effortsQuery);
        console.log('Efforts Params:', effortsParams);

        // Execute efforts query
        const effortsResult = await db.query(effortsQuery, effortsParams);
        if (effortsResult.rows[0]) {
            estimatedEffortsHours = parseFloat(effortsResult.rows[0].total_estimated_efforts_hours) || 0;
            totalEffortsHours = parseFloat(effortsResult.rows[0].total_efforts_hours) || 0;
        }

        console.log('Efforts Results:', {
            estimatedEffortsHours,
            totalEffortsHours,
            rowCount: effortsResult.rowCount
        });

        // Get employees data
        const { rows: employees } = await db.query(query, queryParams);

        // Calculate summary statistics
        let summary = {
            total_employees: employees.length,
            total_work_hours: 0,
            total_overtime_hours: 0,
            avg_utilization_rate: 0,
            departments: {},
            estimated_efforts_hours: estimatedEffortsHours,
            total_efforts_hours: totalEffortsHours
        };

        employees.forEach(emp => {
            summary.total_work_hours += parseFloat(emp.total_work_hours) || 0;
            summary.total_overtime_hours += parseFloat(emp.total_overtime_hours) || 0;
            summary.avg_utilization_rate += parseFloat(emp.utilization_rate) || 0;

            // Group by department
            if (!summary.departments[emp.department_name]) {
                summary.departments[emp.department_name] = {
                    employee_count: 0,
                    total_hours: 0
                };
            }
            summary.departments[emp.department_name].employee_count++;
            summary.departments[emp.department_name].total_hours += parseFloat(emp.total_work_hours) || 0;
        });

        if (employees.length > 0) {
            summary.avg_utilization_rate = Math.round(summary.avg_utilization_rate / employees.length);
            summary.avg_hours_per_employee = Math.round(summary.total_work_hours / employees.length);
        }

        res.json({
            success: true,
            data: {
                employees,
                summary,
                pagination: {
                    limit,
                    offset,
                    total: employees.length
                }
            }
        });

    } catch (error) {
        console.error('Error fetching employee report:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching employee report',
            error: error.message
        });
    }
});

// 2. routes/employeeReport.js
router.get('/usecases', async (req, res) => {
    try {
        const db = req.app.locals.db;

        const result = await db.query(`
            SELECT
                p.poc_prj_id,
                p.client_name,
                p.poc_prj_name,
                MAX(e.actual_start_date) AS latest_actual_start_date
            FROM poc_prj_details p
            LEFT JOIN poc_prj_efforts e
                ON p.poc_prj_id = e.poc_prj_id
            GROUP BY
                p.poc_prj_id,
                p.client_name,
                p.poc_prj_name
            ORDER BY
                latest_actual_start_date DESC NULLS LAST,
                p.client_name,
                p.poc_prj_name
        `);

        res.json({
            success: true,
            data: result.rows
        });
    } catch (err) {
        console.error('Error fetching usecases:', err);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch usecases'
        });
    }
});











export default router;