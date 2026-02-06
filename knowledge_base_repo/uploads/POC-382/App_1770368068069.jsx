import React, { useState, useEffect, useCallback } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, useNavigate, useLocation } from "react-router-dom";
import Dashboard from "./components/Dashboard";
import LoginPage from "./components/LoginPage";
import PocTable from "./components/PocTable";

import axios from "axios";
import "./App.css";
import Report from "./components/Report";
import StatusComponent from "./components/StatusComponent";
import InitiateUsecase from "./components/InitiateUsecase";
import InitiateUsecaseTable from "./components/InitiateUsecaseTable";
import InitiateUsecaseEdit from './components/InitiateUsecaseEdit';
import LeaveManagement from './components/LeaveManagement';
import SalesTable from "./components/sales/SalesTable";
import SalesStatusComponent from "./components/sales/SalesStatusComponent";

import {
  AppBar,
  Toolbar,
  IconButton,
  Typography,
  Button as MuiButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableRow,
  Box
} from '@mui/material';
import MenuIcon from '@mui/icons-material/Menu';

// Main App component with routing
function App() {
  return (
    <Router basename="/usecase">
      <AppContent />
    </Router>
  );
}

// Move all your existing logic to this component
function AppContent() {
  const navigate = useNavigate();
  const location = useLocation();

  // Authentication and navigation state
  const [currentUser, setCurrentUser] = useState(null);
  const [authChecked, setAuthChecked] = useState(false);
  const [submittedData, setSubmittedData] = useState(null);

  // Function to fetch sales persons from API
  const fetchSalesPersons = (token) => {
    return new Promise((resolve, reject) => {
      axios.get('http://localhost:5050/poc/getAllSalesPerson', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })
        .then(response => {
          if (response.data) {
            const salesData = processApiData(response.data);
            console.log('Processed sales data:', salesData);
            resolve(salesData.length > 0 ? salesData : []);
          } else {
            console.error('Invalid response format for sales persons');
            resolve([]);
          }
        })
        .catch(error => {
          console.error('Error fetching sales persons:', error);
          reject(error);
        });
    });
  };

  // Add the processApiData function to your App.jsx (copy it from your other component)
  const processApiData = (data) => {
    // Copy the same implementation from your other component
    if (!data) return [];

    if (Array.isArray(data)) {
      return data.map(item => {
        if (typeof item === 'string') return item;
        return item.name || item.emp_name || item.username || 'Unknown';
      });
    }

    return [];
  };

  useEffect(() => {
    const token = localStorage.getItem('authToken');
    const userData = localStorage.getItem('user');

    if (token && userData) {
      const cachedUser = JSON.parse(userData);
      setCurrentUser(cachedUser);
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;

      const validateInBackground = async () => {
        try {
          const response = await axios.get('http://localhost:5050/poc/api/auth/validate', {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 5000
          });

          if (!response.data.valid) {
            localStorage.removeItem('authToken');
            localStorage.removeItem('user');
            setCurrentUser(null);
            if (location.pathname !== '/login') {
              navigate('/login', { replace: true });
            }
          }
        } catch (error) {
          console.warn('Background validation failed:', error.message);
        }
      };

      validateInBackground();

      if (location.pathname === '/login') {
        navigate('/dashboard', { replace: true });
      }

      setAuthChecked(true);
    } else {
      setAuthChecked(true);
      if (location.pathname !== '/login') {
        navigate('/login', { replace: true });
      }
    }
  }, [navigate, location.pathname]);

  // Handle login
  const handleLogin = (user) => {
    setCurrentUser(user);
    navigate('/dashboard');
    const token = localStorage.getItem('authToken');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }
  };

  // Handle logout
  const handleLogout = async () => {
    try {
      await axios.post('http://localhost:5050/poc/api/auth/logout', {}, {
        withCredentials: true
      });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('authToken');
      localStorage.removeItem('user');
      delete axios.defaults.headers.common['Authorization'];
      setCurrentUser(null);
      navigate('/login');
    }
  };

  // Handle form submission success
  const handleSubmissionSuccess = (data) => {
    setSubmittedData(data);
    navigate('/confirmation');
  };

  // Navigation functions
  const navigateTo = (view) => {
    navigate(`/${view}`);
  };

  // Protected Route component
  const ProtectedRoute = ({ children }) => {
    if (!authChecked) return <div className="loading">Loading...</div>;
    if (!currentUser) return <Navigate to="/login" replace />;
    return children;
  };

  // Public Route component (redirect to dashboard if already authenticated)
  const PublicRoute = ({ children }) => {
    if (!authChecked) return <div className="loading">Loading...</div>;
    if (currentUser) return <Navigate to="/dashboard" replace />;
    return children;
  };

  // Render Confirmation Screen
  const renderConfirmation = () => {
    console.log('Confirmation data:', submittedData);

    if (!submittedData) {
      return (
        <div className="confirmation-container">
          <h2>No submission data found</h2>
          <button onClick={() => navigate('/initiate')} className="nav-btn">Back to POC Form</button>
        </div>
      );
    }

    return (
      <div className="confirmation-container">
        {/* Header with AppBar similar to other components */}
        <AppBar position="sticky" elevation={1}>
          <Toolbar>
            <IconButton
              edge="start"
              color="inherit"
              aria-label="open drawer"
              onClick={() => navigate('/dashboard')}
              sx={{ mr: 2 }}
            >
              <MenuIcon />
            </IconButton>
            <Typography
              component="h1"
              variant="h6"
              color="inherit"
              noWrap
              sx={{ flexGrow: 1 }}
            >
              POC Created Successfully
            </Typography>
            <Typography variant="body2" color="inherit" sx={{ mr: 2 }}>
              Welcome, {currentUser?.emp_name}
              {currentUser?.emp_id && ` (${currentUser.emp_id})`}
            </Typography>
            <MuiButton
              color="inherit"
              onClick={() => navigate('/poc-records')}
              sx={{ mr: 2, cursor: 'pointer' }}
            >
              POC Records
            </MuiButton>
            <MuiButton
              color="inherit"
              onClick={handleLogout}
              sx={{ cursor: 'pointer' }}
            >
              Logout
            </MuiButton>
          </Toolbar>
        </AppBar>

        <div className="form-container">
          <div className="section-container">
            <Typography variant="h4" component="h2" gutterBottom align="center" color="primary">
              ✅ POC Created Successfully
            </Typography>
            <Typography variant="subtitle1" align="center" color="textSecondary" gutterBottom>
              Your POC has been initiated with ID: <strong>{submittedData.id || 'N/A'}</strong>
            </Typography>
          </div>

          {/* POC Details Table using Material-UI */}
          <div className="section-container">
            <Typography variant="h5" component="h3" gutterBottom>
              POC Details
            </Typography>

            <Paper elevation={2} sx={{ width: '100%', overflow: 'hidden' }}>
              <TableContainer>
                <Table aria-label="poc details table">
                  <TableBody>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold', width: '30%' }}>
                        POC ID
                      </TableCell>
                      <TableCell>{submittedData.id || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Sales Person
                      </TableCell>
                      <TableCell>{submittedData.salesPerson || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Region
                      </TableCell>
                      <TableCell>{submittedData.region || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        End Customer Type
                      </TableCell>
                      <TableCell>{submittedData.endCustomerType || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Process Type
                      </TableCell>
                      <TableCell>{submittedData.processType || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Customer Company
                      </TableCell>
                      <TableCell>{submittedData.companyName || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Customer SPOC
                      </TableCell>
                      <TableCell>{submittedData.spoc || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        SPOC Email
                      </TableCell>
                      <TableCell>{submittedData.spocEmail || 'N/A'}</TableCell>
                    </TableRow>
                    {submittedData.designation && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                          Designation
                        </TableCell>
                        <TableCell>{submittedData.designation}</TableCell>
                      </TableRow>
                    )}
                    {submittedData.mobileNumber && (
                      <TableRow>
                        <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                          Mobile Number
                        </TableCell>
                        <TableCell>{submittedData.mobileNumber}</TableCell>
                      </TableRow>
                    )}
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Use Case
                      </TableCell>
                      <TableCell>{submittedData.usecase || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Brief Description
                      </TableCell>
                      <TableCell sx={{ whiteSpace: 'pre-wrap' }}>{submittedData.brief || 'N/A'}</TableCell>
                    </TableRow>
                    <TableRow>
                      <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                        Remark
                      </TableCell>
                      <TableCell sx={{ whiteSpace: 'pre-wrap' }}>{submittedData.remark || 'N/A'}</TableCell>
                    </TableRow>

                    {submittedData.endCustomerType === "Partner" && (
                      <>
                        <TableRow sx={{ backgroundColor: 'action.hover' }}>
                          <TableCell colSpan={2} sx={{ fontWeight: 'bold', textAlign: 'center', color: 'primary.main' }}>
                            Partner Information
                          </TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                            Partner Company
                          </TableCell>
                          <TableCell>{submittedData.partnerCompanyName || 'N/A'}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                            Partner SPOC
                          </TableCell>
                          <TableCell>{submittedData.partnerSpoc || 'N/A'}</TableCell>
                        </TableRow>
                        <TableRow>
                          <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                            Partner SPOC Email
                          </TableCell>
                          <TableCell>{submittedData.partnerSpocEmail || 'N/A'}</TableCell>
                        </TableRow>
                        {submittedData.partnerDesignation && (
                          <TableRow>
                            <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                              Partner Designation
                            </TableCell>
                            <TableCell>{submittedData.partnerDesignation}</TableCell>
                          </TableRow>
                        )}
                        {submittedData.partnerMobileNumber && (
                          <TableRow>
                            <TableCell component="th" scope="row" sx={{ fontWeight: 'bold' }}>
                              Partner Mobile
                            </TableCell>
                            <TableCell>{submittedData.partnerMobileNumber}</TableCell>
                          </TableRow>
                        )}
                      </>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </div>

          {/* Action Buttons */}
          <div className="section-container">
            <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
              <MuiButton
                variant="contained"
                color="primary"
                onClick={() => navigate('/initiate')}
                size="large"
              >
                Create New POC
              </MuiButton>
              <MuiButton
                variant="outlined"
                onClick={() => navigate('/poc-records')}
                size="large"
              >
                View All POC Records
              </MuiButton>
              <MuiButton
                variant="outlined"
                onClick={() => navigate('/dashboard')}
                size="large"
              >
                Back to Dashboard
              </MuiButton>
            </Box>
          </div>
        </div>
      </div>
    );
  };

  if (!authChecked) {
    return <div className="loading">Loading...</div>;
  }

  return (
    <div className="app">
      <Routes>
        <Route
          path="/login"
          element={
            <PublicRoute>
              <LoginPage onLogin={handleLogin} />
            </PublicRoute>
          }
        />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard
                onNavigate={navigateTo}
                onLogout={handleLogout}
                user={currentUser}
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/poc-table"
          element={
            <ProtectedRoute>
              <PocTable
                onNavigate={navigateTo}
                onLogout={handleLogout}
                user={currentUser}
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/status-tracker"
          element={
            <ProtectedRoute>
              <StatusComponent
                onNavigate={navigateTo}
                onLogout={handleLogout}
                user={currentUser}
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/initiate"
          element={
            <ProtectedRoute>
              <InitiateUsecase
                currentUser={currentUser}
                onLogout={handleLogout}
                navigate={navigate}
                fetchSalesPersons={fetchSalesPersons}
                processApiData={processApiData}
                onSubmissionSuccess={handleSubmissionSuccess}
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/poc-records"
          element={
            <ProtectedRoute>
              <InitiateUsecaseTable
                currentUser={currentUser}
                navigate={navigate}
                handleLogout={handleLogout}
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/report"
          element={
            <ProtectedRoute>
              <Report
                onNavigate={navigateTo}
                onLogout={handleLogout}
                user={currentUser}
              />
            </ProtectedRoute>
          }
        />

        <Route
          path="/edit-poc"
          element={
            <InitiateUsecaseEdit
              currentUser={currentUser}
              onLogout={handleLogout}
              navigate={navigate}
              fetchSalesPersons={fetchSalesPersons}
              onSubmissionSuccess={handleSubmissionSuccess}
              editRecord={location.state?.editRecord} // Pass the record to edit
            />
          }
        />

        <Route
          path="/confirmation"
          element={
            <ProtectedRoute>
              {renderConfirmation()}
            </ProtectedRoute>
          }
        />

        <Route
          path="/leave-management"
          element={
            <ProtectedRoute>
              <LeaveManagement
                user={currentUser}
                onNavigate={() => navigate('/dashboard')}  // Add this
                onLogout={handleLogout}  // Add this
              />
            </ProtectedRoute>
          }
        />

         <Route
          path="/sales-Info"
          element={
            <ProtectedRoute>
              <SalesTable
                onNavigate={navigateTo}
                onLogout={handleLogout}
                user={currentUser}
              />
            </ProtectedRoute>
          }
        />
         <Route
          path="/sales-status-tracker"
          element={
            <ProtectedRoute>
              <SalesStatusComponent
                onNavigate={navigateTo}
                onLogout={handleLogout}
                user={currentUser}
              />
            </ProtectedRoute>
          }
        />

        <Route path="/" element={<Navigate to="/login" replace />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </div>
  );
}

export default App;