import React, { useState } from "react";
import logo from "./assets/ac-logo.jpg";
import './App.css'
import {
  LogOut,
  User,
  CheckCircle,
  XCircle,
  Clock,
  AlertTriangle,
  Eye,
  EyeOff,
} from "lucide-react";

// =============================================
// CONFIGURATION - BACKEND API URL
// =============================================
const API_BASE_URL =
  process.env.REACT_APP_API_BASE_URL || "http://localhost:3001/api";

// =============================================
// MAIN APP COMPONENT
// =============================================
function StudentPortal() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userType, setUserType] = useState(null); // "student" or "teacher"
  const [currentStudent, setCurrentStudent] = useState(null);
  const [attendanceRecords, setAttendanceRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // =============================================
  // STUDENT LOGIN HANDLER
  // =============================================
  const handleStudentLogin = async (preferredName, password) => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ preferredName, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Login failed");
      }

      setCurrentStudent(data.student);
      setUserType("student");
      setIsLoggedIn(true);

      // Fetch attendance records after successful login
      await fetchAttendanceRecords(data.student.preferredName);
    } catch (err) {
      setError(err.message || "Login failed. Please try again.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // =============================================
  // TEACHER LOGIN HANDLER
  // =============================================
  const handleTeacherLogin = async (password) => {
    setLoading(true);
    setError("");

    try {
      const response = await fetch(`${API_BASE_URL}/teacher/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Login failed");
      }

      setUserType("teacher");
      setIsLoggedIn(true);
    } catch (err) {
      setError(err.message || "Invalid teacher password.");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  // =============================================
  // FETCH ATTENDANCE FROM BACKEND API
  // =============================================
  const fetchAttendanceRecords = async (preferredName) => {
    setLoading(true);

    try {
      const response = await fetch(
        `${API_BASE_URL}/attendance/${preferredName}`
      );

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to fetch attendance");
      }
      setAttendanceRecords(data.records);
    } catch (err) {
      setError("Could not load attendance records.");
      console.error(err);

      // Show demo data on error
      setAttendanceRecords([
        {
          id: "1",
          date: "2025-10-20",
          course: "Sept 2025 - Advanced Backend",
          blockA: "On Time",
          blockB: "On Time",
          blockC: "On Time",
          blockD: "On Time",
        },
        {
          id: "2",
          date: "2025-10-16",
          course: "Sept 2025 - Advanced Backend",
          blockA: "Absent (missed 20+ min...)",
          blockB: "Absent (20+ minutes la...)",
          blockC: "Absent (20+ minutes late)",
          blockD: "Absent (20+ minutes late)",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  // =============================================
  // LOGOUT HANDLER
  // =============================================
  const handleLogout = () => {
    setIsLoggedIn(false);
    setUserType(null);
    setCurrentStudent(null);
    setAttendanceRecords([]);
    setError("");
  };

  if (!isLoggedIn) {
    return (
      <LoginScreen
        onStudentLogin={handleStudentLogin}
        onTeacherLogin={handleTeacherLogin}
        loading={loading}
        error={error}
        setError={setError}
      />
    );
  }

  if (userType === "student") {
    return (
      <StudentDashboard
        student={currentStudent}
        records={attendanceRecords}
        onLogout={handleLogout}
        loading={loading}
      />
    );
  }

  if (userType === "teacher") {
    return <TeacherDashboard onLogout={handleLogout} />;
  }
}

// =============================================
// LOGIN SCREEN COMPONENT
// =============================================
function LoginScreen({ onStudentLogin, onTeacherLogin, loading, error, setError }) {
  const [loginMode, setLoginMode] = useState("student"); // "student" or "teacher"
  const [preferredName, setPreferredName] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const handleSubmit = () => {
    if (loginMode === "student") {
      onStudentLogin(preferredName, password);
    } else {
      onTeacherLogin(password);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      handleSubmit();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-8">
        <div className="text-center mb-8">
          {/* <div className="inline-flex items-center justify-center w-16 h-16 bg-indigo-100 rounded-full mb-4">
            <User className="w-8 h-8 text-indigo-600" />
          </div> */}
          <div className="inline-flex items-center justify-center w-36 h-36 bg-indigo-100 rounded-full mb-4">
            <img src={logo} alt="Logo" className="w-120 h-36" />
          </div>
          <h1 className="text-3xl font-bold text-gray-800 mb-2">
            Attendance Portal
          </h1>
          <p className="text-gray-600">Sign in to continue</p>
        </div>

        {/* Login Mode Tabs */}
        <div className="flex gap-2 mb-6 bg-gray-100 p-1 rounded-lg">
          <button
            onClick={() => {
              setLoginMode("student");
              setError?.("");
            }}
            className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
              loginMode === "student"
                ? "bg-white text-indigo-600 shadow-sm"
                : "text-gray-600 hover:text-gray-800"
            }`}
          >
            Student
          </button>
          <button
            onClick={() => {
              setLoginMode("teacher");
              setError?.("");
            }}
            className={`flex-1 py-2 px-4 rounded-md font-medium transition-colors ${
              loginMode === "teacher"
                ? "bg-white text-indigo-600 shadow-sm"
                : "text-gray-600 hover:text-gray-800"
            }`}
          >
            Instructor
          </button>
        </div>

        <div className="space-y-6">
          {loginMode === "student" ? (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Name
                </label>
                <input
                  type="text"
                  value={preferredName}
                  onChange={(e) => setPreferredName(e.target.value)}
                  onKeyPress={handleKeyPress}
                  className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  placeholder="Your Name"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    onKeyPress={handleKeyPress}
                    className="w-full px-4 py-3 pr-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                  >
                    {showPassword ? (
                      <EyeOff className="w-5 h-5" />
                    ) : (
                      <Eye className="w-5 h-5" />
                    )}
                  </button>
                </div>
              </div>
            </>
          ) : (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyPress={handleKeyPress}
                  className="w-full px-4 py-3 pr-12 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                >
                  {showPassword ? (
                    <EyeOff className="w-5 h-5" />
                  ) : (
                    <Eye className="w-5 h-5" />
                  )}
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
              {error}
            </div>
          )}

          <button
            onClick={handleSubmit}
            disabled={loading}
            className="w-full bg-indigo-600 text-white py-3 rounded-lg font-semibold hover:bg-indigo-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </div>
      </div>
    </div>
  );
}

// =============================================
// STUDENT DASHBOARD COMPONENT
// =============================================
function StudentDashboard({ student, records, onLogout, loading }) {
  const [studentProfile, setStudentProfile] = useState(null);

  // Fetch student profile data on mount
  React.useEffect(() => {
    const fetchProfile = async () => {
      try {
        // console.log("🔍 Fetching profile for:", student.preferredName);
        const response = await fetch(
          `${API_BASE_URL}/student/profile/${student.preferredName}`
        );
        const data = await response.json();
        // console.log("📦 Profile response:", data);
        if (response.ok) {
          setStudentProfile(data.profile);
          // console.log("✅ Profile set:", data.profile);
        } else {
          console.error("❌ Profile fetch failed:", data.error);
        }
      } catch (err) {
        console.error("❌ Failed to fetch student profile:", err);
      }
    };

    if (student?.preferredName) {
      fetchProfile();
    }
  }, [student]);

  // Calculate attendance statistics across all blocks
  const calculateStats = () => {
    let totalBlocks = 0;
    let onTimeBlocks = 0;
    let tardyBlocks = 0;
    let absentBlocks = 0;

    records.forEach((record) => {
      ["blockA", "blockB", "blockC", "blockD"].forEach((block) => {
        const status = record[block];
        if (status) {
          totalBlocks++;
          if (status === "On Time") {
            onTimeBlocks++;
          } else if (status.includes("Tardy")) {
            tardyBlocks++;
          } else if (status.includes("Absent")) {
            absentBlocks++;
          }
        }
      });
    });

    return {
      totalBlocks,
      onTimeBlocks,
      tardyBlocks,
      absentBlocks,
      attendanceRate:
        totalBlocks > 0 ? Math.round((onTimeBlocks / totalBlocks) * 100) : 0,
    };
  };

  const stats = calculateStats();

  // Determine which % missed to show based on current course
  const getRelevantPercentMissed = () => {
    // console.log("📊 Getting percent missed, profile:", studentProfile);
    if (!studentProfile) {
      // console.log("⚠️ No profile yet");
      return null;
    }
    
    const course = studentProfile.currentCourse || "";
    // console.log("🎯 Current course:", course);
    
    if (course.includes("Frontend") || course.includes("FE")) {
      // console.log("✅ Returning FE %:", studentProfile.percentMissedFE);
      return studentProfile.percentMissedFE;
    } else if (course.includes("Backend") || course.includes("BE")) {
      // console.log("✅ Returning BE %:", studentProfile.percentMissedBE);
      return studentProfile.percentMissedBE;
    } else if (course.includes("TCF") || course.includes("ITP")) {
      // console.log("✅ Returning TCF %:", studentProfile.percentMissedTCF);
      return studentProfile.percentMissedTCF;
    }
    
    // console.log("⚠️ No matching course found");
    return null;
  };

  const percentMissed = getRelevantPercentMissed();
  // console.log("🎯 Final percentMissed value:", percentMissed);

  // Determine zone based on absent blocks
  const getZoneStatus = () => {
    if (stats.absentBlocks >= 23) {
      return { zone: "red", message: "Critical: You have missed 23+ blocks" };
    } else if (stats.absentBlocks >= 12) {
      return { zone: "yellow", message: "Warning: You have missed 12+ blocks" };
    }
    return { zone: "green", message: "Good standing" };
  };

  const zoneStatus = getZoneStatus();

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center ${
                  zoneStatus.zone === "red"
                    ? "bg-red-600"
                    : zoneStatus.zone === "yellow"
                    ? "bg-yellow-500"
                    : "bg-green-600"
                }`}
              >
                <User className="w-6 h-6 text-white" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-gray-800">
                  {student.preferredName}
                </h2>
                {studentProfile?.currentCourse && (
                  <p className="text-sm text-gray-600">
                    {studentProfile.currentCourse}
                  </p>
                )}
              </div>
            </div>
            <button
              onClick={onLogout}
              className="flex items-center space-x-2 px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Zone Status Banner - Always Visible */}
        <div
          className={`mb-6 p-4 rounded-lg border-2 flex items-center justify-center ${
            zoneStatus.zone === "red"
              ? "bg-red-100 border-red-400 text-red-900"
              : zoneStatus.zone === "yellow"
              ? "bg-yellow-100 border-yellow-400 text-yellow-900"
              : "bg-green-100 border-green-400 text-green-900"
          }`}
        >
          <p className="text-lg font-bold">
            You are in the {zoneStatus.zone.toUpperCase()} zone
          </p>
        </div>

        {/* Zone Warning Banner - Only for Yellow/Red */}
        {zoneStatus.zone !== "green" && (
          <div
            className={`mb-6 p-4 rounded-lg border-2 flex items-center space-x-3 ${
              zoneStatus.zone === "red"
                ? "bg-red-50 border-red-300 text-red-800"
                : "bg-yellow-50 border-yellow-300 text-yellow-800"
            }`}
          >
            <AlertTriangle className="w-6 h-6 flex-shrink-0" />
            <div>
              <p className="font-semibold">{zoneStatus.message}</p>
              <p className="text-sm mt-1">
                {zoneStatus.zone === "red"
                  ? "Please speak with the Student Success Coordinator as soon as possible."
                  : "You are approaching the absence limit. Please improve your attendance."}
              </p>
            </div>
          </div>
        )}

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <StatCard
            label="On Time Blocks"
            value={stats.onTimeBlocks}
            icon={CheckCircle}
            color="green"
          />
          <StatCard
            label="Absent Blocks"
            value={stats.absentBlocks}
            icon={XCircle}
            color="red"
          />
          <StatCard
            label="Tardy Blocks"
            value={stats.tardyBlocks}
            icon={Clock}
            color="yellow"
          />
          {percentMissed !== null && (
            <StatCard
              label="% Missed"
              value={`${Math.round(percentMissed)}%`}
              icon={AlertTriangle}
              color={percentMissed > 7 ? "red" : percentMissed > 4 ? "yellow" : "green"}
            />
          )}
        </div>

        {/* Attendance Zone Table */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-x-auto">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-800">
              Attendance Zone Reference
            </h3>
            <p className="text-sm text-gray-600 mt-1">
              <a className="text-blue-600 hover:underline" href="https://docs.google.com/document/d/1Tdj0PFWu98j3JDTBsvHHszxOKGazHUvt0faf2Ftogss/edit?tab=t.0#heading=h.1vg41lkd6ugb">Click here to view the full Attendance Policy.</a>
            </p>
            <p className="text-sm text-gray-600 mt-1">
              Use this chart to understand your current attendance standing.
            </p>
            <p className="text-sm text-gray-600 mt-1">
              You are marked tardy if you arrive between 1 and 19 minutes late.
            </p>
            <p className="text-sm text-gray-600 mt-1">
              You are marked absent if you arrive more than 20 minutes late.
            </p>
          </div>

          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-gray-50 text-left text-sm font-medium text-gray-700">
                <th className="px-6 py-3 border-b border-gray-200">Zone</th>
                <th className="px-6 py-3 border-b border-gray-200">
                  # of Absences
                </th>
                <th className="px-6 py-3 border-b border-gray-200">
                  What It Means
                </th>
                <th className="px-6 py-3 border-b border-gray-200">
                  Next Steps
                </th>
              </tr>
            </thead>

            <tbody className="text-sm text-gray-800">
              {/* Green Zone */}
              <tr className="bg-green-50">
                <td className="px-6 py-4 font-semibold text-green-800 border-b border-gray-200">
                  Green Zone (On Track)
                </td>
                <td className="px-6 py-4 border-b border-gray-200">
                  ≤ 12 blocks (≈3 days, 4% of the course)
                </td>
                <td className="px-6 py-4 border-b border-gray-200">
                  You are keeping up with attendance.
                </td>
                <td className="px-6 py-4 border-b border-gray-200">
                  No action is needed.
                </td>
              </tr>

              {/* Yellow Zone */}
              <tr className="bg-yellow-50">
                <td className="px-6 py-4 font-semibold text-yellow-800 border-b border-gray-200">
                  Yellow Zone (Needs Attention)
                </td>
                <td className="px-6 py-4 border-b border-gray-200">
                  13–20 blocks (≈3.5–5 days, 4–7% of course)
                </td>
                <td className="px-6 py-4 border-b border-gray-200">
                  Attendance is starting to impact your progress.
                </td>
                <td className="px-6 py-4 border-b border-gray-200">
                  Meet with the instructor, TA, and Student Success to make a
                  plan. A PIP may be added if extra support is needed. Other
                  factors (like assignment completion) will be considered.
                </td>
              </tr>

              {/* Red Zone */}
              <tr className="bg-red-50">
                <td className="px-6 py-4 font-semibold text-red-800">
                  Red Zone (At Risk)
                </td>
                <td className="px-6 py-4">
                  &gt; 20 blocks (≈more than 5 days, 7%+ of course)
                </td>
                <td className="px-6 py-4">
                  Attendance is likely to affect your progress and may affect
                  your ability to continue.
                </td>
                <td className="px-6 py-4">
                  A PIP will be put in place. Pausing may be necessary,
                  depending on the situation.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}

// =============================================
// TEACHER DASHBOARD COMPONENT
// =============================================
function TeacherDashboard({ onLogout }) {
  const [classes, setClasses] = useState([]);
  const [selectedClass, setSelectedClass] = useState(null);
  const [students, setStudents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Fetch classes on mount
  React.useEffect(() => {
    const fetchClasses = async () => {
      setLoading(true);
      setError("");
      try {
        const response = await fetch(`${API_BASE_URL}/teacher/classes`);
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || "Failed to fetch classes");
        }
        setClasses(data.classes || []);
        setSelectedClass(null);
      } catch (err) {
        setError(err.message);
        console.error(err);
      } finally {
        setLoading(false);
      }
    };
    fetchClasses();
  }, []);

  // Fetch students for selected class
  React.useEffect(() => {
    if (!selectedClass) return;

    const fetchClassData = async () => {
      setLoading(true);
      setError("");
      try {
        const response = await fetch(
          `${API_BASE_URL}/teacher/class/${encodeURIComponent(selectedClass)}`
        );
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || "Failed to fetch class data");
        }
        setStudents(data.students || []);
      } catch (err) {
        setError(err.message);
        console.error(err);
        setStudents([]);
      } finally {
        setLoading(false);
      }
    };

    fetchClassData();
  }, [selectedClass]);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-800">
                Instructor Attendance Report
              </h1>
              <p className="text-sm text-gray-600 mt-1">
                View attendance summary for your classes
              </p>
            </div>
            <button
              onClick={onLogout}
              className="flex items-center space-x-2 px-4 py-2 text-gray-700 hover:bg-gray-100 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
              <span>Logout</span>
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Class Selector */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6">
          <label className="block text-sm font-medium text-gray-700 mb-3">
            Select Class
          </label>
          {loading && !selectedClass ? (
            <p className="text-gray-600">Loading classes...</p>
          ) : classes.length === 0 ? (
            <p className="text-gray-600">No classes available</p>
          ) : (
            <select
              value={selectedClass || ""}
              onChange={(e) => setSelectedClass(e.target.value)}
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            >
              <option value="">Choose a course</option>
              {classes.map((cls) => (
                <option key={cls} value={cls}>
                  {cls}
                </option>
              ))}
            </select>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">
            {error}
          </div>
        )}

        {/* Attendance Table */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-200">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-semibold text-gray-800">
              Student Attendance Summary
            </h3>
            <p className="text-sm text-gray-600 mt-1">
              {selectedClass && `Class: ${selectedClass}`}
            </p>
          </div>

          {loading && selectedClass ? (
            <div className="p-8 text-center text-gray-500">
              Loading attendance data...
            </div>
          ) : students.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              No students found for this class.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                      Student Name
                    </th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                      Absences
                    </th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                      Tardies
                    </th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                      % Missed
                    </th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                      Zone
                    </th>
                    <th className="px-6 py-3 text-left text-sm font-semibold text-gray-700">
                      Total Blocks
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {students.map((student, idx) => {
                    // Determine zone based on absences
                    const getZone = (absences) => {
                      if (absences >= 23) return { zone: "red", label: "Red" };
                      if (absences >= 12) return { zone: "yellow", label: "Yellow" };
                      return { zone: "green", label: "Green" };
                    };
                    
                    const zoneInfo = getZone(student.absences);
                    
                    return (
                      <tr key={idx} className="hover:bg-gray-50">
                        <td className="px-6 py-4 text-sm text-gray-900">
                          {student.preferredName}
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex px-3 py-1 rounded-full text-sm font-semibold ${
                              student.absences > 0
                                ? "bg-red-200 text-red-900"
                                : "bg-green-100 text-green-800"
                            }`}
                          >
                            {student.absences}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex px-3 py-1 rounded-full text-sm font-semibold ${
                              student.tardies > 0
                                ? "bg-yellow-200 text-yellow-900"
                                : "bg-green-100 text-green-800"
                            }`}
                          >
                            {student.tardies}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex px-3 py-1 rounded-full text-sm font-semibold ${
                              student.percentMissed > 7
                                ? "bg-red-200 text-red-900"
                                : student.percentMissed > 4
                                ? "bg-yellow-200 text-yellow-900"
                                : "bg-green-100 text-green-800"
                            }`}
                          >
                            {student.percentMissed ? `${Math.round(student.percentMissed)}%` : "N/A"}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <span
                            className={`inline-flex px-3 py-1 rounded-full text-sm font-semibold ${
                              zoneInfo.zone === "red"
                                ? "bg-red-200 text-red-900"
                                : zoneInfo.zone === "yellow"
                                ? "bg-yellow-200 text-yellow-900"
                                : "bg-green-100 text-green-800"
                            }`}
                          >
                            {zoneInfo.label}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600">
                          {student.totalBlocks}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

// =============================================
// STAT CARD COMPONENT
// =============================================
function StatCard({ label, value, icon: Icon, color }) {
  const colorClasses = {
    indigo: "bg-indigo-100 text-indigo-600",
    green: "bg-green-100 text-green-600",
    red: "bg-red-100 text-red-600",
    yellow: "bg-yellow-100 text-yellow-600",
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600 mb-1">{label}</p>
          <p className="text-2xl font-bold text-gray-800">{value}</p>
        </div>
        <div
          className={`w-12 h-12 rounded-full flex items-center justify-center ${colorClasses[color]}`}
        >
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

export default StudentPortal;
export { StudentPortal as App };