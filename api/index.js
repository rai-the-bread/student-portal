// server.js
// Student Portal API (Express + Airtable)
// Node 18+ recommended (for global fetch)

const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

// console.log("ENV sanity:", {
//   baseIdPrefix: (process.env.AIRTABLE_BASE_ID || "").slice(0, 3), // expect 'app'
//   keyKind: (process.env.AIRTABLE_API_KEY || "").startsWith("pat")
//     ? "pat"
//     : (process.env.AIRTABLE_API_KEY || "").startsWith("key")
//     ? "legacy"
//     : "missing/other",
//   hasKey: !!process.env.AIRTABLE_API_KEY,
// });

// If you're on Node < 18, uncomment the next 2 lines:
// const fetch = (...args) =>
//   import("node-fetch").then((m) => m.default(...args));

// -------------------------
// Environment
// -------------------------
const {
  PORTAL_PW_SECRET,
  MASTER_PORTAL_PW,
  AIRTABLE_API_KEY,
  AIRTABLE_BASE_ID,
  AIRTABLE_STUDENTS_VIEW = "", // optional view for Students
  AIRTABLE_ATTENDANCE_TABLE = "Attendance",
  // AIRTABLE_ATTENDANCE_VIEW = "",
  ALLOWED_ORIGINS, // comma-separated list (optional)
} = process.env;

const PORT = process.env.PORT || 3001;

// Additional debugging after destructuring
// console.log("🔍 After destructuring:", {
//   hasApiKey: !!AIRTABLE_API_KEY,
//   apiKeyPrefix: AIRTABLE_API_KEY?.substring(0, 4),
//   hasBaseId: !!AIRTABLE_BASE_ID,
//   baseIdPrefix: AIRTABLE_BASE_ID?.substring(0, 3),
// });

if (!PORTAL_PW_SECRET) {
  throw new Error("PORTAL_PW_SECRET is not set. Add it to your .env");
}
if (!AIRTABLE_API_KEY || !AIRTABLE_BASE_ID) {
  console.warn(
    "⚠️ AIRTABLE_API_KEY or AIRTABLE_BASE_ID missing; Airtable calls will fail."
  );
}

// -------------------------
// Helpers
// -------------------------
function derivePassword(studentId) {
  const raw = crypto
    .createHmac("sha256", PORTAL_PW_SECRET)
    .update(String(studentId).trim())
    .digest("base64url");
  return `ac-${raw.slice(0, 5)}-${raw.slice(5, 11)}`;
}

function extractStudentId(rawName) {
  if (typeof rawName !== "string") return null;
  // Accept hyphen -, en dash – (U+2013), em dash — (U+2014)
  let m = rawName.match(/^([A-Za-z]\d{2,})\s*[-–—]\s*/);
  if (m) return m[1];
  // Fallback: grab the leading token like S022 before any non-alnum
  m = rawName.match(/^([A-Za-z]\d{2,})\b/);
  if (m) return m[1];
  return null;
}

// -------------------------
// In-memory student map
// -------------------------
let STUDENTS = {}; // keyed by Preferred Name

async function loadStudentsFromAirtable() {
  const TABLE = "Students"; // change if your base uses a different name

  // Debug logging
  // console.log(
  //   "🔍 loadStudentsFromAirtable - AIRTABLE_API_KEY exists:",
  //   !!AIRTABLE_API_KEY
  // );
  // console.log(
  //   "🔍 loadStudentsFromAirtable - AIRTABLE_API_KEY starts with:",
  //   AIRTABLE_API_KEY?.substring(0, 4)
  // );
  // console.log(
  //   "🔍 loadStudentsFromAirtable - AIRTABLE_BASE_ID:",
  //   AIRTABLE_BASE_ID
  // );

  const params = new URLSearchParams();
  if (AIRTABLE_STUDENTS_VIEW) params.set("view", AIRTABLE_STUDENTS_VIEW);

  const url = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
    TABLE
  )}?${params.toString()}`;

  // console.log("🔍 Request URL:", url);
  // console.log(
  //   "🔍 Auth header will be:",
  //   `Bearer ${AIRTABLE_API_KEY?.substring(0, 10)}...`
  // );

  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${AIRTABLE_API_KEY}`,
      Accept: "application/json",
    },
  });

  if (!resp.ok) {
    const text = await resp.text();
    console.error("❌ Airtable error response:", text);
    throw new Error(`Students fetch failed: ${resp.status} ${text}`);
  }

  const data = await resp.json();

  const next = {};
  for (const r of data.records || []) {
    const fields = r.fields || {};
    const preferredName = fields["Preferred Name"];
    const rawName = fields["Name"];
    const studentId = extractStudentId(rawName) || fields["StudentID"] || null;
    if (!preferredName || !studentId) continue;

    next[preferredName] = {
      preferredName,
      studentId,
      password: derivePassword(studentId),
    };
  }

  STUDENTS = next;
  // console.log(
  //   `✅ Loaded ${Object.keys(STUDENTS).length} students from Airtable`
  // );
}

// -------------------------
// App setup
// -------------------------
const app = express();

// CORS (open in dev; allowlist in prod)
// console.log("🔍 ALLOWED_ORIGINS:", ALLOWED_ORIGINS);
if (ALLOWED_ORIGINS) {
  const allowed = ALLOWED_ORIGINS.split(",").map((s) => s.trim());
  // console.log("🔍 Allowed origins array:", allowed);
  app.use(
    cors({
      origin: (origin, cb) => {
        // console.log(
        //   "🔍 CORS check - Request origin:",
        //   origin,
        //   "Allowed?",
        //   !origin || allowed.includes(origin)
        // );
        if (!origin || allowed.includes(origin)) return cb(null, true);
        return cb(new Error("CORS: origin not allowed"));
      },
    })
  );
} else {
  // console.log("⚠️ ALLOWED_ORIGINS not set - allowing all origins");
  app.use(cors()); // dev-friendly; tighten before prod
}

app.use(express.json());

// Rate limit login to slow brute force
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});

// -------------------------
// Routes
// -------------------------
app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Server is running" });
});

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { preferredName, password } = req.body;
    if (!preferredName || !password) {
      return res
        .status(400)
        .json({ error: "Preferred name and password are required" });
    }

    const normalized = preferredName.trim().toLowerCase();
    const student = Object.values(STUDENTS).find(
      (s) => (s.preferredName || "").trim().toLowerCase() === normalized
    );
    if (!student) return res.status(401).json({ error: "Invalid credentials" });

    // Master override
    if (MASTER_PORTAL_PW && password === MASTER_PORTAL_PW) {
      // console.log(
      //   `[STAFF OVERRIDE] ${preferredName} at ${new Date().toISOString()}`
      // );
      return res.json({
        success: true,
        staffOverride: true,
        student: {
          preferredName: student.preferredName,
          studentId: student.studentId,
        },
      });
    }

    // Per-student password
    if (password !== student.password) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    return res.json({
      success: true,
      staffOverride: false,
      student: {
        preferredName: student.preferredName,
        studentId: student.studentId,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

app.get("/attendance/:preferredName", async (req, res) => {
  try {
    const { preferredName } = req.params;
    const normalized = preferredName.trim().toLowerCase();

    const student = Object.values(STUDENTS).find(
      (s) => (s.preferredName || "").trim().toLowerCase() === normalized
    );
    if (!student) return res.status(404).json({ error: "Student not found" });

    const BASE_ID = AIRTABLE_BASE_ID;
    const TABLE_NAME = AIRTABLE_ATTENDANCE_TABLE;

    const safeName = student.preferredName.replace(/'/g, "\\'");
    
    // Use 2026-01-12 as the course start date (filter out data before course started)
    const courseStartDate = new Date('2026-01-12');

    let allRecords = [];
    let offset = null;

    do {
      const params = new URLSearchParams();
      params.set("filterByFormula", `{PreferredNameText}='${safeName}'`);
      params.set("sort[0][field]", "Date");
      params.set("sort[0][direction]", "desc");
      if (offset) params.set("offset", offset);

      const response = await fetch(
        `https://api.airtable.com/v0/${BASE_ID}/${encodeURIComponent(
          TABLE_NAME
        )}?${params.toString()}`,
        {
          headers: {
            Authorization: `Bearer ${AIRTABLE_API_KEY}`,
            Accept: "application/json",
          },
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error("Airtable error:", response.status, errorText);
        return res
          .status(response.status)
          .json({ error: "Failed to fetch from Airtable", details: errorText });
      }

      const data = await response.json();
      allRecords = allRecords.concat(data.records || []);
      offset = data.offset;
    } while (offset);

    // Filter records to only include those on or after 2026-01-12
    const records = allRecords
      .filter((record) => {
        const recordDate = record.fields?.Date;
        if (!recordDate) return false;
        const date = new Date(recordDate);
        return date >= courseStartDate;
      })
      .map((record) => ({
        id: record.id,
        date: record.fields?.Date || null,
        course: record.fields?.["Current Course (from Student)"] || null,
        blockA: record.fields?.["Block A"] ?? null,
        blockB: record.fields?.["Block B"] ?? null,
        blockC: record.fields?.["Block C"] ?? null,
        blockD: record.fields?.["Block D"] ?? null,
      }));

    res.json({ success: true, records });
  } catch (error) {
    console.error("Attendance fetch error:", error.message);
    res.status(500).json({
      error: "Server error fetching attendance",
      message: error.message,
    });
  }
});

//get percentages for each student
//get percentages for each student
app.get("/student/profile/:preferredName", async (req, res) => {
  try {
    const { preferredName } = req.params;
    // console.log("📊 Fetching profile for:", preferredName);
    const normalized = preferredName.trim().toLowerCase();

    const student = Object.values(STUDENTS).find(
      (s) => (s.preferredName || "").trim().toLowerCase() === normalized
    );
    if (!student) {
      // console.log("❌ Student not found in STUDENTS map");
      return res.status(404).json({ error: "Student not found" });
    }

    // Fetch full student record from Airtable Students table
    const params = new URLSearchParams();
    const safeName = student.preferredName.replace(/'/g, "\\'");
    params.set("filterByFormula", `{Preferred Name}='${safeName}'`);

    // console.log("🔍 Querying Airtable with formula:", `{Preferred Name}='${safeName}'`);

    const response = await fetch(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/Students?${params.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${AIRTABLE_API_KEY}`,
          Accept: "application/json",
        },
      }
    );

    if (!response.ok) {
      const errorText = await response.text();
      console.error("❌ Airtable error:", response.status, errorText);
      return res.status(response.status).json({ 
        error: "Failed to fetch student profile" 
      });
    }

    const data = await response.json();
    // console.log("📦 Airtable response records count:", data.records?.length);
    
    if (!data.records || data.records.length === 0) {
      // console.log("❌ No records found for student");
      return res.status(404).json({ error: "Student profile not found" });
    }

    const fields = data.records[0].fields;
    // console.log("📋 Available fields:", Object.keys(fields));
    
    // Get the course record ID
    const courseRecordIds = fields["Current Course"];
    // console.log("🎯 Current Course (record IDs):", courseRecordIds);
    
    let courseName = null;
    
    // If there's a linked course, fetch its name from the Courses table
    if (courseRecordIds && Array.isArray(courseRecordIds) && courseRecordIds.length > 0) {
      const courseRecordId = courseRecordIds[0]; // Get the first course
      // console.log("🔍 Fetching course name for record ID:", courseRecordId);
      
      try {
        const courseResponse = await fetch(
          `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/Courses/${courseRecordId}`,
          {
            headers: {
              Authorization: `Bearer ${AIRTABLE_API_KEY}`,
              Accept: "application/json",
            },
          }
        );
        
        if (courseResponse.ok) {
          const courseData = await courseResponse.json();
          courseName = courseData.fields?.Name || null;
          // console.log("✅ Course name:", courseName);
        } else {
          console.log("⚠️ Could not fetch course details");
        }
      } catch (err) {
        console.log("⚠️ Error fetching course:", err.message);
      }
    }
    
    // console.log("📊 % missed FE:", fields["% missed FE"]);
    // console.log("📊 % missed BE:", fields["% missed BE"]);
    // console.log("📊 % missed TCF/ITP:", fields["% missed TCF/ITP"]);
    
    const profile = {
      preferredName: fields["Preferred Name"],
      currentCourse: courseName,
      percentMissedFE: fields["% missed FE"] || 0,
      percentMissedBE: fields["% missed BE"] || 0,
      percentMissedTCF: fields["% missed TCF/ITP"] || 0,
    };
    
    // console.log("✅ Sending profile:", profile);
    
    res.json({
      success: true,
      profile: profile,
    });
  } catch (error) {
    console.error("❌ Student profile fetch error:", error.message);
    res.status(500).json({ 
      error: "Server error fetching student profile",
      message: error.message 
    });
  }
});

// -------------------------
// TEACHER ROUTES
// -------------------------

// Teacher login - uses MASTER_PORTAL_PW
app.post("/teacher/login", loginLimiter, async (req, res) => {
  try {
    // console.log("🔐 Teacher login attempt");
    // console.log("Request body:", req.body);
    // console.log("MASTER_PORTAL_PW set:", !!MASTER_PORTAL_PW);
    // console.log("MASTER_PORTAL_PW value:", MASTER_PORTAL_PW);
    
    const { password } = req.body;
    // console.log("Received password:", password);
    
    if (!password) {
      // console.log("❌ No password provided");
      return res.status(400).json({ error: "Password is required" });
    }

    // console.log("Comparing passwords:");
    // console.log("  Received:", password);
    // console.log("  Expected:", MASTER_PORTAL_PW);
    // console.log("  Match:", password === MASTER_PORTAL_PW);

    if (!MASTER_PORTAL_PW || password !== MASTER_PORTAL_PW) {
      console.log("❌ Invalid password");
      return res.status(401).json({ error: "Invalid teacher password" });
    }

    // console.log("✅ Teacher login successful");
    res.json({
      success: true,
      userType: "teacher",
    });
  } catch (err) {
    console.error("Teacher login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// Get list of unique classes
app.get("/teacher/classes", async (req, res) => {
  try {
    // console.log("📚 Fetching classes from Courses table...");
    
    const BASE_ID = AIRTABLE_BASE_ID;
    const COURSES_TABLE = "Courses";

    const params = new URLSearchParams();
    // Filter to only 2026 courses
    params.set("filterByFormula", "FIND('2026', {Name})");

    let allCourses = [];
    let offset = null;

    do {
      const pageParams = new URLSearchParams(params);
      if (offset) pageParams.set("offset", offset);

      const response = await fetch(
        `https://api.airtable.com/v0/${BASE_ID}/${encodeURIComponent(
          COURSES_TABLE
        )}?${pageParams.toString()}`,
        {
          headers: {
            Authorization: `Bearer ${AIRTABLE_API_KEY}`,
            Accept: "application/json",
          },
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error("Airtable error:", response.status);
        return res.status(response.status).json({ error: "Failed to fetch classes" });
      }

      const data = await response.json();
      
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      (data.records || []).forEach((record) => {
        const courseName = record.fields?.["Name"];
        const startDate = record.fields?.["Start Date"];
        const endDate = record.fields?.["End Date"];
        
        if (courseName && typeof courseName === "string" && startDate && endDate) {
          const courseStart = new Date(startDate);
          const courseEnd = new Date(endDate);
          courseEnd.setHours(23, 59, 59, 999);
          
          // Only include courses where: today >= start date AND today <= end date
          if (today >= courseStart && today <= courseEnd) {
            allCourses.push(courseName);
          }
        }
      });

      offset = data.offset;
    } while (offset);

    const classes = allCourses.sort();
    res.json({ success: true, classes });
  } catch (error) {
    console.error("Classes fetch error:", error.message);
    res.status(500).json({ error: "Server error fetching classes" });
  }
});

// Get attendance summary for a specific class
app.get("/teacher/class/:className", async (req, res) => {
  try {
    const { className } = req.params;
    
    const BASE_ID = AIRTABLE_BASE_ID;
    const TABLE_NAME = AIRTABLE_ATTENDANCE_TABLE;

    // First, get the course record ID and Start Date from the Courses table
    const courseParams = new URLSearchParams();
    courseParams.set("filterByFormula", `{Name}='${className.replace(/'/g, "\\'")}'`);

    let courseRecordId = null;
    let startDate = null;

    const courseResponse = await fetch(
      `https://api.airtable.com/v0/${BASE_ID}/Courses?${courseParams.toString()}`,
      {
        headers: {
          Authorization: `Bearer ${AIRTABLE_API_KEY}`,
          Accept: "application/json",
        },
      }
    );

    if (courseResponse.ok) {
      const courseData = await courseResponse.json();
      if (courseData.records && courseData.records.length > 0) {
        courseRecordId = courseData.records[0].id;
        startDate = courseData.records[0].fields?.["Start Date"];
      }
    }

    if (!courseRecordId) {
      return res.status(404).json({ error: "Course not found" });
    }

    if (!startDate) {
      return res.status(400).json({ error: "Course start date not set" });
    }

    // Now fetch ALL attendance records and filter them manually
    let allRecords = [];
    let offset = null;

    do {
      const params = new URLSearchParams();
      if (offset) params.set("offset", offset);

      const response = await fetch(
        `https://api.airtable.com/v0/${BASE_ID}/${encodeURIComponent(
          TABLE_NAME
        )}?${params.toString()}`,
        {
          headers: {
            Authorization: `Bearer ${AIRTABLE_API_KEY}`,
            Accept: "application/json",
          },
        }
      );

      if (!response.ok) {
        const errorText = await response.text();
        console.error("Airtable error:", response.status);
        return res.status(response.status).json({ error: "Failed to fetch class data" });
      }

      const data = await response.json();
      allRecords = allRecords.concat(data.records || []);
      offset = data.offset;
    } while (offset);

    // console.log(`  Total records fetched: ${allRecords.length}`);

    // Filter records where Current Course (from Student) includes our courseRecordId
    // AND the attendance date is on or after the course start date
    const startDateObj = new Date(startDate);
    const courseRecords = allRecords.filter(record => {
      const courses = record.fields?.["Current Course (from Student)"] || [];
      const recordDate = record.fields?.["Date"];
      
      // Check if this record's course matches AND the date is >= start date
      const courseMatches = Array.isArray(courses) && courses.includes(courseRecordId);
      const dateMatches = recordDate ? new Date(recordDate) >= startDateObj : false;
      
      return courseMatches && dateMatches;
    });

    // Now aggregate by student
    const studentMap = {};

    courseRecords.forEach((record) => {
      let preferredName = record.fields?.["PreferredNameText"];
      
      // Handle if it's an array (take first element)
      if (Array.isArray(preferredName)) {
        preferredName = preferredName[0];
      }
      
      if (!preferredName) {
        return;
      }
      
      if (!studentMap[preferredName]) {
        studentMap[preferredName] = {
          preferredName,
          absences: 0,
          tardies: 0,
          totalBlocks: 0,
        };
      }

      ["Block A", "Block B", "Block C", "Block D"].forEach((blockName) => {
        const status = record.fields?.[blockName];
        if (status) {
          studentMap[preferredName].totalBlocks++;
          if (status.includes("Absent")) {
            studentMap[preferredName].absences++;
          } else if (status.includes("Tardy")) {
            studentMap[preferredName].tardies++;
          }
        }
      });
    });

    // Fetch % missed data from Students table for each student
    const studentsWithPercent = await Promise.all(
      Object.values(studentMap)
        .filter(s => s && s.preferredName && typeof s.preferredName === 'string')
        .map(async (student) => {
          try {
            const safeName = student.preferredName.replace(/'/g, "\\'");
            const studentParams = new URLSearchParams();
            studentParams.set("filterByFormula", `{Preferred Name}='${safeName}'`);

            const studentResponse = await fetch(
              `https://api.airtable.com/v0/${BASE_ID}/Students?${studentParams.toString()}`,
              {
                headers: {
                  Authorization: `Bearer ${AIRTABLE_API_KEY}`,
                  Accept: "application/json",
                },
              }
            );

            if (studentResponse.ok) {
              const studentData = await studentResponse.json();
              if (studentData.records && studentData.records.length > 0) {
                const fields = studentData.records[0].fields;
                
                // Determine which % to use based on the course name
                let percentMissed = 0;
                if (className.includes("Frontend") || className.includes("FE")) {
                  percentMissed = fields["% missed FE"] || 0;
                } else if (className.includes("Backend") || className.includes("BE")) {
                  percentMissed = fields["% missed BE"] || 0;
                } else if (className.includes("TCF") || className.includes("ITP")) {
                  percentMissed = fields["% missed TCF/ITP"] || 0;
                }

                return {
                  ...student,
                  percentMissed,
                };
              }
            }
            
            // If fetch fails, return student without percentMissed
            return { ...student, percentMissed: null };
          } catch (err) {
            console.error(`Error fetching % missed for ${student.preferredName}:`, err);
            return { ...student, percentMissed: null };
          }
        })
    );

    const students = studentsWithPercent.sort((a, b) => 
      a.preferredName.localeCompare(b.preferredName)
    );

    res.json({ success: true, students });
  } catch (error) {
    console.error("Class summary error:", error.message);
    res.status(500).json({ error: "Server error fetching class summary" });
  }
});

// -------------------------
// Boot: load students first, then listen
// -------------------------

let studentsLoaded = false;

async function ensureStudentsLoaded() {
  if (!studentsLoaded) {
    await loadStudentsFromAirtable();
    studentsLoaded = true;
  }
}

// For local development only
if (require.main === module) {
  (async () => {
    try {
      await loadStudentsFromAirtable();
      setInterval(loadStudentsFromAirtable, 5 * 60 * 1000);

      app.listen(PORT, () => {
        console.log(`🚀 Student Portal API running on http://localhost:${PORT}`);
        console.log(`🗂️ Attendance Table: ${AIRTABLE_ATTENDANCE_TABLE}`);
      });
    } catch (e) {
      console.error("Failed initial Airtable load:", e);
      process.exit(1);
    }
  })();
}