// print_passwords.js
require("dotenv").config();
const crypto = require("crypto");
const fs = require("fs");

// ------------------------------------------------------
// CONFIG
// ------------------------------------------------------
const PORTAL_PW_SECRET = process.env.PORTAL_PW_SECRET || "aljkfehGHIUYOGljblajdfb";
// console.log("PW SECRET prefix (script):", (PORTAL_PW_SECRET || "").slice(0, 8));

// ------------------------------------------------------
// PASSWORD DERIVATION FUNCTION
// ------------------------------------------------------
function derivePassword(studentId) {
  const raw = crypto
    .createHmac("sha256", PORTAL_PW_SECRET)
    .update(String(studentId).trim())
    .digest("base64url");
  return `ac-${raw.slice(0, 5)}-${raw.slice(5, 11)}`;
}

// console.log("Derive S022 directly:", derivePassword("S022"));

function extractStudentId(rawName) {
  if (typeof rawName !== "string") return null;
  // Support hyphen -, en dash – (U+2013), em dash — (U+2014)
  let m = rawName.match(/^([A-Za-z]\d{2,})\s*[-–—]\s*/);
  if (m) return m[1];
  // Fallback: grab first token like S022 before any non-alphanumeric
  m = rawName.match(/^([A-Za-z]\d{2,})\b/);
  if (m) return m[1];
  return null;
}

// ------------------------------------------------------
// FETCH STUDENTS AND COURSES FROM AIRTABLE
// ------------------------------------------------------
(async () => {
  try {
    const { AIRTABLE_BASE_ID, AIRTABLE_API_KEY } = process.env;

    // Fetch all students
    console.log("📚 Fetching students...");
    const studentsResp = await fetch(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
        "Students"
      )}`,
      {
        headers: {
          Authorization: `Bearer ${AIRTABLE_API_KEY}`,
          Accept: "application/json",
        },
      }
    );

    if (!studentsResp.ok) throw new Error(await studentsResp.text());
    const studentsData = await studentsResp.json();

    // Build student map
    const studentMap = {};
    for (const r of studentsData.records) {
      const preferredName = r.fields["Preferred Name"];
      const rawName = r.fields["Name"] || "";
      const studentId = extractStudentId(rawName) || r.fields["StudentID"] || r.id;

      if (!preferredName || !studentId) continue;

      studentMap[r.id] = {
        preferredName,
        studentId,
        recordId: r.id,
        password: derivePassword(studentId),
        courses: r.fields["Current Course (from Student)"] || []
      };
    }

    // Fetch all courses to find Jan 2026 courses
    console.log("📖 Fetching courses...");
    const coursesResp = await fetch(
      `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(
        "Courses"
      )}`,
      {
        headers: {
          Authorization: `Bearer ${AIRTABLE_API_KEY}`,
          Accept: "application/json",
        },
      }
    );

    if (!coursesResp.ok) throw new Error(await coursesResp.text());
    const coursesData = await coursesResp.json();

    // Find courses that are active in Jan 2026
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const jan2026CourseIds = new Set();
    for (const record of coursesData.records) {
      const name = record.fields?.["Name"] || "";
      const startDate = record.fields?.["Start Date"];
      const endDate = record.fields?.["End Date"];

      if (name && startDate && endDate) {
        const courseStart = new Date(startDate);
        const courseEnd = new Date(endDate);
        courseEnd.setHours(23, 59, 59, 999);

        // Check if course includes Jan 2026
        const courseIncludesJan2026 = (
          (courseStart.getFullYear() === 2026 && courseStart.getMonth() === 0) ||
          (courseEnd.getFullYear() === 2026 && courseEnd.getMonth() === 0) ||
          (courseStart < new Date('2026-02-01') && courseEnd >= new Date('2026-01-01'))
        );

        if (courseIncludesJan2026) {
          jan2026CourseIds.add(record.id);
        }
      }
    }

    console.log(`\n✅ Found ${jan2026CourseIds.size} courses that include Jan 2026`);
    console.log(`📋 Jan 2026 Course IDs: ${Array.from(jan2026CourseIds).join(", ")}\n`);

    // Debug: show total students
    console.log(`📊 Total students in database: ${Object.keys(studentMap).length}`);

    // Filter students to only those with Jan 2026 courses
    const currentStudents = [];
    for (const student of Object.values(studentMap)) {
      const hasCurrent2026Course = student.courses.some(courseId => jan2026CourseIds.has(courseId));
      if (hasCurrent2026Course) {
        currentStudents.push(student);
      }
    }

    // If no students found by course filtering, just show all students
    if (currentStudents.length === 0) {
      console.log("⚠️  No students found with Jan 2026 course links.\n");
      console.log("📌 Sample student data:");
      const sampleStudents = Object.values(studentMap).slice(0, 3);
      for (const s of sampleStudents) {
        console.log(`   ${s.preferredName}: courses = [${s.courses.join(", ")}]`);
      }
      console.log("\nℹ️  Showing all students instead:\n");
      currentStudents.push(...Object.values(studentMap));
    }

    // Sort by preferred name
    currentStudents.sort((a, b) => a.preferredName.localeCompare(b.preferredName));

    // Print to console
    console.log("🔐 CURRENT STUDENT PASSWORDS (Jan 2026):");
    console.log("=======================================\n");
    
    for (const student of currentStudents) {
      console.log(`${student.preferredName} (${student.studentId}): ${student.password}`);
    }

    console.log(`\n✅ Total: ${currentStudents.length} students`);

    // Also write to CSV for backup
    const rows = [["Preferred Name", "Student ID", "Password"]];
    for (const student of currentStudents) {
      rows.push([student.preferredName, student.studentId, student.password]);
    }

    const csv = rows
      .map((r) => r.map((x) => `"${String(x).replace(/"/g, '""')}"`).join(","))
      .join("\n");
    fs.writeFileSync("student_passwords.csv", csv);
    console.log("\n📄 Also wrote to student_passwords.csv");
  } catch (err) {
    console.error("Error:", err.message);
  }
})();
