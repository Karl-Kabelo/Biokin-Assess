require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');

const app = express();
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_only';
const DATABASE_FILE = process.env.DATABASE_FILE || './biokin.db';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:5500';

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

const db = new Database(DATABASE_FILE);
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('patient','intern','supervisor','admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    patient_name TEXT NOT NULL,
    patient_age INTEGER,
    category TEXT NOT NULL,
    figure_type TEXT NOT NULL,
    body_view TEXT NOT NULL,
    selected_regions_json TEXT NOT NULL,
    pain_score INTEGER NOT NULL,
    screening_json TEXT NOT NULL,
    free_text TEXT,
    ai_structured_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Awaiting Intern Review',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(patient_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL UNIQUE,
    appointment_time TEXT NOT NULL,
    consultant_name TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS intern_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL UNIQUE,
    intern_id INTEGER NOT NULL,
    subjective_notes TEXT,
    objective_plan TEXT,
    clinical_reasoning TEXT,
    intervention_plan TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
    FOREIGN KEY(intern_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS supervisor_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL UNIQUE,
    supervisor_id INTEGER NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('Approved','Changes Requested','Escalated')),
    comments TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
    FOREIGN KEY(supervisor_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER,
    user_id INTEGER,
    action TEXT NOT NULL,
    metadata_json TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

function seedDemoUsers() {
  const users = [
    { fullName: 'Demo Patient', email: 'patient@demo.com', password: 'Password123!', role: 'patient' },
    { fullName: 'Demo Intern', email: 'intern@demo.com', password: 'Password123!', role: 'intern' },
    { fullName: 'Demo Supervisor', email: 'supervisor@demo.com', password: 'Password123!', role: 'supervisor' }
  ];

  const findUser = db.prepare('SELECT id FROM users WHERE email = ?');
  const insertUser = db.prepare('INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)');

  for (const user of users) {
    if (!findUser.get(user.email)) {
      insertUser.run(user.fullName, user.email, bcrypt.hashSync(user.password, 12), user.role);
    }
  }
}
seedDemoUsers();

function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, role: user.role, fullName: user.full_name },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
}

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid authorisation token.' });
  }

  try {
    req.user = jwt.verify(authHeader.replace('Bearer ', ''), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have permission to access this resource.' });
    }
    next();
  };
}

function safeJsonParse(value, fallback) {
  try { return JSON.parse(value); } catch { return fallback; }
}

function addAuditLog({ assessmentId = null, userId = null, action, metadata = {} }) {
  db.prepare('INSERT INTO audit_logs (assessment_id, user_id, action, metadata_json) VALUES (?, ?, ?, ?)')
    .run(assessmentId, userId, action, JSON.stringify(metadata));
}

const anatomyReference = {
  'Head/Neck': { structures: ['cervical spine','upper trapezius','sternocleidomastoid','jaw/temporomandibular region'], exam: ['neck range of motion','posture observation','upper limb neurological screen','palpation of neck and shoulder girdle'] },
  Neck: { structures: ['cervical spine','upper trapezius','levator scapulae','shoulder girdle'], exam: ['cervical ROM','shoulder screen','upper limb strength groups','palpation zones'] },
  Shoulder: { structures: ['glenohumeral joint','scapula','rotator cuff region','acromioclavicular joint'], exam: ['shoulder ROM','scapular movement','rotator cuff strength groups','functional reaching patterns'] },
  'Shoulder Blade Region': { structures: ['scapula','thoracic spine','rhomboid region','trapezius region'], exam: ['thoracic movement','scapular control','postural assessment','palpation around scapula'] },
  Chest: { structures: ['rib cage','pectoralis region','thoracic spine','sternal region'], exam: ['thoracic mobility','breathing pattern','postural assessment'] },
  'Upper Back': { structures: ['thoracic spine','ribs','trapezius region','paraspinal muscles'], exam: ['thoracic ROM','postural assessment','scapular movement','palpation regions'] },
  'Lower Back': { structures: ['lumbar spine','sacroiliac region','gluteal region','hip complex'], exam: ['lumbar ROM','hip ROM','trunk strength groups','functional movement screen','palpation zones'] },
  'Hip/Groin': { structures: ['hip joint','adductor region','iliopsoas region','gluteal region'], exam: ['hip ROM','single-leg control','hip strength groups','gait or squat movement'] },
  'Gluteal Region': { structures: ['gluteal muscles','sacroiliac region','hip joint','pelvic region'], exam: ['hip ROM','glute strength groups','single-leg movement','palpation zones'] },
  Knee: { structures: ['knee joint','quadriceps','hamstrings','patellar region','calf region'], exam: ['knee ROM','quadriceps and hamstring strength groups','squat or step-down pattern','gait observation'] },
  Thigh: { structures: ['quadriceps','hamstrings','hip joint','knee joint'], exam: ['hip and knee ROM','thigh strength groups','functional loading patterns'] },
  Hamstring: { structures: ['hamstring muscle group','ischial region','knee joint','hip joint'], exam: ['hamstring flexibility','hip ROM','posterior chain strength','running or hinge pattern if relevant'] },
  Calf: { structures: ['gastrocnemius','soleus','Achilles tendon','ankle joint'], exam: ['ankle ROM','calf strength','heel raise capacity','gait observation'] },
  Achilles: { structures: ['Achilles tendon','calf complex','heel region','ankle joint'], exam: ['ankle ROM','calf strength','heel raise assessment','walking/running load review'] },
  'Ankle/Foot': { structures: ['ankle joint','foot arches','Achilles region','calf complex'], exam: ['ankle ROM','balance screen','gait observation','foot/ankle strength groups'] },
  'Wrist/Hand': { structures: ['wrist joint','hand joints','forearm muscles','tendon regions'], exam: ['wrist ROM','grip strength','finger movement screen','palpation zones'] },
  Elbow: { structures: ['elbow joint','forearm flexor/extensor groups','upper arm region'], exam: ['elbow ROM','grip strength','forearm strength groups','functional lifting or gripping'] },
  'Upper Arm': { structures: ['biceps region','triceps region','shoulder joint','elbow joint'], exam: ['shoulder and elbow ROM','upper arm strength groups','functional reaching or lifting'] },
  Forearm: { structures: ['forearm flexors','forearm extensors','wrist joint','elbow joint'], exam: ['wrist and elbow ROM','grip strength','forearm strength groups'] },
  Abdomen: { structures: ['abdominal wall','trunk muscles','pelvic region','lumbar spine'], exam: ['trunk control','breathing pattern','core strength groups','functional movement screen'] },
  Shin: { structures: ['tibial region','anterior lower leg muscles','ankle joint','knee joint'], exam: ['ankle ROM','walking/running load review','lower limb strength groups'] }
};

function structureIntakeOnly(input) {
  const selectedRegionNames = input.selectedRegions.map(item => item.region);
  const structures = new Set();
  const examComponents = new Set();

  selectedRegionNames.forEach(region => {
    const reference = anatomyReference[region];
    if (reference) {
      reference.structures.forEach(item => structures.add(item));
      reference.exam.forEach(item => examComponents.add(item));
    }
  });

  const positiveScreening = Object.entries(input.screening || {})
    .filter(([, answer]) => answer === 'Yes')
    .map(([question]) => question);

  const unansweredScreening = Object.entries(input.screening || {})
    .filter(([, answer]) => answer === '')
    .map(([question]) => question);

  return {
    outputType: 'AI intake structuring only',
    boundary: {
      diagnosisGenerated: false,
      conditionSuggested: false,
      treatmentGenerated: false,
      referralDecisionGenerated: false,
      clinicalReasoningRequiredFromHuman: true
    },
    reportedSummary: {
      category: input.category,
      figureType: input.figureType,
      bodyView: input.bodyView,
      painScore: `${input.painScore}/10`,
      selectedRegions: input.selectedRegions,
      freeText: input.freeText || 'No free-text narrative provided.'
    },
    anatomyReference: {
      selectedAnatomicalRegions: selectedRegionNames,
      surroundingStructures: [...structures],
      commonExamCategories: [...examComponents]
    },
    screeningSummary: {
      positiveScreeningResponses: positiveScreening,
      unansweredScreeningResponses: unansweredScreening
    },
    warning: 'This output is for information structuring only. It is not a diagnosis, treatment plan, clinical opinion, or referral decision.'
  };
}

const registerSchema = z.object({ fullName: z.string().min(2), email: z.string().email(), password: z.string().min(8) });
const loginSchema = z.object({ email: z.string().email(), password: z.string().min(1) });
const selectedRegionSchema = z.object({ region: z.string().min(1), view: z.enum(['Anterior','Posterior']), symptomType: z.string().min(1) });
const assessmentSchema = z.object({
  patientName: z.string().min(1),
  patientAge: z.number().int().positive().optional().nullable(),
  category: z.enum(['Pain/Injury','Rehabilitation','Chronic Health','Sports Performance','General Fitness']),
  figureType: z.enum(['Male','Female','Neutral']),
  bodyView: z.enum(['Anterior','Posterior']),
  selectedRegions: z.array(selectedRegionSchema).min(1),
  painScore: z.number().int().min(0).max(10),
  screening: z.record(z.string(), z.enum(['Yes','No',''])),
  freeText: z.string().optional()
});
const bookingSchema = z.object({ appointmentTime: z.string().min(1), consultantName: z.string().optional() });
const internNotesSchema = z.object({ subjectiveNotes: z.string().optional(), objectivePlan: z.string().optional(), clinicalReasoning: z.string().optional(), interventionPlan: z.string().optional() });
const supervisorActionSchema = z.object({ action: z.enum(['Approved','Changes Requested','Escalated']), comments: z.string().optional() });

function getFullAssessment(id) {
  const assessment = db.prepare('SELECT * FROM assessments WHERE id = ?').get(id);
  if (!assessment) return null;

  const booking = db.prepare('SELECT * FROM bookings WHERE assessment_id = ?').get(id);
  const internNotes = db.prepare(`
    SELECT intern_notes.*, users.full_name AS intern_name
    FROM intern_notes
    JOIN users ON users.id = intern_notes.intern_id
    WHERE intern_notes.assessment_id = ?
  `).get(id);
  const supervisorReview = db.prepare(`
    SELECT supervisor_reviews.*, users.full_name AS supervisor_name
    FROM supervisor_reviews
    JOIN users ON users.id = supervisor_reviews.supervisor_id
    WHERE supervisor_reviews.assessment_id = ?
  `).get(id);
  const auditLogs = db.prepare(`
    SELECT audit_logs.*, users.full_name AS user_name, users.role AS user_role
    FROM audit_logs
    LEFT JOIN users ON users.id = audit_logs.user_id
    WHERE audit_logs.assessment_id = ?
    ORDER BY audit_logs.created_at ASC
  `).all(id);

  return {
    id: assessment.id,
    patientId: assessment.patient_id,
    patientName: assessment.patient_name,
    patientAge: assessment.patient_age,
    category: assessment.category,
    figureType: assessment.figure_type,
    bodyView: assessment.body_view,
    selectedRegions: safeJsonParse(assessment.selected_regions_json, []),
    painScore: assessment.pain_score,
    screening: safeJsonParse(assessment.screening_json, {}),
    freeText: assessment.free_text,
    aiStructured: safeJsonParse(assessment.ai_structured_json, {}),
    status: assessment.status,
    createdAt: assessment.created_at,
    updatedAt: assessment.updated_at,
    booking: booking ? { appointmentTime: booking.appointment_time, consultantName: booking.consultant_name, createdAt: booking.created_at } : null,
    internNotes: internNotes ? {
      internName: internNotes.intern_name,
      subjectiveNotes: internNotes.subjective_notes,
      objectivePlan: internNotes.objective_plan,
      clinicalReasoning: internNotes.clinical_reasoning,
      interventionPlan: internNotes.intervention_plan,
      updatedAt: internNotes.updated_at
    } : null,
    supervisorReview: supervisorReview ? {
      supervisorName: supervisorReview.supervisor_name,
      action: supervisorReview.action,
      comments: supervisorReview.comments,
      updatedAt: supervisorReview.updated_at
    } : null,
    auditLogs: auditLogs.map(log => ({
      action: log.action,
      userName: log.user_name,
      userRole: log.user_role,
      metadata: safeJsonParse(log.metadata_json, {}),
      createdAt: log.created_at
    }))
  };
}

function canAccessAssessment(user, assessment) {
  if (!assessment) return false;
  if (['intern','supervisor','admin'].includes(user.role)) return true;
  return user.role === 'patient' && user.id === assessment.patientId;
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, service: 'BIOKIN ASSESS API', timestamp: new Date().toISOString() });
});

app.post('/api/auth/register', (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid registration details.', details: parsed.error.flatten() });

  const { fullName, email, password } = parsed.data;
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
    return res.status(409).json({ error: 'A user with this email already exists.' });
  }

  const result = db.prepare('INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)')
    .run(fullName, email, bcrypt.hashSync(password, 12), 'patient');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
  addAuditLog({ userId: user.id, action: 'Patient account registered' });

  res.status(201).json({ message: 'Patient account created.', token: createToken(user), user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role } });
});

app.post('/api/auth/login', (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid login details.' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(parsed.data.email);
  if (!user || !bcrypt.compareSync(parsed.data.password, user.password_hash)) {
    return res.status(401).json({ error: 'Incorrect email or password.' });
  }

  addAuditLog({ userId: user.id, action: 'User logged in' });
  res.json({ message: 'Logged in successfully.', token: createToken(user), user: { id: user.id, fullName: user.full_name, email: user.email, role: user.role } });
});

app.post('/api/assessments', requireAuth, requireRole('patient'), (req, res) => {
  const parsed = assessmentSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid assessment data.', details: parsed.error.flatten() });

  const input = parsed.data;
  const aiStructured = structureIntakeOnly(input);
  const result = db.prepare(`
    INSERT INTO assessments (
      patient_id, patient_name, patient_age, category, figure_type, body_view,
      selected_regions_json, pain_score, screening_json, free_text, ai_structured_json, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    req.user.id,
    input.patientName,
    input.patientAge || null,
    input.category,
    input.figureType,
    input.bodyView,
    JSON.stringify(input.selectedRegions),
    input.painScore,
    JSON.stringify(input.screening),
    input.freeText || '',
    JSON.stringify(aiStructured),
    'Awaiting Intern Review'
  );

  addAuditLog({ assessmentId: result.lastInsertRowid, userId: req.user.id, action: 'Patient submitted assessment' });
  addAuditLog({ assessmentId: result.lastInsertRowid, userId: req.user.id, action: 'AI intake structuring completed', metadata: { diagnosisGenerated: false, treatmentGenerated: false } });

  res.status(201).json({ message: 'Assessment submitted.', assessment: getFullAssessment(result.lastInsertRowid) });
});

app.get('/api/my/assessments', requireAuth, requireRole('patient'), (req, res) => {
  const assessments = db.prepare('SELECT id, patient_name, category, pain_score, status, created_at FROM assessments WHERE patient_id = ? ORDER BY created_at DESC').all(req.user.id);
  res.json({ assessments });
});

app.get('/api/assessments/:id', requireAuth, (req, res) => {
  const assessment = getFullAssessment(Number(req.params.id));
  if (!assessment) return res.status(404).json({ error: 'Assessment not found.' });
  if (!canAccessAssessment(req.user, assessment)) return res.status(403).json({ error: 'You do not have permission to view this assessment.' });
  res.json({ assessment });
});

app.post('/api/assessments/:id/booking', requireAuth, requireRole('patient'), (req, res) => {
  const assessmentId = Number(req.params.id);
  const parsed = bookingSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid booking data.', details: parsed.error.flatten() });

  const assessment = getFullAssessment(assessmentId);
  if (!assessment) return res.status(404).json({ error: 'Assessment not found.' });
  if (assessment.patientId !== req.user.id) return res.status(403).json({ error: 'You cannot book for this assessment.' });

  db.prepare(`
    INSERT INTO bookings (assessment_id, appointment_time, consultant_name)
    VALUES (?, ?, ?)
    ON CONFLICT(assessment_id)
    DO UPDATE SET appointment_time = excluded.appointment_time, consultant_name = excluded.consultant_name
  `).run(assessmentId, parsed.data.appointmentTime, parsed.data.consultantName || 'Consultant');

  addAuditLog({ assessmentId, userId: req.user.id, action: 'Patient booked consultation', metadata: { appointmentTime: parsed.data.appointmentTime } });
  res.json({ message: 'Booking saved.', assessment: getFullAssessment(assessmentId) });
});

app.get('/api/intern/cases', requireAuth, requireRole('intern','supervisor','admin'), (req, res) => {
  const cases = db.prepare(`
    SELECT assessments.id, assessments.patient_name, assessments.category, assessments.pain_score,
           assessments.status, assessments.created_at, bookings.appointment_time
    FROM assessments
    LEFT JOIN bookings ON bookings.assessment_id = assessments.id
    ORDER BY assessments.created_at DESC
  `).all();
  res.json({ cases });
});

app.patch('/api/intern/cases/:id/notes', requireAuth, requireRole('intern','admin'), (req, res) => {
  const assessmentId = Number(req.params.id);
  const parsed = internNotesSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid intern notes.', details: parsed.error.flatten() });
  if (!getFullAssessment(assessmentId)) return res.status(404).json({ error: 'Assessment not found.' });

  const notes = parsed.data;
  db.prepare(`
    INSERT INTO intern_notes (assessment_id, intern_id, subjective_notes, objective_plan, clinical_reasoning, intervention_plan)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(assessment_id)
    DO UPDATE SET intern_id = excluded.intern_id, subjective_notes = excluded.subjective_notes,
      objective_plan = excluded.objective_plan, clinical_reasoning = excluded.clinical_reasoning,
      intervention_plan = excluded.intervention_plan, updated_at = CURRENT_TIMESTAMP
  `).run(assessmentId, req.user.id, notes.subjectiveNotes || '', notes.objectivePlan || '', notes.clinicalReasoning || '', notes.interventionPlan || '');

  db.prepare('UPDATE assessments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run('Draft Plan Ready', assessmentId);
  addAuditLog({ assessmentId, userId: req.user.id, action: 'Intern saved clinical notes' });
  res.json({ message: 'Intern notes saved.', assessment: getFullAssessment(assessmentId) });
});

app.patch('/api/intern/cases/:id/send-to-supervisor', requireAuth, requireRole('intern','admin'), (req, res) => {
  const assessmentId = Number(req.params.id);
  if (!getFullAssessment(assessmentId)) return res.status(404).json({ error: 'Assessment not found.' });

  db.prepare('UPDATE assessments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run('Supervisor Review Needed', assessmentId);
  addAuditLog({ assessmentId, userId: req.user.id, action: 'Intern sent case for supervisor review' });
  res.json({ message: 'Case sent to supervisor.', assessment: getFullAssessment(assessmentId) });
});

app.get('/api/supervisor/cases', requireAuth, requireRole('supervisor','admin'), (req, res) => {
  const cases = db.prepare(`
    SELECT assessments.id, assessments.patient_name, assessments.category, assessments.pain_score,
           assessments.status, assessments.created_at, bookings.appointment_time
    FROM assessments
    LEFT JOIN bookings ON bookings.assessment_id = assessments.id
    ORDER BY assessments.created_at DESC
  `).all();
  res.json({ cases });
});

app.patch('/api/supervisor/cases/:id/action', requireAuth, requireRole('supervisor','admin'), (req, res) => {
  const assessmentId = Number(req.params.id);
  const parsed = supervisorActionSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid supervisor action.', details: parsed.error.flatten() });
  if (!getFullAssessment(assessmentId)) return res.status(404).json({ error: 'Assessment not found.' });

  const { action, comments } = parsed.data;
  db.prepare(`
    INSERT INTO supervisor_reviews (assessment_id, supervisor_id, action, comments)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(assessment_id)
    DO UPDATE SET supervisor_id = excluded.supervisor_id, action = excluded.action,
      comments = excluded.comments, updated_at = CURRENT_TIMESTAMP
  `).run(assessmentId, req.user.id, action, comments || '');

  db.prepare('UPDATE assessments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(action, assessmentId);
  addAuditLog({ assessmentId, userId: req.user.id, action: `Supervisor action: ${action}`, metadata: { comments: comments || '' } });
  res.json({ message: `Supervisor action saved: ${action}`, assessment: getFullAssessment(assessmentId) });
});

app.get('/api/assessments/:id/audit', requireAuth, requireRole('intern','supervisor','admin'), (req, res) => {
  const assessmentId = Number(req.params.id);
  const auditLogs = db.prepare(`
    SELECT audit_logs.id, audit_logs.action, audit_logs.metadata_json, audit_logs.created_at, users.full_name, users.role
    FROM audit_logs
    LEFT JOIN users ON users.id = audit_logs.user_id
    WHERE audit_logs.assessment_id = ?
    ORDER BY audit_logs.created_at ASC
  `).all(assessmentId).map(log => ({
    id: log.id,
    action: log.action,
    user: log.full_name,
    role: log.role,
    metadata: safeJsonParse(log.metadata_json, {}),
    createdAt: log.created_at
  }));
  res.json({ auditLogs });
});

app.get('/api/reference/anatomy', requireAuth, (req, res) => {
  res.json({ anatomyReference });
});

app.use((req, res) => res.status(404).json({ error: 'Route not found.' }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`BIOKIN ASSESS API running on http://localhost:${PORT}`);
  console.log('Demo users:');
  console.log('patient@demo.com / Password123!');
  console.log('intern@demo.com / Password123!');
  console.log('supervisor@demo.com / Password123!');
});
