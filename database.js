const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'helpdesk.db');
const db = new sqlite3.Database(dbPath);

/* ==========================================================================
   PROMISE-BASED HELPER WRAPPERS (Attached directly to db instance)
   ========================================================================== */

db.getAsync = function (sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

db.runAsync = function (sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

db.allAsync = function (sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

// Enable foreign key support
db.run('PRAGMA foreign_keys = ON');

/* ==========================================================================
   SCHEMA INITIALIZATION & SEEDING
   ========================================================================== */

function initSchema() {
  db.serialize(() => {
    // 1. Users table supporting password reset fields, roles, and permissions (Resolver removed)
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT CHECK(role IN ('requester', 'manager', 'admin', 'super_admin')) DEFAULT 'requester',
        manager_id INTEGER,
        access_helpdesk INTEGER DEFAULT 1,
        access_assets INTEGER DEFAULT 1,
        reset_token_hash TEXT,
        reset_token_expires DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // 2. System state table
    db.run(`
      CREATE TABLE IF NOT EXISTS system_state (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);

    db.run(`INSERT OR IGNORE INTO system_state (key, value) VALUES ('accepting_tickets', 'true')`);

    // 3. Tickets table
    db.run(`
      CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_number TEXT UNIQUE,
        ticket_type TEXT CHECK(ticket_type IN ('Incident', 'Service Request', 'Change Request')) DEFAULT 'Incident',
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        priority TEXT CHECK(priority IN ('Critical', 'High', 'Medium', 'Low')) DEFAULT 'Medium',
        status TEXT CHECK(status IN (
          'Open', 'Approved', 'Rejected', 'In Progress', 'Pending Customer', 'Resolved', 'Closed'
        )) DEFAULT 'Open',
        requester_id INTEGER NOT NULL,
        manager_id INTEGER,
        assigned_to INTEGER,
        asset_id INTEGER,
        quantity INTEGER DEFAULT 1,
        cost REAL DEFAULT 0,
        po_number TEXT,
        vendor TEXT,
        location TEXT,
        rejection_reason TEXT,
        resolution_notes TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        resolved_at DATETIME,
        closed_at DATETIME,
        sla_target_resolution DATETIME,
        sla_resolution_status TEXT DEFAULT 'Pending',
        FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (manager_id) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
        FOREIGN KEY (asset_id) REFERENCES assets(id)
      )
    `);

    // 4. Ticket history table
    db.run(`
      CREATE TABLE IF NOT EXISTS ticket_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ticket_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        comment TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (ticket_id) REFERENCES tickets(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // 5. Assets table (Updated with salvage_value, repair tracking & refresh tracking)
    db.run(`
      CREATE TABLE IF NOT EXISTS assets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_tag TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        model TEXT NOT NULL,
        serial_number TEXT UNIQUE,
        status TEXT CHECK(status IN ('In Stock', 'Assigned', 'Under Repair', 'Retired', 'Refreshed')) DEFAULT 'In Stock',
        assigned_to INTEGER,
        cost REAL DEFAULT 0,
        salvage_value REAL DEFAULT 0,
        po_number TEXT,
        vendor TEXT,
        location TEXT,
        purchase_date DATE,
        warranty_expiry DATE,
        last_repair_date DATE,
        refreshed_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // 6. Asset repair logs table
    db.run(`
      CREATE TABLE IF NOT EXISTS asset_repair_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        asset_id INTEGER NOT NULL,
        repair_start_date DATE NOT NULL,
        repair_end_date DATE,
        issue_description TEXT NOT NULL,
        repair_cost REAL DEFAULT 0,
        repaired_by TEXT,
        status TEXT CHECK(status IN ('In Progress', 'Completed', 'Unrepairable')) DEFAULT 'In Progress',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
      )
    `);

    // Dynamic Safe Column Migrations
    const safeAddColumn = (table, column, typeDef) => {
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${typeDef}`, (err) => {
        if (err && !/duplicate column/i.test(err.message)) {
          console.error(`[!] Error adding ${column} to ${table}:`, err.message);
        }
      });
    };

    safeAddColumn('users', 'access_helpdesk', 'INTEGER DEFAULT 1');
    safeAddColumn('users', 'access_assets', 'INTEGER DEFAULT 1');
    safeAddColumn('assets', 'cost', 'REAL DEFAULT 0');
    safeAddColumn('assets', 'salvage_value', 'REAL DEFAULT 0');
    safeAddColumn('assets', 'po_number', 'TEXT');
    safeAddColumn('assets', 'vendor', 'TEXT');
    safeAddColumn('assets', 'location', 'TEXT');
    safeAddColumn('assets', 'last_repair_date', 'DATE');
    safeAddColumn('assets', 'refreshed_at', 'DATETIME');
    safeAddColumn('tickets', 'asset_id', 'INTEGER REFERENCES assets(id)');
    safeAddColumn('tickets', 'quantity', 'INTEGER DEFAULT 1');
    safeAddColumn('tickets', 'cost', 'REAL DEFAULT 0');
    safeAddColumn('tickets', 'po_number', 'TEXT');
    safeAddColumn('tickets', 'vendor', 'TEXT');
    safeAddColumn('tickets', 'location', 'TEXT');

    migrateLegacyResolvers();
    seedSuperAdminUser();
  });
}

function migrateLegacyResolvers() {
  db.run(
    `UPDATE users SET role = 'admin', access_helpdesk = 1 WHERE LOWER(role) = 'resolver'`,
    function (err) {
      if (err) {
        console.error('[-] Error migrating legacy resolver roles:', err.message);
      } else if (this.changes > 0) {
        console.log(`[+] Migrated ${this.changes} legacy resolver account(s) to admin.`);
      }
    }
  );
}

function seedSuperAdminUser() {
  const defaultEmail = 'superadmin@helpdesk.local';
  const defaultPassword = 'SuperAdmin123!';
  const hashedPassword = bcrypt.hashSync(defaultPassword, 10);

  db.get('SELECT id FROM users WHERE LOWER(email) = ?', [defaultEmail], (err, row) => {
    if (err) {
      console.error('Error querying database:', err);
      return;
    }

    if (!row) {
      db.run(
        `INSERT INTO users (name, email, password, role, access_helpdesk, access_assets) VALUES (?, ?, ?, 'super_admin', 1, 1)`,
        ['Super Admin', defaultEmail, hashedPassword],
        (insertErr) => {
          if (insertErr) {
            console.error('[-] Failed to seed Super Admin:', insertErr.message);
          } else {
            console.log('[+] Super Admin seeded: superadmin@helpdesk.local / SuperAdmin123!');
          }
        }
      );
    } else {
      db.run(
        `UPDATE users SET password = ?, role = 'super_admin', access_helpdesk = 1, access_assets = 1 WHERE id = ?`,
        [hashedPassword, row.id],
        () => console.log('[+] Super Admin account verified & credentials updated.')
      );
    }
  });
}

initSchema();

/* ==========================================================================
   AUTH HELPER FUNCTIONS
   ========================================================================== */

db.findUserByEmail = async function (email) {
  return await db.getAsync('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email]);
};

db.updateUserResetToken = async function (userId, tokenHash, expiresAt) {
  return await db.runAsync(
    'UPDATE users SET reset_token_hash = ?, reset_token_expires = ? WHERE id = ?',
    [tokenHash, expiresAt.toISOString(), userId]
  );
};

db.findUserByResetToken = async function (tokenHash) {
  return await db.getAsync('SELECT * FROM users WHERE reset_token_hash = ?', [tokenHash]);
};

db.updateUserPasswordAndClearToken = async function (userId, hashedPassword) {
  return await db.runAsync(
    'UPDATE users SET password = ?, reset_token_hash = NULL, reset_token_expires = NULL WHERE id = ?',
    [hashedPassword, userId]
  );
};

/* ==========================================================================
   USER MANAGEMENT HELPER FUNCTIONS
   ========================================================================== */

db.getUsers = async function () {
  const sql = `
    SELECT u.id, u.name, u.email, u.role, u.manager_id, u.access_helpdesk, u.access_assets, u.created_at,
           m.name AS manager_name
    FROM users u
    LEFT JOIN users m ON u.manager_id = m.id
    ORDER BY u.id DESC
  `;
  return await db.allAsync(sql);
};

db.getUserById = async function (id) {
  const sql = `
    SELECT u.id, u.name, u.email, u.role, u.manager_id, u.access_helpdesk, u.access_assets, u.created_at,
           m.name AS manager_name
    FROM users u
    LEFT JOIN users m ON u.manager_id = m.id
    WHERE u.id = ?
  `;
  return await db.getAsync(sql, [id]);
};

/* ==========================================================================
   ASSET MANAGEMENT HELPER FUNCTIONS
   ========================================================================== */

db.getAssets = async function ({ search = '', status = '' } = {}) {
  let sql = `
    SELECT 
      a.id, a.asset_tag, a.category, a.model, a.serial_number, a.status,
      a.assigned_to, a.cost, a.salvage_value, a.po_number, a.vendor, a.location,
      a.purchase_date, a.warranty_expiry, a.last_repair_date, a.refreshed_at, a.created_at,
      u.name AS assigned_user_name, u.email AS assigned_user_email
    FROM assets a
    LEFT JOIN users u ON a.assigned_to = u.id
    WHERE 1=1
  `;
  const params = [];

  if (status) {
    sql += ` AND a.status = ?`;
    params.push(status);
  }

  if (search) {
    sql += ` AND (
      a.asset_tag LIKE ? OR a.model LIKE ? OR a.serial_number LIKE ? OR 
      a.po_number LIKE ? OR a.vendor LIKE ? OR a.location LIKE ? OR u.name LIKE ?
    )`;
    const searchPattern = `%${search.trim()}%`;
    params.push(searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern);
  }

  sql += ` ORDER BY a.id DESC`;
  return await db.allAsync(sql, params);
};

db.getAssetById = async function (id) {
  const sql = `
    SELECT 
      a.id, a.asset_tag, a.category, a.model, a.serial_number, a.status,
      a.assigned_to, a.cost, a.salvage_value, a.po_number, a.vendor, a.location,
      a.purchase_date, a.warranty_expiry, a.last_repair_date, a.refreshed_at, a.created_at,
      u.name AS assigned_user_name, u.email AS assigned_user_email
    FROM assets a
    LEFT JOIN users u ON a.assigned_to = u.id
    WHERE a.id = ?
  `;
  return await db.getAsync(sql, [id]);
};

db.createAsset = async function ({
  asset_tag, category, model, serial_number, status,
  assigned_to, cost, salvage_value, po_number, vendor, location,
  purchase_date, warranty_expiry
}) {
  const sql = `
    INSERT INTO assets (
      asset_tag, category, model, serial_number, status, 
      assigned_to, cost, salvage_value, po_number, vendor, location, 
      purchase_date, warranty_expiry
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  return await db.runAsync(sql, [
    asset_tag, category, model, serial_number || null, status || 'In Stock',
    assigned_to || null, cost ? parseFloat(cost) : 0, salvage_value ? parseFloat(salvage_value) : 0,
    po_number || null, vendor || null, location || null, purchase_date || null, warranty_expiry || null
  ]);
};

db.updateAsset = async function (
  id,
  { category, model, serial_number, status, assigned_to, cost, salvage_value, po_number, vendor, location, purchase_date, warranty_expiry, last_repair_date }
) {
  const sql = `
    UPDATE assets 
    SET category = ?, model = ?, serial_number = ?, status = ?, 
        assigned_to = ?, cost = ?, salvage_value = ?, po_number = ?, vendor = ?, 
        location = ?, purchase_date = ?, warranty_expiry = ?, last_repair_date = COALESCE(?, last_repair_date)
    WHERE id = ?
  `;
  return await db.runAsync(sql, [
    category, model, serial_number || null, status || 'In Stock',
    assigned_to || null, cost ? parseFloat(cost) : 0, salvage_value ? parseFloat(salvage_value) : 0,
    po_number || null, vendor || null, location || null, purchase_date || null, warranty_expiry || null,
    last_repair_date || null, id
  ]);
};

db.reassignAsset = async function (id, assigned_to, location = null) {
  const status = assigned_to ? 'Assigned' : 'In Stock';
  const sql = `
    UPDATE assets
    SET assigned_to = ?, status = ?, location = COALESCE(?, location)
    WHERE id = ?
  `;
  return await db.runAsync(sql, [assigned_to || null, status, location, id]);
};

db.refreshAsset = async function (id, salvage_value) {
  const sql = `
    UPDATE assets
    SET status = 'Refreshed', assigned_to = NULL, salvage_value = ?, refreshed_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `;
  return await db.runAsync(sql, [salvage_value ? parseFloat(salvage_value) : 0, id]);
};

db.deleteAsset = async function (id) {
  return await db.runAsync('DELETE FROM assets WHERE id = ?', [id]);
};

/* ==========================================================================
   ASSET REPAIR LOG HELPER FUNCTIONS
   ========================================================================== */

db.addAssetRepairLog = async function ({
  asset_id, repair_start_date, issue_description, repair_cost, repaired_by
}) {
  const sql = `
    INSERT INTO asset_repair_logs (
      asset_id, repair_start_date, issue_description, repair_cost, repaired_by, status
    )
    VALUES (?, ?, ?, ?, ?, 'In Progress')
  `;
  const result = await db.runAsync(sql, [
    asset_id, repair_start_date, issue_description, repair_cost ? parseFloat(repair_cost) : 0, repaired_by || null
  ]);

  // Automatically update asset status and last repair date
  await db.runAsync(
    `UPDATE assets SET status = 'Under Repair', last_repair_date = ? WHERE id = ?`,
    [repair_start_date, asset_id]
  );

  return result;
};

db.getRepairLogsByAssetId = async function (asset_id) {
  const sql = `
    SELECT * FROM asset_repair_logs 
    WHERE asset_id = ? 
    ORDER BY repair_start_date DESC
  `;
  return await db.allAsync(sql, [asset_id]);
};

db.completeAssetRepair = async function (log_id, { repair_end_date, repair_cost, status = 'Completed' }) {
  const log = await db.getAsync('SELECT asset_id FROM asset_repair_logs WHERE id = ?', [log_id]);
  if (!log) throw new Error('Repair log record not found');

  const sql = `
    UPDATE asset_repair_logs
    SET repair_end_date = ?, repair_cost = COALESCE(?, repair_cost), status = ?
    WHERE id = ?
  `;
  const result = await db.runAsync(sql, [repair_end_date, repair_cost ? parseFloat(repair_cost) : null, status, log_id]);

  // Return asset to 'In Stock' if repair is complete
  if (status === 'Completed') {
    await db.runAsync(`UPDATE assets SET status = 'In Stock' WHERE id = ?`, [log.asset_id]);
  }

  return result;
};

module.exports = db;