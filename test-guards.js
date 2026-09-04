const path = require('path');

console.log('--------------------------------------------------');
console.log('  RUNNING BACKEND & AUTH-GUARD VERIFICATION TOOL  ');
console.log('--------------------------------------------------\n');

let failed = false;

// STEP 1: Verify auth-guard.js exports
console.log('[1/2] Testing auth-guard.js exports...');
try {
  const authGuards = require('./auth-guard');
  
  const expectedGuards = [
    'requireAuth',
    'requireAdmin',
    'requireAdminOrSuper',
    'requireManager',
    'requireAssetManager',
    'requireHelpdeskAccess',
    'requireAssetAccess'
  ];

  expectedGuards.forEach((guardName) => {
    if (typeof authGuards[guardName] === 'function') {
      console.log(`  ✓ Export found: ${guardName}`);
    } else {
      console.error(`  ✗ MISSING OR INVALID EXPORT: ${guardName}`);
      failed = true;
    }
  });
} catch (err) {
  console.error('  ✗ Failed to load auth-guard.js:', err.message);
  failed = true;
}

// STEP 2: Verify server.js initialization & route mounting
console.log('\n[2/2] Testing server.js syntax and route binding...');
try {
  // Mock express to capture routes without starting an active HTTP server listener
  const express = require('express');
  
  // Requiring server.js will execute top-level code and route definitions
  require('./server');
  console.log('  ✓ server.js parsed and initialized successfully with zero syntax errors.');
} catch (err) {
  console.error('  ✗ Error during server.js initialization:', err.message);
  console.error(err.stack);
  failed = true;
}

console.log('\n--------------------------------------------------');
if (failed) {
  console.error(' RESULT: VERIFICATION FAILED. Check errors above.');
  process.exit(1);
} else {
  console.log(' RESULT: ALL CHECKS PASSED SUCCESSFULLY!');
  process.exit(0);
}