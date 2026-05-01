#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const reportDir = path.join(process.cwd(), 'reports');
fs.mkdirSync(reportDir, { recursive: true });
