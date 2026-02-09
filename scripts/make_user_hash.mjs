import crypto from 'crypto';

function usage() {
  console.log('Usage: npm run hash-password -- "<password>"');
}

const password = process.argv[2];
if (!password) {
  usage();
  process.exit(1);
}

const iterations = 210000;
const salt = crypto.randomBytes(16).toString('hex');
const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('hex');

console.log(`pbkdf2$sha256$${iterations}$${salt}$${hash}`);
