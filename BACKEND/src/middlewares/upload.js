const multer = require('multer');
const path = require('path');
const fs = require('fs');

const uploadDir = path.resolve(process.env.UPLOAD_DIR || './uploads');

// Ensure upload directory exists
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
    const ext = path.extname(file.originalname) || '';
    const safeName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9-_]/g, '_');
    cb(null, `${safeName}-${uniqueSuffix}${ext}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedExts = ['.yaml', '.yml', '.json', '.dockerfile', ''];
  const ext = path.extname(file.originalname).toLowerCase();
  
  const isDockerfile = file.originalname.toLowerCase().includes('dockerfile');
  if (allowedExts.includes(ext) || isDockerfile) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Allowed files: .yaml, .yml, .json, or Dockerfile.'));
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
});

module.exports = upload;
