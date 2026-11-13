const { initDatabase } = require('../src/db');
const { performBackup } = require('../src/backupService');

initDatabase();
const result = performBackup({
  tipo: 'AUTOMATICO_24H',
  ejecutadoPor: 'Script CLI / Tarea Programada 24h'
});

console.log('====================================================');
console.log(' RESPALDO CIFRADO AES-256-GCM COMPLETADO CON EXITO');
console.log('====================================================');
console.log('Archivo       :', result.filename);
console.log('Ruta Local    :', result.local_path);
console.log('Ruta Externa  :', result.external_path);
console.log('Tamaño (Bytes):', result.size_bytes);
console.log('SHA-256 Hash  :', result.sha256_hash);
console.log('Estado        :', result.estado);
