const fs = require('fs');
const path = require('path');
const analyzer = require('./services/malwareAnalyzer');

const samplesDir = path.join(__dirname, '..', 'muestras_seguras');
const outDir = path.join(__dirname, '..', 'analysis_outputs');
if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

const sampleFiles = fs.readdirSync(samplesDir).filter(f => f.toLowerCase().endsWith('.txt') || f.toLowerCase().endsWith('.py'));

sampleFiles.forEach(file => {
    const filePath = path.join(samplesDir, file);
    const buffer = fs.readFileSync(filePath);
    const stats = fs.statSync(filePath);
    const result = analyzer.analyze(file, stats.size, 'application/octet-stream', buffer);
    const outPath = path.join(outDir, file + '.json');
    fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
    console.log('Wrote', outPath);
});

console.log('Analysis complete.');
