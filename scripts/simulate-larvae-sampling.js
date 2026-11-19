#!/usr/bin/env node

/**
 * Simula un muestreo aleatorio de calidad de larvas de Litopenaeus vannamei.
 * Genera métricas de supervivencia, talla y actividad para un lote ficticio.
 */

const SPECIES = 'LITOPENAEUS_VANNAMEI';
const STAGES = ['Nauplio', 'Zoea I', 'Zoea II', 'Zoea III', 'Mysis I', 'Mysis II', 'Mysis III', 'Post-larva'];

function rand(min, max) {
  return Math.random() * (max - min) + min;
}

function randInt(min, max) {
  return Math.floor(rand(min, max + 1));
}

function generateBatchId() {
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, '');
  const suffix = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `LRV-${date}-${suffix}`;
}

function sampleLarva(stage) {
  const isActive = Math.random() > 0.1;
  return {
    length_mm: parseFloat(rand(0.3, 12).toFixed(2)),
    alive: Math.random() > 0.05,
    active: isActive,
    abnormal: Math.random() < 0.08,
  };
}

function runSampling() {
  const stageIndex = randInt(0, STAGES.length - 1);
  const stage = STAGES[stageIndex];
  const sampleSize = randInt(50, 200);
  const batchId = generateBatchId();
  const tankId = `T-${randInt(1, 20).toString().padStart(2, '0')}`;
  const waterTemp = parseFloat(rand(27.5, 31.5).toFixed(1));
  const salinity = parseFloat(rand(28, 35).toFixed(1));
  const pH = parseFloat(rand(7.8, 8.4).toFixed(2));

  console.log('='.repeat(52));
  console.log('  SIMULACIÓN DE MUESTREO — Larvas de Camarón');
  console.log('='.repeat(52));
  console.log(`  Especie   : ${SPECIES}`);
  console.log(`  Lote      : ${batchId}`);
  console.log(`  Tanque    : ${tankId}`);
  console.log(`  Etapa     : ${stage} (${stageIndex + 1}/${STAGES.length})`);
  console.log(`  Muestra   : ${sampleSize} organismos`);
  console.log(`  Temp agua : ${waterTemp} °C`);
  console.log(`  Salinidad : ${salinity} ppt`);
  console.log(`  pH        : ${pH}`);
  console.log('-'.repeat(52));

  const larvae = Array.from({ length: sampleSize }, () => sampleLarva(stage));

  const alive = larvae.filter(l => l.alive).length;
  const active = larvae.filter(l => l.active).length;
  const abnormal = larvae.filter(l => l.abnormal).length;
  const avgLength = larvae.reduce((s, l) => s + l.length_mm, 0) / sampleSize;

  const survivalRate = ((alive / sampleSize) * 100).toFixed(1);
  const activityRate = ((active / alive) * 100).toFixed(1);
  const abnormalityRate = ((abnormal / alive) * 100).toFixed(1);

  console.log('  RESULTADOS:');
  console.log(`  Supervivencia   : ${survivalRate}%  (${alive}/${sampleSize})`);
  console.log(`  Actividad       : ${activityRate}%  (${active}/${alive} vivas)`);
  console.log(`  Anormalidad     : ${abnormalityRate}%  (${abnormal} organismos)`);
  console.log(`  Talla promedio  : ${avgLength.toFixed(2)} mm`);

  const score =
    parseFloat(survivalRate) * 0.5 +
    parseFloat(activityRate) * 0.3 +
    (100 - parseFloat(abnormalityRate)) * 0.2;

  const quality =
    score >= 85 ? 'ÓPTIMA' :
    score >= 70 ? 'ACEPTABLE' :
    score >= 50 ? 'MARGINAL' : 'RECHAZADA';

  console.log('-'.repeat(52));
  console.log(`  CALIDAD DEL LOTE : ${quality}  (score: ${score.toFixed(1)})`);
  console.log('='.repeat(52));

  return { batchId, stage, survivalRate, activityRate, abnormalityRate, quality };
}

runSampling();
